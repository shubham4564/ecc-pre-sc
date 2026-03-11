import csv, time, statistics, os, json, secrets, sys, pathlib
from typing import Tuple, List

# Ensure src/ is importable
_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

# Local imports
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

try:
    import SP as sp_module
except ModuleNotFoundError:
    import importlib.util
    spec = importlib.util.spec_from_file_location("SP", str(_ROOT / "src" / "SP.py"))
    sp_module = importlib.util.module_from_spec(spec)
    sys.modules["SP"] = sp_module
    assert spec.loader is not None
    spec.loader.exec_module(sp_module)

try:
    import TTP as ttp_module
except ModuleNotFoundError:
    import importlib.util
    spec = importlib.util.spec_from_file_location("TTP", str(_ROOT / "src" / "TTP.py"))
    ttp_module = importlib.util.module_from_spec(spec)
    sys.modules["TTP"] = ttp_module
    assert spec.loader is not None
    spec.loader.exec_module(ttp_module)


# Generic micro-benchmark harness for a CPU-bound function
def bench(func, args: tuple = (), n: int = 100, warmup: int = 5) -> List[float]:
    import contextlib, io
    # warmup to avoid first-iteration noise (import jitters, cache, etc.)
    for _ in range(warmup):
        with contextlib.redirect_stdout(io.StringIO()):
            func(*args)
    times: List[float] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        with contextlib.redirect_stdout(io.StringIO()):
            func(*args)
        t1 = time.perf_counter_ns()
        times.append((t1 - t0) / 1e6)
    return times


# Helpers to load parameters and build consistent synthetic inputs
def _load_params():
    with open(_ROOT / "data" / "system_parameters.json", "r") as f:
        params = json.load(f)["parameters"]

    q = int(params["q"])  # curve order
    P = Point(SECP256k1.curve, int(params["p_x"]), int(params["p_y"]))

    a_xp = Point(SECP256k1.curve, int(params["a_xp_x"]), int(params["a_xp_y"]))
    a_yp = Point(SECP256k1.curve, int(params["a_yp_x"]), int(params["a_yp_y"]))
    b_x = int(params["b_x"])  # scalars for B's keys
    b_y = int(params["b_y"])  # scalars for B's keys

    id_a = params["id_a"]
    id_b = params["id_b"]
    l_bits = int(params["l_bits"])  # sigma length
    n_bits = int(params["n_bits"])  # key length

    return {
        "q": q,
        "P": P,
        "a_xp": a_xp,
        "a_yp": a_yp,
        "b_x": b_x,
        "b_y": b_y,
        "id_a": id_a,
        "id_b": id_b,
        "l_bits": l_bits,
        "n_bits": n_bits,
    }


def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)


def _rand_bits(n: int) -> str:
    # Generate n random bits as a string
    n_bytes = (n + 7) // 8
    data = secrets.token_bytes(n_bytes)
    bits = _bytes_to_bits(data)
    return bits[:n]


def _xor_bits(a: str, b: str) -> str:
    # XOR two equal-length bit strings
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _gen_synthetic_cipher(ttp, params: dict, override_n: int | None = None):
    """Generate a self-consistent (c1', c2', c3', c4') tuple plus the underlying (key, sigma).

    This avoids any on-chain calls and ensures SP.redecrypt-hotpath math has valid inputs.
    """
    q = params["q"]
    P = params["P"]
    a_xp = params["a_xp"]
    a_yp = params["a_yp"]
    b_x = params["b_x"]
    b_y = params["b_y"]
    id_a = params["id_a"]
    id_b = params["id_b"]
    l_bits = params["l_bits"]
    n_bits = params["n_bits"]

    # Pick random scalars and build points
    k1 = secrets.randbelow(q - 1) + 1
    k2 = secrets.randbelow(q - 1) + 1
    c1p = k1 * P
    c2p = k2 * P

    # Public keys of B (as points), as in SP.redecrypt
    sk_pr_x = b_x * P
    sk_pr_y = b_y * P

    s_prime = ttp.hash4(id_a, id_b, sk_pr_x.x(), sk_pr_y.x())
    hash2_point = s_prime * (c1p + c2p)
    total_bits = (override_n if override_n is not None else (l_bits + n_bits))
    h2_bits = ttp.hash2(total_bits, hash2_point.x())

    # Choose a random key and optional sigma to match total_bits
    if override_n is None:
        key_bytes = secrets.token_bytes(n_bits // 8)
        key_bits = _bytes_to_bits(key_bytes)
        sigma_bits = _rand_bits(l_bits)
        key_plus_sigma = key_bits + sigma_bits
    else:
        # n = override_n -> use all bits for key, no sigma to avoid mismatch with SP expectations
        key_bytes = secrets.token_bytes(override_n // 8)
        key_bits = _bytes_to_bits(key_bytes)
        sigma_bits = ""
        key_plus_sigma = key_bits

    # c3' is XOR so that decryption recovers our key
    c3p_bits = _xor_bits(h2_bits, key_plus_sigma)

    # Build a matching c4' for completeness only when sigma exists (default path)
    if override_n is None:
        sigma_int = int(sigma_bits, 2)
        r = ttp.hash1(key_bytes, sigma_int, id_a, a_xp.x(), a_yp.x())
        # Note: s_prime inverse and multiply by (a_xp.x + a_yp.x) as in SP.redecrypt
        from ecdsa.numbertheory import inverse_mod
        ver_scalar = (r * inverse_mod(s_prime, q) * (a_xp.x() + a_yp.x())) % q
        ver_point = ver_scalar * P
        c4p_x = ver_point.x()
    else:
        # For n=256 hotpath benchmarks, c4' isn't used; set to 0 to avoid unnecessary work
        c4p_x = 0

    return (c1p, c2p, c3p_bits, c4p_x, key_bytes, sigma_bits)


def redecrypt_hotpath(ttp, params: dict, c1p: Point, c2p: Point, c3p_bits: str, override_n: int | None = None) -> bytes:
    """Only the heavy math done in SP.redecrypt; returns recovered key bytes."""
    q = params["q"]
    P = params["P"]
    a_xp = params["a_xp"]
    a_yp = params["a_yp"]
    b_x = params["b_x"]
    b_y = params["b_y"]
    id_a = params["id_a"]
    id_b = params["id_b"]
    l_bits = params["l_bits"]
    n_bits = params["n_bits"]

    sk_pr_x = b_x * P
    sk_pr_y = b_y * P
    s_prime = ttp.hash4(id_a, id_b, sk_pr_x.x(), sk_pr_y.x())
    total_bits = (override_n if override_n is not None else (l_bits + n_bits))
    h2_bits = ttp.hash2(total_bits, (s_prime * (c1p + c2p)).x())

    # XOR to recover key||sigma
    kps = _xor_bits(h2_bits, c3p_bits)
    if override_n is None:
        key_bits = kps[:n_bits]
    else:
        key_bits = kps[:override_n]

    # bits -> bytes
    out = bytearray()
    for i in range(0, len(key_bits), 8):
        out.append(int(key_bits[i:i+8], 2))
    return bytes(out)


def _print_stats(label: str, times: List[float]):
    if not times:
        print(f"{label}: no samples")
        return
    print(
        f"{label}: avg={statistics.mean(times):.3f} ms, p50={statistics.median(times):.3f} ms, p95={statistics.quantiles(times, n=20)[18]:.3f} ms, n={len(times)}"
    )


def _print_table(stats_rows: List[tuple[str, float, float, float, int]]):
    # Print a simple aligned table
    headers = ["op", "avg_ms", "p50_ms", "p95_ms", "n"]
    col_widths = [max(len(str(r[i])) for r in ([headers] + stats_rows)) for i in range(5)]
    def fmt_row(row):
        return " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row))
    print()
    print(fmt_row(headers))
    print("-+-".join("-" * w for w in col_widths))
    for row in stats_rows:
        print(fmt_row(row))


def main():
    # Instances
    ttp = ttp_module.TTP()
    sp = sp_module.SP()
    params = _load_params()

    # Instances for SP
    sp = sp_module.SP()

    # Synthetic sample tuple for the hot path
    c1p, c2p, c3p_bits, c4p_x, key_bytes, sigma_bits = _gen_synthetic_cipher(ttp, params)
    # Sanity check: ensure SP.redecrypt can recover the key from the synthetic sample
    recovered_key = sp.redecrypt(c1p, c2p, c3p_bits, c4p_x)
    if recovered_key != key_bytes:
        raise RuntimeError("Off-chain bench setup invalid: SP.redecrypt failed to recover key in sanity check.")

    # Define benchmarked callables
    def _bench_rekey():
        sp.rekeygenerate()

    def _bench_ec_ops():
        # A representative EC workload: mixed add/mul
        k = secrets.randbelow(params["q"] - 1) + 1
        _ = (k * params["P"]) + (k * params["P"])  # 2 muls + 1 add

    def _bench_redecrypt():
        sp.redecrypt(c1p, c2p, c3p_bits, c4p_x)

    def _bench_roundtrip():
        # Generate fresh data and fully run SP.redecrypt once per iteration
        _c1, _c2, _c3_bits, _c4x, _kb, _sb = _gen_synthetic_cipher(ttp, params)
        sp.redecrypt(_c1, _c2, _c3_bits, _c4x)

    # n=256 variants (hot path only, without SP.redecrypt to avoid l_bits mismatch)
    def _bench_hotpath_n256():
        _ = redecrypt_hotpath(ttp, params, c1p, c2p, c3p_bits, override_n=256)

    def _bench_roundtrip_n256():
        _c1, _c2, _c3_bits, _c4x, _kb, _sb = _gen_synthetic_cipher(ttp, params, override_n=256)
        _ = redecrypt_hotpath(ttp, params, _c1, _c2, _c3_bits, override_n=256)

    # Run benches
    results = []  # list of (op, latency_ms)
    suites = [
        ("rekey_generate", _bench_rekey),
        ("ec_ops", _bench_ec_ops),
        ("redecrypt_sp", _bench_redecrypt),
        ("roundtrip_offchain", _bench_roundtrip),
        ("redecrypt_hotpath_n256", _bench_hotpath_n256),
        ("roundtrip_offchain_n256", _bench_roundtrip_n256),
    ]

    stats_rows = []
    for label, fn in suites:
        times = bench(fn, n=100, warmup=5)
        _print_stats(label, times)
        results.extend((label, t) for t in times)
        if times:
            p95 = statistics.quantiles(times, n=20)[18]
            stats_rows.append((label, round(statistics.mean(times), 3), round(statistics.median(times), 3), round(p95, 3), len(times)))

    # Write CSV
    with open(_HERE / "offchain_bench.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["op", "latency_ms"])
        writer.writerows(results)

    # Print final summary table
    _print_table(stats_rows)


if __name__ == "__main__":
    main()
