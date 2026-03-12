"""
bench_timing.py
---------------
Comprehensive execution-time benchmark for every ECC-PRE process.

Off-chain processes (100 iterations by default, perf_counter_ns precision):
  1. key_generate    CO   - SECP256k1 keypair + ephemeral generation
  2. encrypt         CO   - Encrypt a 128-bit key to EC ciphertext (c1-c5)
  3. rekey_generate  SP   - Compute re-encryption keys (rk1, rk2, rk3)
  4. zkp_proof_gen   SP   - Fiat-Shamir ZKP commitment + response
  5. redecrypt       User - Recover plaintext key from re-encrypted ciphertext

On-chain processes (optional --onchain flag, 5 iterations by default):
  6. reencrypt_tx    SP   - Full reEncrypt() transaction wall-clock latency

Usage:
    python benchmarks/bench_timing.py
    python benchmarks/bench_timing.py --offchain-iters 200
    python benchmarks/bench_timing.py --onchain --iters 5

Outputs:
    benchmarks/timing_bench.csv   - per-iteration raw data
    benchmarks/timing_bench.png   - visualization
"""

import os
import sys
import csv
import time
import json
import secrets
import pathlib
import argparse
import contextlib
import io
import statistics
from typing import List

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
_SRC  = _ROOT / "src"
_DATA = _ROOT / "data"
_OUT_CSV = _HERE / "timing_bench.csv"
_OUT_PNG = _HERE / "timing_bench.png"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Timing harness
# ---------------------------------------------------------------------------

def _time_n(func, args: tuple = (), n: int = 100, warmup: int = 5) -> List[float]:
    """Run func(*args) n times after warmup; return per-call latencies in ms."""
    for _ in range(warmup):
        with contextlib.redirect_stdout(io.StringIO()):
            func(*args)
    out: List[float] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        with contextlib.redirect_stdout(io.StringIO()):
            func(*args)
        out.append((time.perf_counter_ns() - t0) / 1e6)
    return out

# ---------------------------------------------------------------------------
# Helpers for building a valid synthetic re-encrypted ciphertext
# (avoids needing an on-chain call just to get SP.redecrypt inputs)
# ---------------------------------------------------------------------------

def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _xor_bits(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))

def _load_params() -> dict:
    with open(_DATA / "system_parameters.json") as f:
        p = json.load(f)["parameters"]
    return {
        "q":      int(p["q"]),
        "P":      Point(SECP256k1.curve, int(p["p_x"]), int(p["p_y"])),
        "a_xp":   Point(SECP256k1.curve, int(p["a_xp_x"]), int(p["a_xp_y"])),
        "a_yp":   Point(SECP256k1.curve, int(p["a_yp_x"]), int(p["a_yp_y"])),
        "b_x":    int(p["b_x"]),
        "b_y":    int(p["b_y"]),
        "id_a":   p["id_a"],
        "id_b":   p["id_b"],
        "l_bits": int(p["l_bits"]),
        "n_bits": int(p["n_bits"]),
    }

def _make_synthetic_reencrypted(ttp, params: dict):
    """Build a consistent (c1', c2', c3', c4') tuple valid for SP.redecrypt."""
    q, P = params["q"], params["P"]
    c1p = secrets.randbelow(q - 1) + 1
    c2p = secrets.randbelow(q - 1) + 1
    c1p_pt = c1p * P
    c2p_pt = c2p * P

    sk_x = params["b_x"] * P
    sk_y = params["b_y"] * P
    s_prime = ttp.hash4(params["id_a"], params["id_b"], sk_x.x(), sk_y.x())

    total = params["l_bits"] + params["n_bits"]
    h2 = ttp.hash2(total, (s_prime * (c1p_pt + c2p_pt)).x())

    key_bytes = secrets.token_bytes(params["n_bits"] // 8)
    sigma_bits = bin(secrets.randbelow(2 ** params["l_bits"]))[2:].zfill(params["l_bits"])
    c3p = _xor_bits(h2, _bytes_to_bits(key_bytes) + sigma_bits)

    r = ttp.hash1(key_bytes, int(sigma_bits, 2),
                  params["id_a"], params["a_xp"].x(), params["a_yp"].x())
    c4p_scalar = (r * inverse_mod(s_prime, q) * (params["a_xp"].x() + params["a_yp"].x())) % q
    c4p_x = int((c4p_scalar * P).x())

    return c1p_pt, c2p_pt, c3p, c4p_x

# ---------------------------------------------------------------------------
# Off-chain benchmark
# ---------------------------------------------------------------------------

def run_offchain(n: int) -> List[tuple]:
    import TTP as ttp_module
    import SP as sp_module
    from CODeployment import CO

    ttp = ttp_module.TTP()
    sp  = sp_module.SP()

    # ── One-time setup: write consistent system_parameters.json ─────────────
    # We call key_generate once on a real CO to produce the parameters file
    # that all other benchmarks (SP, User) depend on.
    print("  [setup] Generating initial key parameters ...", flush=True)
    setup_co = CO()
    setup_co.key_generate(128)   # writes system_parameters.json

    params = _load_params()

    # CO instance used for encrypt bench — keys pre-generated, params fixed
    co_enc = CO()
    co_enc.key_generate(128)
    params = _load_params()   # re-sync after second write (same curve, fresh scalars)

    # Build one synthetic re-encrypted ciphertext for the User/redecrypt bench
    c1p, c2p, c3p, c4p_x = _make_synthetic_reencrypted(ttp, params)
    sanity = sp.redecrypt(c1p, c2p, c3p, c4p_x)
    if sanity is None:
        raise RuntimeError(
            "Synthetic ciphertext sanity check failed. Check system_parameters.json.")

    # Pre-compute rk values for ZKP proof bench (we time only the proof, not rk gen)
    rk1, rk2, rk3 = sp.rekeygenerate()

    try:
        with open(_DATA / "contract_info.json") as f:
            contract_addr = json.load(f)["contract_address"]
    except Exception:
        contract_addr = "0x000000000000000000000000000000000000dEaD"
    try:
        with open(_DATA / "sp_proof_material.json") as f:
            sender_addr = json.load(f)["wallet_address"]
    except Exception:
        sender_addr = os.getenv("WALLET_ADDRESS", "0x000000000000000000000000000000000000dEaD")

    # ── Benchmarked callables ────────────────────────────────────────────────

    def _bench_keygen():
        # Monkey-patch save_key_parameters on the instance so the disk write
        # is excluded from the timing (we measure pure EC arithmetic).
        c = CO()
        c.save_key_parameters = lambda: None
        c.key_generate(128)

    def _bench_encrypt():
        k = os.urandom(16)
        co_enc.encrypt(k)

    def _bench_rekey():
        sp.rekeygenerate()

    def _bench_zkp():
        sp.generate_reencryption_proof(contract_addr, sender_addr, rk1, rk2, rk3)

    def _bench_redecrypt():
        # Supply pre-built points so each call uses the same fixed input
        sp.redecrypt(c1p, c2p, c3p, c4p_x)

    suites = [
        ("key_generate",   "CO",   _bench_keygen),
        ("encrypt",        "CO",   _bench_encrypt),
        ("rekey_generate", "SP",   _bench_rekey),
        ("zkp_proof_gen",  "SP",   _bench_zkp),
        ("redecrypt",      "User", _bench_redecrypt),
    ]

    rows: List[tuple] = []
    for process, actor, fn in suites:
        print(f"  [{actor}] {process} × {n} ...", flush=True)
        times = _time_n(fn, n=n, warmup=5)
        m = statistics.mean(times)
        s = statistics.stdev(times) if len(times) > 1 else 0.0
        print(f"       mean={m:.3f} ms  stdev={s:.3f} ms  "
              f"min={min(times):.3f} ms  max={max(times):.3f} ms")
        for i, t in enumerate(times, 1):
            rows.append((process, actor, "off-chain", i, round(t, 6)))
    return rows

# ---------------------------------------------------------------------------
# On-chain benchmark
# ---------------------------------------------------------------------------

def run_onchain(n: int) -> List[tuple]:
    from web3 import Web3
    from eth_account import Account
    import SP as sp_module

    rpc = os.getenv("RPC_URL") or os.getenv("ALCHEMY_API")
    if rpc and not rpc.startswith("http"):
        rpc = f"https://eth-sepolia.g.alchemy.com/v2/{rpc}"
    pk       = os.getenv("PRIVATE_KEY")
    sender   = os.getenv("WALLET_ADDRESS")
    chain_id = int(os.getenv("CHAIN_ID", "11155111"))

    if not all([rpc, pk, sender]):
        raise ValueError(
            "Missing .env values: set RPC_URL (or ALCHEMY_API), PRIVATE_KEY, WALLET_ADDRESS")

    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise RuntimeError("Cannot connect to RPC endpoint")

    acct = Account.from_key(pk)

    with open(_DATA / "contract_info.json") as f:
        contract_addr = json.load(f)["contract_address"]
    with open(_DATA / "PRE_compData1.json") as f:
        abi = json.load(f)["PRE"]["abi"]

    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_addr), abi=abi)
    sp = sp_module.SP()

    rows: List[tuple] = []
    print(f"  [SP] reencrypt_tx × {n} (Sepolia) ...", flush=True)

    for i in range(1, n + 1):
        rk1, rk2, rk3 = sp.rekeygenerate()
        proof = sp.generate_reencryption_proof(contract_addr, sender, rk1, rk2, rk3)
        params_dict = {
            "rk1": rk1, "rk2": rk2, "rk3": rk3,
            "proofCommitmentX": proof["proofCommitmentX"],
            "proofCommitmentY": proof["proofCommitmentY"],
            "proofResponse":    proof["proofResponse"],
            "proofNonce":       proof["proofNonce"],
            "proofExpiry":      proof["proofExpiry"],
        }

        # Dry-run to surface any revert before spending gas
        contract.functions.reEncrypt(params_dict).call({"from": acct.address})

        block_gas_limit = int(w3.eth.get_block("latest")["gasLimit"])
        tx = contract.functions.reEncrypt(params_dict).build_transaction({
            "from":                 acct.address,
            "nonce":                w3.eth.get_transaction_count(acct.address, "pending"),
            "gas":                  min(5_000_000, block_gas_limit - 100_000),
            "maxFeePerGas":         w3.to_wei("50", "gwei"),
            "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
            "chainId":              chain_id,
        })
        signed = w3.eth.account.sign_transaction(tx, pk)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")

        t0 = time.perf_counter_ns()
        tx_hash = w3.eth.send_raw_transaction(raw)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1e6

        if receipt["status"] != 1:
            print(f"    [!] iter {i} tx failed: {tx_hash.hex()} — skipped")
            continue

        print(f"    [{i}/{n}] {elapsed_ms / 1000:.1f} s  ({elapsed_ms:.0f} ms)")
        rows.append(("reencrypt_tx", "SP", "on-chain", i, round(elapsed_ms, 3)))

    return rows

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _print_summary(rows: List[tuple]):
    from collections import defaultdict
    by_proc: dict = defaultdict(list)
    meta: dict = {}
    for p, a, cat, i, t in rows:
        by_proc[p].append(t)
        meta[p] = (a, cat)

    hdr = (f"{'Process':<22} {'Actor':<6} {'Category':<12} "
           f"{'Mean ms':>9} {'Stdev ms':>9} {'Min ms':>8} {'Max ms':>8} {'N':>5}")
    print(f"\n{hdr}\n{'─' * len(hdr)}")

    order = sorted(by_proc, key=lambda p: (meta[p][1], statistics.mean(by_proc[p])))
    for p in order:
        ts   = by_proc[p]
        a, cat = meta[p]
        m = statistics.mean(ts)
        s = statistics.stdev(ts) if len(ts) > 1 else 0.0
        print(f"{p:<22} {a:<6} {cat:<12} {m:>9.3f} {s:>9.3f} "
              f"{min(ts):>8.3f} {max(ts):>8.3f} {len(ts):>5}")

# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def plot_timing(rows: List[tuple], out_path: pathlib.Path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        import numpy as np
    except ImportError:
        print("\n[plot] matplotlib not found — skipping. Install with: pip install matplotlib")
        return

    from collections import defaultdict

    actor_colors = {"CO": "#1976D2", "SP": "#388E3C", "User": "#F57C00"}

    def _aggregate(data):
        by_proc: dict = defaultdict(list)
        actor_of: dict = {}
        for p, a, t in data:
            by_proc[p].append(t)
            actor_of[p] = a
        return {
            p: (actor_of[p],
                statistics.mean(vs),
                statistics.stdev(vs) if len(vs) > 1 else 0.0,
                vs)
            for p, vs in by_proc.items()
        }

    off_data = [(p, a, t) for p, a, cat, i, t in rows if cat == "off-chain"]
    on_data  = [(p, a, t) for p, a, cat, i, t in rows if cat == "on-chain"]
    off_stats = _aggregate(off_data)
    on_stats  = _aggregate(on_data)

    n_plots = (1 if off_stats else 0) + (1 if on_stats else 0)
    if n_plots == 0:
        return

    # Off-chain spans several orders of magnitude so we use a log x-axis.
    # On-chain latency is all in the seconds range; linear is fine.
    fig_h = max(5, 1.3 * max(len(off_stats), len(on_stats), 1) + 1)
    fig, axes = plt.subplots(1, n_plots, figsize=(7 * n_plots, fig_h))
    if n_plots == 1:
        axes = [axes]

    def _draw(ax, stats: dict, title: str, log_scale: bool):
        # Sort by mean so slowest operation is at the top
        procs  = sorted(stats, key=lambda p: stats[p][1])
        means  = [stats[p][1] for p in procs]
        stdevs = [stats[p][2] for p in procs]
        colors = [actor_colors.get(stats[p][0], "#9E9E9E") for p in procs]
        ypos   = np.arange(len(procs))

        ax.barh(ypos, means, xerr=stdevs, color=colors, alpha=0.82,
                error_kw={"capsize": 5, "ecolor": "#333", "elinewidth": 1.3})

        # Individual data points overlaid as translucent dots
        for idx, p in enumerate(procs):
            ax.scatter(stats[p][3], [idx] * len(stats[p][3]),
                       color="black", s=6, alpha=0.20, zorder=5)

        ax.set_yticks(ypos)
        ax.set_yticklabels(procs, fontsize=10)
        ax.set_xlabel("Execution time (ms)", fontsize=11)
        ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
        ax.grid(axis="x", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        if log_scale:
            ax.set_xscale("log")
            ax.set_xlabel("Execution time (ms)  [log scale]", fontsize=11)

        # Mean value annotation — just past the error-bar cap, slightly above the bar
        for idx, p in enumerate(procs):
            mean  = stats[p][1]
            stdev = stats[p][2]
            if log_scale:
                x_pos = (mean + stdev) * 1.06
            else:
                x_pos = (mean + stdev) * 1.04
            ax.text(x_pos, idx + 0.05,
                    f"{mean:.3f} ms", va="bottom", ha="left", fontsize=8.5,
                    bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.85))

        # Widen x-axis so annotations are never clipped
        x0, x1 = ax.get_xlim()
        if log_scale:
            ax.set_xlim(right=x1 * 3.0)
        else:
            ax.set_xlim(right=x1 * 1.20)

        # Actor color legend
        patches = [
            mpatches.Patch(color=c, label=act)
            for act, c in actor_colors.items()
            if any(stats[p][0] == act for p in procs)
        ]
        ax.legend(handles=patches, loc="lower right", fontsize=9, framealpha=0.85)

    plot_idx = 0
    if off_stats:
        _draw(axes[plot_idx], off_stats,
              f"Off-chain Process Timing\n(mean ± stdev, n={len(off_data)//len(off_stats)})",
              log_scale=True)
        plot_idx += 1
    if on_stats:
        _draw(axes[plot_idx], on_stats,
              f"On-chain Transaction Latency\n(mean ± stdev, n={len(on_data)//len(on_stats)})",
              log_scale=False)

    plt.tight_layout(pad=2.5)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n[plot] Saved → {out_path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ECC-PRE comprehensive execution-time benchmark",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--offchain-iters", type=int, default=100,
        help="Iterations per off-chain operation",
    )
    parser.add_argument(
        "--onchain", action="store_true",
        help="Also run on-chain reEncrypt() timing (requires .env)",
    )
    parser.add_argument(
        "--iters", type=int, default=5,
        help="On-chain reEncrypt iterations (used only with --onchain)",
    )
    args = parser.parse_args()

    all_rows: List[tuple] = []

    print(f"\n=== Off-chain timing benchmark  ({args.offchain_iters} iters / process) ===")
    all_rows.extend(run_offchain(args.offchain_iters))

    if args.onchain:
        print(f"\n=== On-chain timing benchmark  ({args.iters} iters) ===")
        all_rows.extend(run_onchain(args.iters))

    # ── CSV output ───────────────────────────────────────────────────────────
    with open(_OUT_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["process", "actor", "category", "iteration", "time_ms"])
        w.writerows(all_rows)
    print(f"\n[csv]  Saved → {_OUT_CSV}")

    _print_summary(all_rows)
    plot_timing(all_rows, _OUT_PNG)


if __name__ == "__main__":
    main()
