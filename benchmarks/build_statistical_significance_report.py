import csv
import math
import random
from pathlib import Path
from typing import Dict, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"
RNG = random.Random(42)


def read_csv(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_float(x: str) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def percentile(sorted_x: List[float], q: float) -> float:
    if not sorted_x:
        return 0.0
    if len(sorted_x) == 1:
        return sorted_x[0]
    pos = (len(sorted_x) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return sorted_x[lo]
    w = pos - lo
    return sorted_x[lo] * (1 - w) + sorted_x[hi] * w


def bootstrap_mean_ci(xs: List[float], n_boot: int = 2000, alpha: float = 0.05) -> Tuple[float, float, float]:
    if not xs:
        return 0.0, 0.0, 0.0
    if len(xs) == 1:
        v = xs[0]
        return v, v, v
    boots = []
    n = len(xs)
    for _ in range(n_boot):
        sample = [xs[RNG.randrange(n)] for _ in range(n)]
        boots.append(mean(sample))
    boots.sort()
    lo = percentile(boots, alpha / 2)
    hi = percentile(boots, 1 - alpha / 2)
    return mean(xs), lo, hi


def rankdata(vals: List[float]) -> List[float]:
    indexed = sorted((v, i) for i, v in enumerate(vals))
    ranks = [0.0] * len(vals)
    i = 0
    n = len(vals)
    while i < n:
        j = i
        while j + 1 < n and indexed[j + 1][0] == indexed[i][0]:
            j += 1
        avg_rank = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][1]] = avg_rank
        i = j + 1
    return ranks


def normal_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def mann_whitney_u_test(x: List[float], y: List[float]) -> Tuple[float, float]:
    if not x or not y:
        return 0.0, 1.0
    n1, n2 = len(x), len(y)
    all_vals = x + y
    ranks = rankdata(all_vals)
    r1 = sum(ranks[:n1])
    u1 = r1 - (n1 * (n1 + 1)) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)

    tie_counts: Dict[float, int] = {}
    for v in all_vals:
        tie_counts[v] = tie_counts.get(v, 0) + 1
    tie_term = sum(t * t * t - t for t in tie_counts.values())

    mu = n1 * n2 / 2.0
    n = n1 + n2
    var = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1) if n > 1 else 1))
    if var <= 0:
        return u, 1.0

    z = (u - mu + 0.5) / math.sqrt(var)
    p_two = 2.0 * min(normal_cdf(z), 1.0 - normal_cdf(z))
    p_two = max(0.0, min(1.0, p_two))
    return u, p_two


def cliffs_delta(x: List[float], y: List[float]) -> float:
    if not x or not y:
        return 0.0
    gt = 0
    lt = 0
    for xi in x:
        for yi in y:
            if xi > yi:
                gt += 1
            elif xi < yi:
                lt += 1
    return (gt - lt) / (len(x) * len(y))


def holm_bonferroni(p_values: List[float], alpha: float = 0.05) -> Tuple[List[float], List[bool]]:
    m = len(p_values)
    if m == 0:
        return [], []

    indexed = sorted((p, i) for i, p in enumerate(p_values))

    raw_adj_sorted = []
    for rank, (p, _) in enumerate(indexed, start=1):
        raw_adj_sorted.append((m - rank + 1) * p)

    monotone_adj_sorted = []
    running_max = 0.0
    for val in raw_adj_sorted:
        running_max = max(running_max, val)
        monotone_adj_sorted.append(min(1.0, running_max))

    reject_sorted = []
    reject_prefix = True
    for rank, (p, _) in enumerate(indexed, start=1):
        threshold = alpha / (m - rank + 1)
        if reject_prefix and p <= threshold:
            reject_sorted.append(True)
        else:
            reject_prefix = False
            reject_sorted.append(False)

    adj_out = [1.0] * m
    reject_out = [False] * m
    for pos, (_, original_idx) in enumerate(indexed):
        adj_out[original_idx] = monotone_adj_sorted[pos]
        reject_out[original_idx] = reject_sorted[pos]

    return adj_out, reject_out


def load_samples() -> Dict[str, Dict[str, List[float]]]:
    data = {
        "existing_ecc_pre": {"gas": [], "lat": []},
        "paper_vpre_sepolia": {"gas": [], "lat": []},
        "paper_blocynfo_sepolia": {"gas": [], "lat": []},
        "paper_sensh_sepolia": {"gas": [], "lat": []},
        "paper_lowlatency_oabe_sepolia": {"gas": [], "lat": []},
        "paper_anon_iot_pre_sepolia": {"gas": [], "lat": []},
    }

    baseline = BENCH / "reencrypt_bench.csv"
    if baseline.exists():
        for r in read_csv(baseline):
            data["existing_ecc_pre"]["gas"].append(to_float(r.get("gas_used", "0")))
            data["existing_ecc_pre"]["lat"].append(to_float(r.get("latency_ms", "0")))

    mappings = {
        "paper_vpre_sepolia": ROOT / "paper-vpre-sepolia" / "benchmarks" / "paper_vpre_sepolia_detail.csv",
        "paper_blocynfo_sepolia": ROOT / "paper-blocynfo-sepolia" / "benchmarks" / "paper_blocynfo_sepolia_detail.csv",
        "paper_sensh_sepolia": ROOT / "paper-sensh-sepolia" / "benchmarks" / "paper_sensh_sepolia_detail.csv",
        "paper_lowlatency_oabe_sepolia": ROOT / "paper-lowlatency-oabe-sepolia" / "benchmarks" / "paper_lowlatency_oabe_sepolia_detail.csv",
        "paper_anon_iot_pre_sepolia": ROOT / "paper-anon-iot-pre-sepolia" / "benchmarks" / "paper_anon_iot_pre_sepolia_detail.csv",
    }

    for impl, path in mappings.items():
        if not path.exists():
            continue
        for r in read_csv(path):
            data[impl]["gas"].append(to_float(r.get("gas_used", "0")))
            data[impl]["lat"].append(to_float(r.get("latency_ms", "0")))

    return data


def build_summary_rows(samples: Dict[str, Dict[str, List[float]]]) -> List[dict]:
    rows = []
    for impl, s in samples.items():
        gas_mean, gas_lo, gas_hi = bootstrap_mean_ci(s["gas"])
        lat_mean, lat_lo, lat_hi = bootstrap_mean_ci(s["lat"])
        rows.append(
            {
                "implementation": impl,
                "gas_n": len(s["gas"]),
                "gas_mean": round(gas_mean, 6),
                "gas_ci95_low": round(gas_lo, 6),
                "gas_ci95_high": round(gas_hi, 6),
                "latency_n": len(s["lat"]),
                "latency_mean_ms": round(lat_mean, 6),
                "latency_ci95_low_ms": round(lat_lo, 6),
                "latency_ci95_high_ms": round(lat_hi, 6),
            }
        )
    rows.sort(key=lambda r: r["implementation"])
    return rows


def build_pairwise_rows(samples: Dict[str, Dict[str, List[float]]], baseline_key: str = "existing_ecc_pre") -> List[dict]:
    out = []
    bx = samples.get(baseline_key, {"gas": [], "lat": []})
    for impl, s in samples.items():
        if impl == baseline_key:
            continue
        gas_u, gas_p = mann_whitney_u_test(s["gas"], bx["gas"])
        lat_u, lat_p = mann_whitney_u_test(s["lat"], bx["lat"])
        gas_delta = cliffs_delta(s["gas"], bx["gas"])
        lat_delta = cliffs_delta(s["lat"], bx["lat"])
        out.append(
            {
                "implementation": impl,
                "vs": baseline_key,
                "gas_u": round(gas_u, 6),
                "gas_p_two_sided": round(gas_p, 8),
                "gas_cliffs_delta": round(gas_delta, 6),
                "latency_u": round(lat_u, 6),
                "latency_p_two_sided": round(lat_p, 8),
                "latency_cliffs_delta": round(lat_delta, 6),
            }
        )

    gas_p = [r["gas_p_two_sided"] for r in out]
    lat_p = [r["latency_p_two_sided"] for r in out]
    gas_adj, gas_reject = holm_bonferroni(gas_p, alpha=0.05)
    lat_adj, lat_reject = holm_bonferroni(lat_p, alpha=0.05)

    for i, r in enumerate(out):
        r["gas_p_holm"] = round(gas_adj[i], 8)
        r["gas_holm_reject_0_05"] = "yes" if gas_reject[i] else "no"
        r["latency_p_holm"] = round(lat_adj[i], 8)
        r["latency_holm_reject_0_05"] = "yes" if lat_reject[i] else "no"

    out.sort(key=lambda r: r["implementation"])
    return out


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def write_markdown(summary_rows: List[dict], pair_rows: List[dict]) -> None:
    out = BENCH / "statistical_significance_report.md"
    lines = []
    lines.append("# Statistical Significance Report")
    lines.append("")
    lines.append("This report compares implementations using bootstrap 95% confidence intervals and Mann-Whitney U tests versus existing_ecc_pre.")
    lines.append("")
    lines.append("## Summary (Bootstrap 95% CI)")
    lines.append("")
    lines.append("| Implementation | Gas n | Gas mean | Gas CI95 low | Gas CI95 high | Latency n | Latency mean (ms) | Latency CI95 low | Latency CI95 high |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in summary_rows:
        lines.append(
            f"| {r['implementation']} | {r['gas_n']} | {r['gas_mean']:.6f} | {r['gas_ci95_low']:.6f} | {r['gas_ci95_high']:.6f} | "
            f"{r['latency_n']} | {r['latency_mean_ms']:.6f} | {r['latency_ci95_low_ms']:.6f} | {r['latency_ci95_high_ms']:.6f} |"
        )

    lines.append("")
    lines.append("## Pairwise vs existing_ecc_pre (Mann-Whitney U)")
    lines.append("")
    lines.append("| Implementation | Gas p-value | Gas Holm p | Gas Holm reject | Gas Cliff's delta | Latency p-value | Latency Holm p | Latency Holm reject | Latency Cliff's delta |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in pair_rows:
        lines.append(
            f"| {r['implementation']} | {r['gas_p_two_sided']:.8f} | {r['gas_p_holm']:.8f} | {r['gas_holm_reject_0_05']} | {r['gas_cliffs_delta']:.6f} | "
            f"{r['latency_p_two_sided']:.8f} | {r['latency_p_holm']:.8f} | {r['latency_holm_reject_0_05']} | {r['latency_cliffs_delta']:.6f} |"
        )

    lines.append("")
    lines.append("Interpretation guide: p < 0.05 suggests statistically significant distribution difference; Cliff's delta near 0 means small effect.")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    samples = load_samples()
    summary_rows = build_summary_rows(samples)
    pair_rows = build_pairwise_rows(samples)

    summary_csv = BENCH / "statistical_summary.csv"
    pair_csv = BENCH / "pairwise_significance_vs_existing.csv"

    write_csv(
        summary_csv,
        summary_rows,
        [
            "implementation",
            "gas_n",
            "gas_mean",
            "gas_ci95_low",
            "gas_ci95_high",
            "latency_n",
            "latency_mean_ms",
            "latency_ci95_low_ms",
            "latency_ci95_high_ms",
        ],
    )
    write_csv(
        pair_csv,
        pair_rows,
        [
            "implementation",
            "vs",
            "gas_u",
            "gas_p_two_sided",
            "gas_p_holm",
            "gas_holm_reject_0_05",
            "gas_cliffs_delta",
            "latency_u",
            "latency_p_two_sided",
            "latency_p_holm",
            "latency_holm_reject_0_05",
            "latency_cliffs_delta",
        ],
    )
    write_markdown(summary_rows, pair_rows)

    print(f"saved_summary={summary_csv}")
    print(f"saved_pairwise={pair_csv}")
    print(f"saved_md={BENCH / 'statistical_significance_report.md'}")


if __name__ == "__main__":
    main()
