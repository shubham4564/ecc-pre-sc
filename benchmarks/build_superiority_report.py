import csv
import json
import math
import statistics
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"


def read_csv(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_float(x: str) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def mean(vals: List[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def stdev(vals: List[float]) -> float:
    if len(vals) < 2:
        return 0.0
    return statistics.pstdev(vals)


def cv(vals: List[float]) -> float:
    m = mean(vals)
    if m == 0:
        return 0.0
    return stdev(vals) / m


def normalize_lower_is_better(values_by_key: Dict[str, float]) -> Dict[str, float]:
    vals = list(values_by_key.values())
    lo = min(vals)
    hi = max(vals)
    if math.isclose(lo, hi):
        return {k: 1.0 for k in values_by_key}
    out = {}
    for k, v in values_by_key.items():
        out[k] = (hi - v) / (hi - lo)
    return out


def load_conformance() -> Dict[str, float]:
    p = BENCH / "paper_methodology_conformance.json"
    if not p.exists():
        return {
            "existing_ecc_pre": 0.0,
            "paper_vpre_sepolia": 0.0,
            "paper_sensh_sepolia": 0.0,
            "paper_blocynfo_sepolia": 0.0,
            "paper_lowlatency_oabe_sepolia": 0.0,
            "paper_anon_iot_pre_sepolia": 0.0,
        }

    data = json.loads(p.read_text(encoding="utf-8"))
    status = {r["check"]: r["status"] for r in data.get("checks", [])}

    # All six implementations are tested at the same level via Sepolia-based
    # conformance scripts.  Each check name maps directly to one implementation.
    score = {
        "existing_ecc_pre": 1.0 if status.get("existing_ecc_pre_conformance") == "pass" else 0.0,
        "paper_vpre_sepolia": 1.0 if status.get("vpre_sepolia_conformance") == "pass" else 0.0,
        "paper_sensh_sepolia": 1.0 if status.get("sensh_sepolia_conformance") == "pass" else 0.0,
        "paper_blocynfo_sepolia": 1.0 if status.get("blocynfo_sepolia_conformance") == "pass" else 0.0,
        "paper_lowlatency_oabe_sepolia": 1.0 if status.get("lowlatency_sepolia_conformance") == "pass" else 0.0,
        "paper_anon_iot_pre_sepolia": 1.0 if status.get("anon_iot_pre_sepolia_conformance") == "pass" else 0.0,
    }
    return score


def load_runtime_rows() -> List[dict]:
    p = BENCH / "all_impl_comparison_gas_time.csv"
    rows = read_csv(p)
    out = []
    for r in rows:
        out.append(
            {
                "implementation": r["implementation"],
                "total_gas": to_float(r["total_gas"]),
                "total_latency_ms": to_float(r["total_latency_ms"]),
            }
        )
    return out


def load_detail_samples() -> Dict[str, Dict[str, List[float]]]:
    data: Dict[str, Dict[str, List[float]]] = {
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


def build_report() -> List[dict]:
    runtime = load_runtime_rows()
    conf = load_conformance()
    samples = load_detail_samples()

    gas_map = {r["implementation"]: r["total_gas"] for r in runtime}
    lat_map = {r["implementation"]: r["total_latency_ms"] for r in runtime}

    gas_score = normalize_lower_is_better(gas_map)
    lat_score = normalize_lower_is_better(lat_map)

    # Robustness = low variability in gas and latency detail samples.
    var_map = {}
    for impl, detail in samples.items():
        v = (cv(detail["gas"]) + cv(detail["lat"])) / 2.0
        var_map[impl] = v
    robust_score = normalize_lower_is_better(var_map)

    rows = []
    for r in runtime:
        impl = r["implementation"]
        efficiency = (gas_score.get(impl, 0.0) + lat_score.get(impl, 0.0)) / 2.0
        conformance = conf.get(impl, 0.0)
        robustness = robust_score.get(impl, 0.0)

        # Weighted score emphasizing security/methodology correctness.
        overall = 0.25 * efficiency + 0.45 * conformance + 0.30 * robustness

        rows.append(
            {
                "implementation": impl,
                "total_gas": r["total_gas"],
                "total_latency_ms": r["total_latency_ms"],
                "efficiency_score_0_1": round(efficiency, 4),
                "conformance_score_0_1": round(conformance, 4),
                "robustness_score_0_1": round(robustness, 4),
                "overall_superiority_score_0_1": round(overall, 4),
            }
        )

    rows.sort(key=lambda x: x["overall_superiority_score_0_1"], reverse=True)
    return rows


def write_outputs(rows: List[dict]) -> None:
    out_csv = BENCH / "superiority_scorecard.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "implementation",
                "total_gas",
                "total_latency_ms",
                "efficiency_score_0_1",
                "conformance_score_0_1",
                "robustness_score_0_1",
                "overall_superiority_score_0_1",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    ours = next((r for r in rows if r["implementation"] == "existing_ecc_pre"), None)

    out_md = BENCH / "superiority_scorecard.md"
    lines = []
    lines.append("# Superiority Scorecard")
    lines.append("")
    lines.append("Weights: conformance 0.45, robustness 0.30, efficiency 0.25")
    lines.append("")
    lines.append("| Implementation | Gas | Latency (ms) | Efficiency | Conformance | Robustness | Overall |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        lines.append(
            f"| {r['implementation']} | {r['total_gas']:.4f} | {r['total_latency_ms']:.4f} | "
            f"{r['efficiency_score_0_1']:.4f} | {r['conformance_score_0_1']:.4f} | "
            f"{r['robustness_score_0_1']:.4f} | {r['overall_superiority_score_0_1']:.4f} |"
        )

    if ours:
        lines.append("")
        lines.append("## Delta vs existing_ecc_pre")
        lines.append("")
        lines.append("| Implementation | Overall Delta |")
        lines.append("|---|---:|")
        for r in rows:
            if r["implementation"] == "existing_ecc_pre":
                continue
            delta = r["overall_superiority_score_0_1"] - ours["overall_superiority_score_0_1"]
            lines.append(f"| {r['implementation']} | {delta:+.4f} |")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"saved_csv={out_csv}")
    print(f"saved_md={out_md}")


def main() -> None:
    rows = build_report()
    write_outputs(rows)


if __name__ == "__main__":
    main()
