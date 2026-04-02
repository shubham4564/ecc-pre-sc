"""
rebuild_comparison_csv.py
-------------------------
Rebuilds all_impl_comparison_gas_time.csv from the latest fresh benchmark
summary CSVs for all 6 implementations.

For the baseline (existing_ecc_pre), reads reencrypt_bench.csv and computes
the mean gas and latency across all trial rows.

For the 5 paper implementations, reads their per-operation summary CSVs and
sums the mean gas and mean latency across all operations.
"""
import csv
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"


def sum_summary(path: pathlib.Path) -> tuple[float, float]:
    """Sum gas_mean and latency_ms_mean across all operations."""
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    total_gas = sum(float(r["gas_mean"]) for r in rows)
    total_lat = sum(float(r["latency_ms_mean"]) for r in rows)
    return total_gas, total_lat


def mean_rawcsv(path: pathlib.Path) -> tuple[float, float]:
    """Compute mean gas and latency from a raw trial CSV (gas_used, latency_ms)."""
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    gas_vals = [float(r["gas_used"]) for r in rows]
    lat_vals = [float(r["latency_ms"]) for r in rows]
    return statistics.mean(gas_vals), statistics.mean(lat_vals)


def main():
    impls = []

    # Baseline ECC-PRE: use mean of raw trial rows
    baseline_path = BENCH / "reencrypt_bench.csv"
    g, l = mean_rawcsv(baseline_path)
    impls.append(("existing_ecc_pre", g, l))
    print(f"existing_ecc_pre: gas={g:.1f}, latency_ms={l:.1f}")

    # Paper implementations: sum per-operation means
    papers = [
        ("paper_vpre_sepolia",
         ROOT / "paper-vpre-sepolia" / "benchmarks" / "paper_vpre_sepolia_summary.csv"),
        ("paper_sensh_sepolia",
         ROOT / "paper-sensh-sepolia" / "benchmarks" / "paper_sensh_sepolia_summary.csv"),
        ("paper_lowlatency_oabe_sepolia",
         ROOT / "paper-lowlatency-oabe-sepolia" / "benchmarks" / "paper_lowlatency_oabe_sepolia_summary.csv"),
        ("paper_blocynfo_sepolia",
         ROOT / "paper-blocynfo-sepolia" / "benchmarks" / "paper_blocynfo_sepolia_summary.csv"),
        ("paper_anon_iot_pre_sepolia",
         ROOT / "paper-anon-iot-pre-sepolia" / "benchmarks" / "paper_anon_iot_pre_sepolia_summary.csv"),
    ]

    for name, path in papers:
        g, l = sum_summary(path)
        impls.append((name, g, l))
        print(f"{name}: gas={g:.1f}, latency_ms={l:.1f}")

    # Sort by gas ascending (our system last, as it has highest gas)
    impls.sort(key=lambda x: x[1])

    out = BENCH / "all_impl_comparison_gas_time.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["implementation", "total_gas", "total_latency_ms"])
        for name, g, l in impls:
            writer.writerow([name, g, l])

    print(f"\nWritten: {out}")


if __name__ == "__main__":
    main()
