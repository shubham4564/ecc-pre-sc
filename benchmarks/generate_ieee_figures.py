"""
generate_ieee_figures.py
========================
Produces IEEE-quality publication figures comparing all 6 blockchain PRE implementations.

Figures generated:
  Fig 1  – Total on-chain gas cost per implementation (log scale)
  Fig 2  – End-to-end transaction latency per implementation
  Fig 3  – Per-operation gas breakdown (grouped bar chart)
  Fig 4  – Per-operation latency breakdown (grouped bar chart)
  Fig 5  – Security / Functionality feature matrix (heatmap)
  Fig 6  – Overall superiority scorecard (radar / spider chart)
  Fig 7  – Statistical significance: Cliff's delta + p-values

Output: benchmarks/figures/  (PDF + 300 Dpi PNG pairs)
"""

from __future__ import annotations

import csv
import math
import pathlib
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for headless / server runs

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parent.parent          # …/ECC-PRE
BENCH_DIR = ROOT / "benchmarks"
FIGURES_DIR = BENCH_DIR / "figures"
FIGURES_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# IEEE layout constants (single-column = 3.5 in, double = 7.16 in)
# ---------------------------------------------------------------------------
SINGLE_COL = (3.5, 2.6)   # width, height  (inches)
DOUBLE_COL = (7.16, 3.2)
DOUBLE_COL_TALL = (7.16, 4.2)
RADAR_SIZE = (3.5, 3.5)

DPI = 300

# Use a font stack that approximates Times New Roman for IEEE style
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif", "serif"],
    "font.size": 8,
    "axes.titlesize": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 6.5,
    "figure.dpi": DPI,
    "lines.linewidth": 0.9,
    "axes.linewidth": 0.6,
    "grid.linewidth": 0.4,
    "grid.alpha": 0.5,
    "pdf.fonttype": 42,      # embed TrueType in PDF
    "ps.fonttype": 42,
})

# ---------------------------------------------------------------------------
# Color palette (accessible, prints well in greyscale)
# ---------------------------------------------------------------------------
COLORS = {
    "existing_ecc_pre":           "#1f77b4",   # steel blue
    "paper_vpre_sepolia":         "#ff7f0e",   # orange
    "paper_sensh_sepolia":        "#2ca02c",   # green
    "paper_lowlatency_oabe_sepolia": "#d62728", # red
    "paper_blocynfo_sepolia":     "#9467bd",   # purple
    "paper_anon_iot_pre_sepolia": "#8c564b",   # brown
}

HATCHES = {
    "existing_ecc_pre":           "",
    "paper_vpre_sepolia":         "//",
    "paper_sensh_sepolia":        "\\\\",
    "paper_lowlatency_oabe_sepolia": "xx",
    "paper_blocynfo_sepolia":     "..",
    "paper_anon_iot_pre_sepolia": "++",
}

LABELS = {
    "existing_ecc_pre":              "Our ECC-PRE",
    "paper_vpre_sepolia":            "VPRE [1]",
    "paper_sensh_sepolia":           "SENSH [2]",
    "paper_lowlatency_oabe_sepolia": "Low-Lat. OABE [3]",
    "paper_blocynfo_sepolia":        "BloCyNfo [4]",
    "paper_anon_iot_pre_sepolia":    "Anon-IoT-PRE [5]",
}

# Ordered for consistent x-axis placement (ascending gas cost, our system last)
ORDER = [
    "paper_sensh_sepolia",
    "paper_anon_iot_pre_sepolia",
    "paper_lowlatency_oabe_sepolia",
    "paper_blocynfo_sepolia",
    "paper_vpre_sepolia",
    "existing_ecc_pre",
]

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def load_comparison() -> Dict[str, Dict[str, float]]:
    """Load all_impl_comparison_gas_time.csv."""
    path = BENCH_DIR / "all_impl_comparison_gas_time.csv"
    data: Dict[str, Dict[str, float]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            impl = row["implementation"].strip().strip('"')
            data[impl] = {
                "total_gas": float(row["total_gas"]),
                "total_latency_ms": float(row["total_latency_ms"]),
            }
    return data


def load_per_operation(impl: str) -> List[Dict[str, object]]:
    """Load the summary CSV for a given implementation."""
    paths = {
        "existing_ecc_pre":              BENCH_DIR / "reencrypt_bench.csv",
        "paper_vpre_sepolia":            ROOT / "paper-vpre-sepolia" / "benchmarks" / "paper_vpre_sepolia_summary.csv",
        "paper_sensh_sepolia":           ROOT / "paper-sensh-sepolia" / "benchmarks" / "paper_sensh_sepolia_summary.csv",
        "paper_lowlatency_oabe_sepolia": ROOT / "paper-lowlatency-oabe-sepolia" / "benchmarks" / "paper_lowlatency_oabe_sepolia_summary.csv",
        "paper_blocynfo_sepolia":        ROOT / "paper-blocynfo-sepolia" / "benchmarks" / "paper_blocynfo_sepolia_summary.csv",
        "paper_anon_iot_pre_sepolia":    ROOT / "paper-anon-iot-pre-sepolia" / "benchmarks" / "paper_anon_iot_pre_sepolia_summary.csv",
    }

    path = paths[impl]
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if impl == "existing_ecc_pre":
                # reencrypt_bench.csv has gas_used, latency_ms columns (no operation column)
                rows.append({
                    "operation": "reEncrypt",
                    "gas_mean": float(row.get("gas_used", 0)),
                    "latency_ms_mean": float(row.get("latency_ms", 0)),
                })
            else:
                rows.append({
                    "operation": row["operation"],
                    "gas_mean": float(row.get("gas_mean", 0)),
                    "latency_ms_mean": float(row.get("latency_ms_mean", 0)),
                })
    return rows


def load_scorecard() -> Dict[str, Dict[str, float]]:
    path = BENCH_DIR / "superiority_scorecard.csv"
    data = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            impl = row["implementation"].strip()
            data[impl] = {
                "efficiency":   float(row["efficiency_score_0_1"]),
                "conformance":  float(row["conformance_score_0_1"]),
                "robustness":   float(row["robustness_score_0_1"]),
                "overall":      float(row["overall_superiority_score_0_1"]),
            }
    return data


def load_significance() -> Dict[str, Dict[str, object]]:
    path = BENCH_DIR / "pairwise_significance_vs_existing.csv"
    data = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            impl = row["implementation"].strip()
            data[impl] = {
                "gas_cliffs_delta":    float(row["gas_cliffs_delta"]),
                "latency_cliffs_delta": float(row["latency_cliffs_delta"]),
                "gas_p":               float(row["gas_p_holm"]),
                "latency_p":           float(row["latency_p_holm"]),
                "gas_sig":             row["gas_holm_reject_0_05"].strip().lower() == "yes",
                "latency_sig":         row["latency_holm_reject_0_05"].strip().lower() == "yes",
            }
    return data


# ---------------------------------------------------------------------------
# Figure 1: Total gas cost (log scale)
# ---------------------------------------------------------------------------

def fig_total_gas(comp: Dict):
    fig, ax = plt.subplots(figsize=SINGLE_COL)
    impls = ORDER
    gas_vals = [comp[i]["total_gas"] for i in impls]
    x = np.arange(len(impls))
    bar_labels = [LABELS[i] for i in impls]
    cols = [COLORS[i] for i in impls]
    hats = [HATCHES[i] for i in impls]

    bars = ax.bar(x, gas_vals, color=cols, hatch=hats, edgecolor="black",
                  linewidth=0.5, zorder=3)

    # Value annotations
    for bar, val in zip(bars, gas_vals):
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y * 1.08,
                f"{val/1e6:.2f}M" if val >= 1e6 else f"{int(val/1000)}K",
                ha="center", va="bottom", fontsize=5.5, rotation=0)

    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v/1e6:.1f}M" if v >= 1e6 else (f"{int(v/1000)}K" if v >= 1000 else str(int(v)))))
    ax.set_xticks(x)
    ax.set_xticklabels(bar_labels, rotation=30, ha="right", fontsize=6)
    ax.set_ylabel("Total On-chain Gas (log scale)")
    ax.set_title("(a) Total Gas Cost")
    ax.grid(axis="y", zorder=0)
    ax.set_ylim(bottom=1e4)
    fig.tight_layout(pad=0.4)
    _save(fig, "fig1_total_gas")


# ---------------------------------------------------------------------------
# Figure 2: End-to-end transaction latency
# ---------------------------------------------------------------------------

def fig_total_latency(comp: Dict):
    fig, ax = plt.subplots(figsize=SINGLE_COL)
    impls = ORDER
    lat_vals = [comp[i]["total_latency_ms"] / 1000 for i in impls]   # convert to seconds
    x = np.arange(len(impls))
    cols = [COLORS[i] for i in impls]
    hats = [HATCHES[i] for i in impls]

    bars = ax.bar(x, lat_vals, color=cols, hatch=hats, edgecolor="black",
                  linewidth=0.5, zorder=3)

    for bar, val in zip(bars, lat_vals):
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + 0.5,
                f"{val:.1f}s", ha="center", va="bottom", fontsize=5.5)

    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[i] for i in impls], rotation=30, ha="right", fontsize=6)
    ax.set_ylabel("Total Latency (seconds)")
    ax.set_title("(b) End-to-End Transaction Latency")
    ax.grid(axis="y", zorder=0)
    fig.tight_layout(pad=0.4)
    _save(fig, "fig2_total_latency")


# ---------------------------------------------------------------------------
# Figure 3: Per-operation gas breakdown (grouped bar)
# ---------------------------------------------------------------------------

def fig_per_op_gas():
    # Build a unified label set per paper
    paper_impls = [i for i in ORDER if i != "existing_ecc_pre"]

    fig, axes = plt.subplots(2, 3, figsize=DOUBLE_COL_TALL)
    axes_flat = axes.flatten()

    all_data = {}
    for impl in ORDER:
        all_data[impl] = load_per_operation(impl)

    # Our baseline first, then each paper
    plot_order = ["existing_ecc_pre"] + paper_impls
    for idx, impl in enumerate(plot_order):
        ax = axes_flat[idx]
        rows = all_data[impl]
        ops = [r["operation"] for r in rows]
        gas = [r["gas_mean"] for r in rows]
        x = np.arange(len(ops))
        col = COLORS[impl]
        hat = HATCHES[impl]
        bars = ax.bar(x, gas, color=col, hatch=hat, edgecolor="black", linewidth=0.4, zorder=3)
        ax.set_xticks(x)
        ax.set_xticklabels(ops, rotation=35, ha="right", fontsize=5.2)
        ax.set_title(LABELS[impl], fontsize=7)
        ax.set_ylabel("Gas" if idx % 3 == 0 else "")
        ax.grid(axis="y", zorder=0)
        # Format y-axis
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(
            lambda v, _: f"{v/1e6:.1f}M" if v >= 1e6 else (f"{int(v/1000)}K" if v >= 1000 else str(int(v)))))

    fig.suptitle("Fig. 3  Per-Operation Gas Cost", fontsize=8, y=1.01)
    fig.tight_layout(pad=0.5)
    _save(fig, "fig3_per_op_gas")


# ---------------------------------------------------------------------------
# Figure 4: Per-operation latency breakdown
# ---------------------------------------------------------------------------

def fig_per_op_latency():
    paper_impls = [i for i in ORDER if i != "existing_ecc_pre"]

    fig, axes = plt.subplots(2, 3, figsize=DOUBLE_COL_TALL)
    axes_flat = axes.flatten()

    all_data = {}
    for impl in ORDER:
        all_data[impl] = load_per_operation(impl)

    plot_order = ["existing_ecc_pre"] + paper_impls
    for idx, impl in enumerate(plot_order):
        ax = axes_flat[idx]
        rows = all_data[impl]
        ops = [r["operation"] for r in rows]
        lat = [r["latency_ms_mean"] / 1000 for r in rows]   # seconds
        x = np.arange(len(ops))
        bars = ax.bar(x, lat, color=COLORS[impl], hatch=HATCHES[impl],
                      edgecolor="black", linewidth=0.4, zorder=3)
        ax.set_xticks(x)
        ax.set_xticklabels(ops, rotation=35, ha="right", fontsize=5.2)
        ax.set_title(LABELS[impl], fontsize=7)
        ax.set_ylabel("Latency (s)" if idx % 3 == 0 else "")
        ax.grid(axis="y", zorder=0)

    fig.suptitle("Fig. 4  Per-Operation Latency", fontsize=8, y=1.01)
    fig.tight_layout(pad=0.5)
    _save(fig, "fig4_per_op_latency")


# ---------------------------------------------------------------------------
# Figure 5: Security / Functionality feature matrix (heatmap)
# ---------------------------------------------------------------------------

def fig_feature_matrix():
    """
    Audit-derived feature matrix for the six implementations.
    Values: 1 = fully implemented, 0.5 = partially, 0 = missing.
    """
    features = [
        "On-chain EC Crypto",
        "ZK Proof Verify",
        "Re-encryption Key",
        "Access Control",
        "Revocation",
        "Off-chain Crypto",
        "Conformance Tests",
    ]

    # Rows = implementations in ORDER, cols = features
    # Values based on audit findings (see audit notes)
    matrix = {
        "existing_ecc_pre":              [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        "paper_vpre_sepolia":            [0.0, 0.0, 1.0, 1.0, 0.5, 1.0, 1.0],
        "paper_sensh_sepolia":           [0.0, 0.0, 0.0, 1.0, 1.0, 0.5, 0.0],
        "paper_lowlatency_oabe_sepolia": [0.0, 0.5, 0.5, 1.0, 0.5, 0.5, 0.0],
        "paper_blocynfo_sepolia":        [0.0, 0.0, 0.5, 1.0, 0.5, 0.5, 0.0],
        "paper_anon_iot_pre_sepolia":    [0.0, 0.0, 0.5, 1.0, 0.0, 0.5, 0.0],
    }

    data = np.array([matrix[i] for i in ORDER])
    impl_labels = [LABELS[i] for i in ORDER]

    fig, ax = plt.subplots(figsize=(7.16, 2.8))
    im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(np.arange(len(features)))
    ax.set_xticklabels(features, rotation=30, ha="right", fontsize=6.5)
    ax.set_yticks(np.arange(len(impl_labels)))
    ax.set_yticklabels(impl_labels, fontsize=6.5)

    # Annotate cells (ASCII to ensure PDF embedding compatibility)
    for i in range(len(ORDER)):
        for j in range(len(features)):
            val = data[i, j]
            txt = "Y" if val == 1.0 else ("~" if val == 0.5 else "N")
            ax.text(j, i, txt, ha="center", va="center", fontsize=7,
                    color="black", fontweight="bold")

    cbar = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.02)
    cbar.set_ticks([0, 0.5, 1])
    cbar.set_ticklabels(["None", "Partial", "Full"], fontsize=6)
    ax.set_title("Implementation Feature / Security Matrix", fontsize=8)
    fig.tight_layout(pad=0.5)
    _save(fig, "fig5_feature_matrix")


# ---------------------------------------------------------------------------
# Figure 6: Superiority scorecard – radar / spider chart
# ---------------------------------------------------------------------------

def fig_radar(scorecard: Dict):
    metrics = ["Efficiency", "Conformance", "Robustness"]
    metric_keys = ["efficiency", "conformance", "robustness"]
    N = len(metrics)

    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]  # close polygon

    fig, ax = plt.subplots(figsize=RADAR_SIZE, subplot_kw=dict(polar=True))

    for impl in ORDER:
        values = [scorecard[impl][k] for k in metric_keys]
        values += values[:1]
        ax.plot(angles, values, color=COLORS[impl], linewidth=1.0, linestyle="solid")
        ax.fill(angles, values, color=COLORS[impl], alpha=0.08)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, size=7)
    ax.set_yticks([0.25, 0.50, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.50", "0.75", "1.0"], size=5.5)
    ax.set_ylim(0, 1)

    legend_handles = [mpatches.Patch(color=COLORS[i], label=LABELS[i]) for i in ORDER]
    ax.legend(handles=legend_handles, loc="upper right", bbox_to_anchor=(1.5, 1.2),
              fontsize=5.5, framealpha=0.8)

    ax.set_title("Fig. 6  Superiority Scorecard (Radar)", fontsize=8, pad=12)
    fig.tight_layout(pad=0.5)
    _save(fig, "fig6_radar_scorecard")


# ---------------------------------------------------------------------------
# Figure 7: Statistical significance – Cliff's delta + p-values
# ---------------------------------------------------------------------------

def fig_significance(sig_data: Dict):
    paper_impls = [i for i in ORDER if i != "existing_ecc_pre"]
    x = np.arange(len(paper_impls))
    width = 0.35

    gas_delta  = [abs(sig_data[i]["gas_cliffs_delta"])     for i in paper_impls]
    lat_delta  = [abs(sig_data[i]["latency_cliffs_delta"])  for i in paper_impls]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=DOUBLE_COL)

    # --- Cliff's delta ---
    ax1.bar(x - width / 2, gas_delta, width, label="Gas", color="#1f77b4",
            edgecolor="black", linewidth=0.5, hatch="//", zorder=3)
    ax1.bar(x + width / 2, lat_delta, width, label="Latency", color="#ff7f0e",
            edgecolor="black", linewidth=0.5, hatch="\\\\", zorder=3)
    ax1.axhline(0.474, color="red", linewidth=0.8, linestyle="--",
                label="|δ|=0.474 (large)")
    ax1.axhline(0.33,  color="orange", linewidth=0.8, linestyle=":",
                label="|δ|=0.33 (medium)")
    ax1.set_xticks(x)
    ax1.set_xticklabels([LABELS[i] for i in paper_impls], rotation=30, ha="right", fontsize=5.8)
    ax1.set_ylim(0, 1.1)
    ax1.set_ylabel("Cliff's Delta |δ|")
    ax1.set_title("(a) Effect Size vs. Our ECC-PRE")
    ax1.legend(fontsize=5.5)
    ax1.grid(axis="y", zorder=0)

    # --- p-values (Holm-Bonferroni corrected) ---
    gas_p   = [sig_data[i]["gas_p"]     for i in paper_impls]
    lat_p   = [sig_data[i]["latency_p"] for i in paper_impls]

    ax2.bar(x - width / 2, gas_p, width, label="Gas", color="#1f77b4",
            edgecolor="black", linewidth=0.5, hatch="//", zorder=3)
    ax2.bar(x + width / 2, lat_p, width, label="Latency", color="#ff7f0e",
            edgecolor="black", linewidth=0.5, hatch="\\\\", zorder=3)
    ax2.axhline(0.05, color="red", linewidth=0.8, linestyle="--",
                label="α = 0.05")
    ax2.set_xticks(x)
    ax2.set_xticklabels([LABELS[i] for i in paper_impls], rotation=30, ha="right", fontsize=5.8)
    ax2.set_ylabel("Holm-Bonferroni p-value")
    ax2.set_title("(b) Corrected p-values")
    ax2.legend(fontsize=5.5)
    ax2.grid(axis="y", zorder=0)

    fig.suptitle("Fig. 7  Statistical Significance (Mann-Whitney U, Holm-Bonferroni)", fontsize=8)
    fig.tight_layout(pad=0.5)
    _save(fig, "fig7_statistical_significance")


# ---------------------------------------------------------------------------
# Figure 8: Overall superiority score (horizontal bar)
# ---------------------------------------------------------------------------

def fig_overall_score(scorecard: Dict):
    fig, ax = plt.subplots(figsize=SINGLE_COL)
    impls_sorted = sorted(ORDER, key=lambda i: scorecard[i]["overall"], reverse=True)
    scores = [scorecard[i]["overall"] for i in impls_sorted]
    y = np.arange(len(impls_sorted))
    cols = [COLORS[i] for i in impls_sorted]
    hats = [HATCHES[i] for i in impls_sorted]

    bars = ax.barh(y, scores, color=cols, hatch=hats, edgecolor="black",
                   linewidth=0.5, zorder=3)
    for bar, val in zip(bars, scores):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.3f}", va="center", fontsize=6)

    ax.set_yticks(y)
    ax.set_yticklabels([LABELS[i] for i in impls_sorted], fontsize=6.5)
    ax.set_xlim(0, 1.15)
    ax.set_xlabel("Overall Superiority Score (0–1)")
    ax.set_title("(c) Weighted Superiority Score")
    ax.axvline(0.5, color="grey", linewidth=0.7, linestyle="--", alpha=0.7)
    ax.grid(axis="x", zorder=0)
    fig.tight_layout(pad=0.4)
    _save(fig, "fig8_overall_score")


# ---------------------------------------------------------------------------
# Figure 9: Combined gas + latency dual-axis comparison
# ---------------------------------------------------------------------------

def fig_gas_latency_combined(comp: Dict):
    fig, ax1 = plt.subplots(figsize=DOUBLE_COL)

    impls = ORDER
    x = np.arange(len(impls))
    width = 0.38

    gas_vals = [comp[i]["total_gas"] for i in impls]
    lat_vals = [comp[i]["total_latency_ms"] / 1000 for i in impls]
    cols = [COLORS[i] for i in impls]
    hats = [HATCHES[i] for i in impls]

    bars1 = ax1.bar(x - width / 2, gas_vals, width, color=cols, hatch=hats,
                    edgecolor="black", linewidth=0.5, zorder=3, label="Gas")
    ax1.set_yscale("log")
    ax1.set_ylabel("Total Gas (log scale)", color="black")
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v/1e6:.1f}M" if v >= 1e6 else (f"{int(v/1000)}K" if v >= 1000 else str(int(v)))))

    ax2 = ax1.twinx()
    bars2 = ax2.bar(x + width / 2, lat_vals, width, color=cols, alpha=0.6,
                    edgecolor="black", linewidth=0.5, zorder=3, label="Latency")
    ax2.set_ylabel("Total Latency (s)")

    ax1.set_xticks(x)
    ax1.set_xticklabels([LABELS[i] for i in impls], rotation=28, ha="right", fontsize=6)

    # Manual legend
    gas_patch = mpatches.Patch(color="grey", label="Gas (log, left axis)", hatch="//")
    lat_patch = mpatches.Patch(color="grey", alpha=0.6, label="Latency (right axis)")
    ax1.legend(handles=[gas_patch, lat_patch], fontsize=6, loc="upper left")

    ax1.set_title("Fig. 9  Gas vs. Latency Trade-off", fontsize=8)
    ax1.grid(axis="y", zorder=0, which="both")
    fig.tight_layout(pad=0.5)
    _save(fig, "fig9_gas_latency_combined")


# ---------------------------------------------------------------------------
# Save helper
# ---------------------------------------------------------------------------

def _save(fig: plt.Figure, name: str):
    pdf_path = FIGURES_DIR / f"{name}.pdf"
    png_path = FIGURES_DIR / f"{name}.png"
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight")
    fig.savefig(png_path, format="png", dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {png_path.name}  +  {pdf_path.name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Loading benchmark data …")
    comp      = load_comparison()
    scorecard = load_scorecard()
    sig_data  = load_significance()

    print("Generating IEEE figures …")
    fig_total_gas(comp)
    fig_total_latency(comp)
    fig_per_op_gas()
    fig_per_op_latency()
    fig_feature_matrix()
    fig_radar(scorecard)
    fig_significance(sig_data)
    fig_overall_score(scorecard)
    fig_gas_latency_combined(comp)

    print(f"\nAll figures saved to: {FIGURES_DIR}")
    print("Files:")
    for p in sorted(FIGURES_DIR.iterdir()):
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
