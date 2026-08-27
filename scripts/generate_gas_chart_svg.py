import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle
from pathlib import Path

# Configure Times New Roman font and vector path export for perfect LaTeX/Inkscape rendering
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Nimbus Roman", "Liberation Serif", "DejaVu Serif", "Times"],
    "mathtext.fontset": "stix",
    "svg.fonttype": "path"  # Converts glyphs to vector paths: fixes text drift in LaTeX \includesvg
})

def generate_gas_consumption_svg(output_path="Gas Consumption ECC-PRE-SC.svg"):
    # Data from the figure
    categories = ["128 bits", "192 bits", "256 bits"]
    first_version = [455, 461, 453]
    second_version = [166, 166, 163]

    x = np.arange(len(categories))
    bar_width = 0.22

    # Figure dimensions
    fig, ax = plt.subplots(figsize=(5.6, 4.2), dpi=300)

    # Colors matching the Excel/paper palette
    color_first = "#5B9BD5"   # Blue
    color_second = "#ED7D31"  # Orange

    # Plot grouped bars
    bars1 = ax.bar(x - bar_width / 2, first_version, width=bar_width, 
                   color=color_first, label="Initial Version", zorder=3)
    bars2 = ax.bar(x + bar_width / 2, second_version, width=bar_width, 
                   color=color_second, label="Optimized Version", zorder=3)

    # Add numeric labels on top of each bar
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f"{height}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 2),  # vertical offset in points
                    textcoords="offset points",
                    ha="center", va="bottom",
                    fontsize=12.5, color="black")

    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f"{height}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha="center", va="bottom",
                    fontsize=12.5, color="black")

    # Axis limits & ticks
    ax.set_ylim(0, 530)
    ax.set_yticks(np.arange(0, 550, 50))
    ax.set_yticklabels([str(y) for y in np.arange(0, 550, 50)], fontsize=12)

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=12.5)

    # Labels
    ax.set_xlabel("Length of Content Key", fontsize=12.5, labelpad=5)
    ax.set_ylabel("Gas Consumption\n$\\times 10^4$", fontsize=12, labelpad=6)

    # Horizontal grid lines
    ax.grid(axis="y", color="#D9D9D9", linestyle="-", linewidth=0.7, zorder=0)

    # Spines / frame styling
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#D9D9D9")
    ax.spines["bottom"].set_color("#808080")
    ax.spines["bottom"].set_linewidth(0.9)
    ax.tick_params(axis="x", length=0)
    ax.tick_params(axis="y", color="#D9D9D9")

    # Legend at the top center
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.14),
        ncol=2,
        frameon=False,
        fontsize=12.5,
        handlelength=0.9,
        handleheight=0.9,
        columnspacing=1.8
    )

    # Draw a clean outer box border around the figure canvas
    border = Rectangle((0.002, 0.002), 0.996, 0.996, 
                       transform=fig.transFigure, fill=False, 
                       edgecolor="#D3D3D3", linewidth=1.0, zorder=10)
    fig.patches.append(border)

    plt.tight_layout(pad=1.4)

    # Save SVG
    out_file = Path(output_path)
    plt.savefig(out_file, format="svg", bbox_inches="tight", pad_inches=0.03)
    print(f"[+] Saved SVG to: {out_file.resolve()}")

    # Save PDF (recommended for LaTeX - avoids Inkscape conversion issues)
    pdf_file = out_file.with_suffix(".pdf")
    plt.savefig(pdf_file, format="pdf", bbox_inches="tight", pad_inches=0.03)
    print(f"[+] Saved PDF to: {pdf_file.resolve()}")

    # Also save copies in images/ for LaTeX
    img_dir = Path("images")
    if img_dir.exists():
        img_out_svg = img_dir / out_file.name
        plt.savefig(img_out_svg, format="svg", bbox_inches="tight", pad_inches=0.03)
        print(f"[+] Saved SVG copy to: {img_out_svg.resolve()}")

        img_out_pdf = img_dir / pdf_file.name
        plt.savefig(img_out_pdf, format="pdf", bbox_inches="tight", pad_inches=0.03)
        print(f"[+] Saved PDF copy to: {img_out_pdf.resolve()}")

    plt.close()

if __name__ == "__main__":
    generate_gas_consumption_svg()
