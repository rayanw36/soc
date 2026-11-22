"""
figstyle.py -- shared style module for manuscript figures (newCol/figures_ms/).

Import this in every fig_N_*.py script; do not restyle per figure.

Palette: colour-blind-safe categorical order from the project's dataviz
skill reference palette (fixed hue order, validated adjacent-pair CVD
delta E >= 8 in both light/dark; here used single-mode for print).
Greyscale legibility is handled by pairing each categorical hue with a
distinct hatch pattern on bar fills (the "texture fill" channel), since
a printed/greyscale render collapses hue but not hatch.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# ---------------------------------------------------------------------------
# Categorical palette (dataviz skill reference palette, fixed slot order --
# never cycled/reassigned per chart; slot 1 = first series introduced, etc.)
# ---------------------------------------------------------------------------
BLUE    = "#2a78d6"   # slot 1
ORANGE  = "#eb6834"   # slot 2
AQUA    = "#1baf7a"   # slot 3
YELLOW  = "#eda100"   # slot 4
MAGENTA = "#e87ba4"   # slot 5
GREEN   = "#008300"   # slot 6
VIOLET  = "#4a3aa7"   # slot 7
RED     = "#e34948"   # slot 8

CATEGORICAL = [BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED]

# hatch pattern paired 1:1 with the categorical slots above, for greyscale/
# print legibility (texture channel, not decorative)
HATCHES = ["", "//", "xx", "\\\\", "..", "++", "oo", "--"]

# ink / chrome (light-surface only -- these are print/vector figures)
INK_PRIMARY   = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED     = "#898781"
GRID_HAIRLINE = "#e1e0d9"
BASELINE      = "#c3c2b7"
SURFACE       = "#ffffff"

# ---------------------------------------------------------------------------
# Sizing (Elsevier-style: single column ~3.5in, double column ~7.16in)
# ---------------------------------------------------------------------------
SINGLE_COL_W = 3.5
DOUBLE_COL_W = 7.16


def apply_style():
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "font.size": 8,
        "axes.titlesize": 8,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "axes.edgecolor": BASELINE,
        "axes.labelcolor": INK_PRIMARY,
        "text.color": INK_PRIMARY,
        "xtick.color": INK_SECONDARY,
        "ytick.color": INK_SECONDARY,
        "axes.grid": True,
        "grid.color": GRID_HAIRLINE,
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "axes.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "lines.linewidth": 2.0,
        "patch.linewidth": 0.8,
        "patch.edgecolor": INK_PRIMARY,
        "savefig.facecolor": SURFACE,
        "svg.fonttype": "none",
        "pdf.fonttype": 42,   # embed as editable text, not outlined paths
        "ps.fonttype": 42,
    })


def save(fig, out_stem):
    """Write both <out_stem>.pdf and <out_stem>.png (300dpi) into figures/out/,
    regardless of the current working directory, and print paths."""
    import os as _os
    out_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "out")
    _os.makedirs(out_dir, exist_ok=True)
    pdf_path = _os.path.join(out_dir, f"{out_stem}.pdf")
    png_path = _os.path.join(out_dir, f"{out_stem}.png")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, bbox_inches="tight", dpi=300)
    print(f"wrote {pdf_path}")
    print(f"wrote {png_path}")


apply_style()
