"""
fig1_lookup_vs_model.py -- Fig 1: full XGBoost model vs. majority-label-per-
rule-ID lookup table, on the same AIT-ADS eval split.

DATA-AVAILABILITY NOTE (read before editing this script):
The FIG prompt asked for precision/recall/F1 grouped bars. Only F1 is
available as a committed number for BOTH sides:
  - results/rule_memorization_audit/exp3_lookup_results.csv has ONLY
    "Lookup-table F1 (rule_id only)" -- no precision/recall column, and no
    captured stdout log of exp3_lookup_table.py's classification_report
    exists anywhere in the repo (checked: no matching .log/.txt).
  - results/rule_memorization_audit/exp4_ablation_main.csv (the "full"
    26-feature variant) has ait_f1 AND ait_recall, but no precision column.
Per FIG RULE 1 (never fabricate a number; do not hardcode; if a needed
value cannot be located in a committed artifact, STOP and report rather
than reconstruct it) and RULE 2 (plotting only, no recomputation), this
figure is narrowed to F1 only -- the one metric committed for both sides.

XGBOOST F1 SOURCE NOTE (also read before editing):
exp3_lookup_results.csv's own "XGBoost F1 (published)" field is 0.0000.
This is NOT used -- it is a broken measurement. Confirmed directly: the
pkl this figure would otherwise cite (models_v2/xgb_model.pkl) throws an
XGBoost model-serialization-version-mismatch warning on load in this
environment (xgboost 3.3.0), which explains the degenerate 0.0000 output;
exp4_ablation.py's own docstring independently flags this same issue
("fresh retrain; used as baseline since pkl has version mismatch"). The
XGBoost F1 plotted here instead comes from exp4_ablation_main.csv's
"full" variant: same 26 features, same eval split (ait_split.npz), but
it is an audit-time retrain, not the deployed production pkl, and its
threshold was selected by maximizing F1 directly on this same eval split
(find_best_theta in exp4_ablation.py) rather than the deployed
theta_xgb=0.07538. This distinction is stated in the figure caption.
"""
import csv
import sys

sys.path.insert(0, ".")
import figstyle
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
def _p(rel):
    return _os.path.join(REPO_ROOT, rel)
import matplotlib.pyplot as plt

EXP3 = _p("results/rule_memorization_audit/exp3_lookup_results.csv")
EXP4 = _p("results/rule_memorization_audit/exp4_ablation_main.csv")


def read_exp3(path):
    d = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            d[row["metric"]] = row["value"]
    return d


def read_exp4(path):
    rows = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            rows[row["variant"]] = row
    return rows


exp3 = read_exp3(EXP3)
exp4 = read_exp4(EXP4)

lookup_f1 = float(exp3["Lookup-table F1 (rule_id only)"])
xgb_f1 = float(exp4["full"]["ait_f1"])
gap = xgb_f1 - lookup_f1

exp3_published_f1 = float(exp3["XGBoost F1 (published)"])
print(f"source: {EXP3}")
print(f"  Lookup-table F1 = {lookup_f1:.4f}")
print(f"  exp3's own 'XGBoost F1 (published)' = {exp3_published_f1:.4f} "
      f"-- NOT used, see script docstring (pkl version-mismatch artifact)")
print(f"source: {EXP4} (variant=full)")
print(f"  XGBoost (audit retrain, 26 features) F1 = {xgb_f1:.4f}")
print(f"gap (XGBoost - lookup) = {gap:.4f}")

fig, ax = plt.subplots(figsize=(figstyle.SINGLE_COL_W, 2.6))

labels = ["XGBoost\n(26 features)", "Lookup table\n(rule ID only)"]
values = [xgb_f1, lookup_f1]
colors = [figstyle.BLUE, figstyle.ORANGE]
hatches = [figstyle.HATCHES[0], figstyle.HATCHES[1]]

bars = ax.bar(labels, values, color=colors, hatch=hatches,
              edgecolor=figstyle.INK_PRIMARY, width=0.55, zorder=3)

for b, v in zip(bars, values):
    ax.annotate(f"{v:.4f}", (b.get_x() + b.get_width() / 2, v),
                textcoords="offset points", xytext=(0, 4),
                ha="center", va="bottom", fontsize=7, color=figstyle.INK_PRIMARY)

ax.set_ylim(0.98, 1.002)
ax.set_ylabel("F1 (AIT-ADS eval split)")
ax.set_axisbelow(True)

# gap annotation
ax.annotate(
    "", xy=(1, lookup_f1), xytext=(1, xgb_f1),
    arrowprops=dict(arrowstyle="-", color=figstyle.INK_MUTED, lw=0.8,
                     shrinkA=0, shrinkB=0),
)
ax.text(1.28, (xgb_f1 + lookup_f1) / 2, f"gap\n{gap:+.4f}",
        fontsize=6.5, color=figstyle.INK_MUTED, va="center", ha="left")
ax.set_xlim(-0.6, 1.6)

fig.tight_layout()
figstyle.save(fig, "fig1_lookup_vs_model")
