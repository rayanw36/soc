"""
fig2_feature_composition.py -- Fig 2: one feature carries the model.

Revised on review (TEMPO-AIT Task 4): the original two-panel version
(feature-count share vs. gain share, both split into three buckets) read
as the same fact stated twice -- both panels were orange-dominated
(RULE-CORRELATED) and added little beyond what one number says. Replaced
with a single horizontal bar making the one load-bearing comparison
directly: is_web_attack alone vs. every other feature combined. The
three-bucket feature-count breakdown (3 identity / 20 rule-correlated /
3 behavioural, of 26) is kept as a one-line caption note instead of a
second panel -- see captions.md.

Source: results/rule_memorization_audit/exp1_feature_classification.csv
(bucket assignment, for the caption's count note) and
exp2_importance_gain.csv (per-feature gain_pct -- cross-checked identical
bucket assignment to exp1 for all 26 features before use).
"""
import csv
import sys
from collections import defaultdict

sys.path.insert(0, ".")
import figstyle
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
def _p(rel):
    return _os.path.join(REPO_ROOT, rel)
import matplotlib.pyplot as plt

EXP1 = _p("results/rule_memorization_audit/exp1_feature_classification.csv")
EXP2 = _p("results/rule_memorization_audit/exp2_importance_gain.csv")

count_by_bucket = defaultdict(int)
with open(EXP1) as f:
    for row in csv.DictReader(f):
        count_by_bucket[row["bucket"]] += 1
n_total = sum(count_by_bucket.values())

is_web_attack_gain_pct = None
gain_total = 0.0
with open(EXP2) as f:
    for row in csv.DictReader(f):
        gain_total += float(row["gain_pct"])
        if row["feature"] == "is_web_attack":
            is_web_attack_gain_pct = float(row["gain_pct"])
other_gain_pct = gain_total - is_web_attack_gain_pct

print(f"source: {EXP1}")
for b in ["RULE-IDENTITY", "RULE-CORRELATED", "BEHAVIORAL"]:
    print(f"  {b}: {count_by_bucket[b]}/{n_total} features")
print(f"source: {EXP2}")
print(f"  is_web_attack: {is_web_attack_gain_pct:.4f}% of gain")
print(f"  other {n_total - 1} features combined: {other_gain_pct:.4f}% of gain")
assert abs(gain_total - 100) < 0.5, f"gain_pct did not sum to ~100: {gain_total}"

fig, ax = plt.subplots(figsize=(figstyle.SINGLE_COL_W, 1.6))

ax.barh([0], [is_web_attack_gain_pct], color=figstyle.ORANGE,
        hatch=figstyle.HATCHES[1], edgecolor=figstyle.INK_PRIMARY,
        height=0.5, zorder=3)
ax.barh([0], [other_gain_pct], left=is_web_attack_gain_pct, color=figstyle.BLUE,
        hatch=figstyle.HATCHES[0], edgecolor=figstyle.INK_PRIMARY,
        height=0.5, zorder=3)

ax.text(is_web_attack_gain_pct / 2, 0, f"is_web_attack\n{is_web_attack_gain_pct:.1f}%",
        ha="center", va="center", fontsize=7.5, color="white")
ax.text(is_web_attack_gain_pct + other_gain_pct / 2, 0,
        f"other {n_total - 1} features\n{other_gain_pct:.1f}%",
        ha="center", va="center", fontsize=7.5, color=figstyle.INK_PRIMARY)

ax.set_xlim(0, 100)
ax.set_ylim(-0.6, 0.6)
ax.set_yticks([])
ax.set_xlabel("share of XGBoost split gain (%)")
ax.set_title("One feature carries the 26-feature model", fontsize=8.5)
ax.grid(False)

fig.tight_layout()
figstyle.save(fig, "fig2_feature_composition")
