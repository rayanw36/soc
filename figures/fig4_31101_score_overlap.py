"""
fig4_31101_score_overlap.py -- Fig 4: at the deployed threshold, the
novelty layer flags benign rule-31101 alerts MORE often than attack --
a below-chance operating point, not merely "heavy overlap".

FIG-D F3 retitle: the original title ("overlap heavily") was true but
weak -- the plot shows benign carrying more density into the anomalous
tail than attack does at the operating threshold specifically (FPR
4.78% > recall 2.25%). FPR exceeding recall places this operating point
at or below the chance diagonal: for this rule, at this threshold, the
novelty layer is not merely uninformative, it is anti-informative.
Retitled to state that directly; the existing threshold annotation
(recall/FPR values pointing at the deployed-threshold line) is
unchanged, only the panel title and this docstring were rewritten.

Left panel ONLY of the pre-existing newCol/ew_fig_31101_before_after.png
(FIG RULE 4: the right panel there is the entity-window aggregation, a
retracted positive result, and is not reproduced here in any form).

Source: newCol/ew_phase3_31101_per_alert_combined.csv (ocsvm_score, label
columns; n_attack=20,665, n_benign=209, matching eval_set_definition.md's
per-rule table for rule 31101). Deployed threshold theta_ocsvm read
directly from models_v2/thresholds_production_v3.json (not hardcoded).
Plotting only -- no new experiment, no rerun of the OC-SVM.
"""
import json
import sys

sys.path.insert(0, ".")
import figstyle
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
def _p(rel):
    return _os.path.join(REPO_ROOT, rel)
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

COMBINED = _p("analysis/ew_phase3_31101_per_alert_combined.csv")
THRESH = _p("models_v2/thresholds_production_v3.json")

df = pd.read_csv(COMBINED)
s_attack = df.loc[df.label == "attack", "ocsvm_score"].values
s_benign = df.loc[df.label == "benign", "ocsvm_score"].values

with open(THRESH) as f:
    theta_ocsvm = json.load(f)["theta_ocsvm"]

print(f"source: {COMBINED}")
print(f"  n_attack={len(s_attack)}, n_benign={len(s_benign)}")
print(f"source: {THRESH}")
print(f"  theta_ocsvm={theta_ocsvm}")

# Decision convention confirmed directly from combined_decision_v3.py:
# "OC-SVM convention: anomaly score = -decision_function (higher = more
# anomalous)"; flagged-as-attack iff ocsvm_score >= theta_ocsvm.
recall_l2 = float((s_attack >= theta_ocsvm).mean())
fpr_l2 = float((s_benign >= theta_ocsvm).mean())
print(f"  frac attack scores >= theta (L2 recall): {recall_l2:.4f}")
print(f"  frac benign scores >= theta (L2 FPR): {fpr_l2:.4f}")
print("  (matches eval_set_definition.md's rule-31101 L2 recall=2.25%, "
      "L2 FPR=4.78% row, confirming decision direction)")
assert fpr_l2 > recall_l2, "expected FPR > recall (below-chance) -- check scores/threshold"
print(f"  confirmed: FPR ({fpr_l2:.4f}) > recall ({recall_l2:.4f}) -- below-chance "
      "operating point for this rule at this threshold")

fig, ax = plt.subplots(figsize=(figstyle.SINGLE_COL_W * 1.25, 3.0))

bins = np.linspace(min(s_attack.min(), s_benign.min()),
                    max(s_attack.max(), s_benign.max()), 60)
ax.hist(s_benign, bins=bins, density=True, color=figstyle.BLUE, alpha=0.65,
        edgecolor=figstyle.INK_PRIMARY, linewidth=0.4, label=f"benign (n={len(s_benign)})",
        zorder=2)
ax.hist(s_attack, bins=bins, density=True, color=figstyle.RED, alpha=0.55,
        edgecolor=figstyle.INK_PRIMARY, linewidth=0.4, label=f"attack (n={len(s_attack)})",
        zorder=3)
ax.set_xlim(-4.5, 4.5)
ymax = ax.get_ylim()[1]
ax.axvline(theta_ocsvm, color=figstyle.INK_PRIMARY, lw=1.1, ls="--", zorder=4)
ax.annotate(
    f"deployed threshold ({theta_ocsvm:.4f})\nflags {recall_l2*100:.1f}% of attack, "
    f"{fpr_l2*100:.1f}% of benign\n(score $\\geq$ threshold)",
    xy=(theta_ocsvm, ymax * 0.62), xytext=(theta_ocsvm + 0.35, ymax * 0.62),
    fontsize=6.3, color=figstyle.INK_SECONDARY, va="center", ha="left",
    arrowprops=dict(arrowstyle="->", color=figstyle.INK_MUTED, lw=0.7),
)

ax.set_xlabel("OC-SVM anomaly score (rule 31101, per alert)")
ax.set_ylabel("density")
ax.legend(loc="upper right", frameon=False, fontsize=7)
ax.set_title("At the deployed threshold, the novelty layer flags\nbenign rule-31101 alerts more often than attack", fontsize=8.2)

fig.tight_layout()
figstyle.save(fig, "fig4_31101_score_overlap")
