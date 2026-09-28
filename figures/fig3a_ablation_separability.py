"""
fig3a_ablation_separability.py -- Fig 3a: every feature subset that
separates AIT-ADS carries rule-definition metadata, in one form or
another -- these are not independent, unrelated shortcuts.

Split out of an earlier combined draft (fig3_two_level_identity.py) after
review: that draft's single-figure framing ("identity-only result shape
recurring at two levels") directly contradicted its own left panel, where
removing identity features changed nothing. Two honest, separate claims
instead of one overreaching one.

Revision note (FIG-C Task 4): the in-figure footnote text (mixed-mechanism
explanation for the right panel) has been removed from the rendered
PDF/PNG and moved to captions.md as the LaTeX \caption{} body. This
docstring is unaffected -- it is source documentation, not rendered image
content.

Revision note (FIG-C Task 1): the left panel was originally titled "Three
unrelated feature subsets each separate AIT-ADS." That title is wrong on
its own evidence: is_web_attack is rule-group/description metadata (Fig
2); the 3 RULE-IDENTITY features are rule identity directly; and
time_since_last_high (the dominant BEHAVIORAL feature, right panel) is
proximity to a rule-SEVERITY event, and rule_level itself is classified
RULE-IDENTITY (exp1_feature_classification.csv). All three routes to
separability are rule-definition metadata in different forms -- none is
an independent behavioral signal. Retitled to state that. Do not restore
"unrelated" without re-reading this note.

LEFT PANEL -- ablation variants (full / no_identity / behav_only).
Source: results/rule_memorization_audit/exp4_ablation_main.csv.
As established when this was fig3's left panel: no_identity is IDENTICAL
to full (rule-identity removal changes nothing; the real carrier is the
rule-CORRELATED feature is_web_attack, see Fig 2) -- and behav_only, only
3 features nominally "BEHAVIORAL," ALSO nearly matches full (recall
0.9886 vs 0.9891, FPR 0.0187 vs 0.0000) -- and, per the right panel and
FIG-C Task 2, 2 of those 3 features carry a rule-metadata mechanism too.

RIGHT PANEL -- what explains behav_only. An earlier draft of this panel
titled it "a capture-tempo artifact" outright; the TEMPO-AIT check
(newCol/figures_ms/tempo_ait_check.md) tested that claim directly against
the specific asymmetry that made this project's own 135x Linux capture-
tempo confound an artifact (benign never approaches attack density) and
found a MIXED result, not a clean confirmation -- so the title and this
docstring were corrected rather than left as an assertion the follow-up
check didn't fully support:
  - alert_rate_1min: 99.3% of attack rows sit at the feature's cap (20)
    vs. 32.9% of benign -- but benign ALSO reaches that same cap in a
    third of rows (unlike the Linux case, where benign never approached
    attack density at all), and the cap itself is a hard structural
    ceiling (AgentHistory's 20-alert rolling buffer, shared_features.py)
    that undercounts true rate for both classes once saturated. Partial,
    coarse tempo signal -- not a clean artifact.
  - time_since_last_high: 80.4% of attack rows equal exactly 0 (a
    level>=10 alert occurred immediately prior) vs. only 1.0% of benign
    -- a much sharper asymmetry, but its mechanism is proximity to a
    RULE-SEVERITY event, not raw alert volume/tempo; rule_level itself
    is classified RULE-IDENTITY (exp1_feature_classification.csv), so
    this feature sits closer to a rule-derived signal than a pure
    capture-tempo one. It carries most of BEHAVIORAL's gain (2.815% vs.
    alert_rate_1min's 0.307%, exp2_importance_gain.csv).
  - Both threshold values (20, 0) were confirmed against
    shared_features.py to be structural/natural boundaries in the
    feature-engineering code, not values selected by looking at eval
    performance -- the "unfitted" label for the RULES is accurate. What
    changed on review is the causal claim about WHY they separate.
What the right panel shows, combined with Fig 2 and FIG-C Task 2's
taxonomy correction: AIT-ADS separability traces to rule-definition
metadata by three different routes -- rule-type/content flags
(is_web_attack), rule identity directly (desc_len/rule_level/
rule_id_encoded), and rule-severity proximity (time_since_last_high).
Only alert_rate_1min (0.307% of gain) is a genuine, if partial and
coarse, behavioral/tempo signal; nearly everything else that separates
this dataset is a rule-metadata shortcut in some form, not learned
generalizable behavior.
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
import numpy as np

EXP4 = _p("results/rule_memorization_audit/exp4_ablation_main.csv")
SPLIT_PATH = _p("models_v2/ait_split.npz")

# ---------------------------------------------------------------------------
# LEFT PANEL data
# ---------------------------------------------------------------------------
left_rows = {}
with open(EXP4) as f:
    for row in csv.DictReader(f):
        left_rows[row["variant"]] = row

LEFT_ORDER = ["full", "no_identity", "behav_only"]
LEFT_LABEL = {
    "full": "Full\n(26 feat.,\nincl. identity)",
    "no_identity": "No identity\n(23 feat.)",
    "behav_only": "Behavioural\nonly (3 feat.)",
}
print(f"source: {EXP4}")
for v in LEFT_ORDER:
    r = left_rows[v]
    print(f"  {v}: F1={r['ait_f1']} recall={r['ait_recall']} FPR={r['ait_fpr']}")

# ---------------------------------------------------------------------------
# RIGHT PANEL data -- capture-tempo confound check, computed directly from
# the committed split (no new experiment: group-wise descriptive stats and
# unfitted single-feature threshold rules only).
# ---------------------------------------------------------------------------
data = np.load(SPLIT_PATH, allow_pickle=True)
feat_cols = list(data["feature_cols"])
X = np.concatenate([data["X_train"], data["X_test"]], axis=0)
y = np.concatenate([data["y_train"], data["y_test"]], axis=0)
print(f"source: {SPLIT_PATH}  (n={len(y)}, attack={int(y.sum())}, "
      f"benign={int((y == 0).sum())})")

tsh = X[:, feat_cols.index("time_since_last_high")].astype(float)
ar = X[:, feat_cols.index("alert_rate_1min")].astype(float)

frac_attack_at_cap = float((ar[y == 1] >= 20).mean())
frac_benign_at_cap = float((ar[y == 0] >= 20).mean())
print(f"  alert_rate_1min: frac attack at cap(20)={frac_attack_at_cap:.4f}, "
      f"frac benign at cap(20)={frac_benign_at_cap:.4f}")

frac_attack_zero = float((tsh[y == 1] == 0).mean())
frac_benign_sentinel = float((tsh[y == 0] == 999).mean())
frac_benign_zero = float((tsh[y == 0] == 0).mean())
print(f"  time_since_last_high: frac attack==0={frac_attack_zero:.4f}, "
      f"frac benign==999(sentinel)={frac_benign_sentinel:.4f}, "
      f"frac benign==0={frac_benign_zero:.4f}")

pred_tsh = (tsh == 0).astype(int)
recall_tsh = float(pred_tsh[y == 1].mean())
fpr_tsh = float(pred_tsh[y == 0].mean())
print(f"  single-feature rule (time_since_last_high==0 -> attack): "
      f"recall={recall_tsh:.4f} FPR={fpr_tsh:.4f}")

pred_ar = (ar >= 20).astype(int)
recall_ar = float(pred_ar[y == 1].mean())
fpr_ar = float(pred_ar[y == 0].mean())
print(f"  single-feature rule (alert_rate_1min>=20 -> attack): "
      f"recall={recall_ar:.4f} FPR={fpr_ar:.4f}")

# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(figstyle.DOUBLE_COL_W * 0.95, 3.0))

# --- LEFT: 26-feature ablation ---
ax = axes[0]
x = np.arange(len(LEFT_ORDER))
w = 0.35
recalls = [float(left_rows[v]["ait_recall"]) for v in LEFT_ORDER]
fprs = [float(left_rows[v]["ait_fpr"]) for v in LEFT_ORDER]

b1 = ax.bar(x - w / 2, recalls, width=w, color=figstyle.BLUE,
            hatch=figstyle.HATCHES[0], edgecolor=figstyle.INK_PRIMARY, zorder=3)
b2 = ax.bar(x + w / 2, fprs, width=w, color=figstyle.ORANGE,
            hatch=figstyle.HATCHES[1], edgecolor=figstyle.INK_PRIMARY, zorder=3)
for bars, vals in [(b1, recalls), (b2, fprs)]:
    for bar, v in zip(bars, vals):
        ax.annotate(f"{v:.4f}", (bar.get_x() + bar.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 3), ha="center",
                    va="bottom", fontsize=6)
ax.set_xticks(x)
ax.set_xticklabels([LEFT_LABEL[v] for v in LEFT_ORDER], fontsize=6.5)
ax.set_ylim(0, 1.35)
ax.set_ylabel("rate (AIT-ADS eval split)")
ax.set_xlim(-0.6, 2.9)
ax.set_title("Every subset that separates AIT-ADS\ncarries rule-definition metadata", fontsize=7.5)
ax.annotate("no_identity == full (is_web_attack:\nrule-type metadata, not identity -- Fig 2)",
            xy=(0.825, recalls[0] + 0.01), xytext=(1.5, 1.22),
            fontsize=6, color=figstyle.INK_SECONDARY, ha="center",
            arrowprops=dict(arrowstyle="->", color=figstyle.INK_MUTED, lw=0.7))
ax.annotate("nearly matches full (2 of 3 features\nalso rule-metadata -- see right panel)",
            xy=(1.825, recalls[2] + 0.01), xytext=(2.5, 0.55),
            fontsize=6, color=figstyle.INK_SECONDARY, ha="center",
            arrowprops=dict(arrowstyle="->", color=figstyle.INK_MUTED, lw=0.7))

# --- RIGHT: capture-tempo evidence for behav_only ---
ax = axes[1]
rule_labels = ["behav_only\n(trained,\n3 features)",
               "time_since_\nlast_high==0\n(no fit)",
               "alert_rate_\n1min>=cap\n(no fit)"]
recalls2 = [float(left_rows["behav_only"]["ait_recall"]), recall_tsh, recall_ar]
fprs2 = [float(left_rows["behav_only"]["ait_fpr"]), fpr_tsh, fpr_ar]
x2 = np.arange(3)
b1 = ax.bar(x2 - w / 2, recalls2, width=w, color=figstyle.BLUE,
            hatch=figstyle.HATCHES[0], edgecolor=figstyle.INK_PRIMARY, zorder=3)
b2 = ax.bar(x2 + w / 2, fprs2, width=w, color=figstyle.ORANGE,
            hatch=figstyle.HATCHES[1], edgecolor=figstyle.INK_PRIMARY, zorder=3)
for bars, vals in [(b1, recalls2), (b2, fprs2)]:
    for bar, v in zip(bars, vals):
        ax.annotate(f"{v:.4f}", (bar.get_x() + bar.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 3), ha="center",
                    va="bottom", fontsize=6)
ax.set_xticks(x2)
ax.set_xticklabels(rule_labels, fontsize=6.5)
ax.set_ylim(0, 1.22)
ax.set_ylabel("rate (AIT-ADS eval split)")
ax.set_title("Unfitted single-feature rate thresholds\nseparate AIT-ADS without training", fontsize=7.5)

fig.suptitle("")
handles = [
    plt.Rectangle((0, 0), 1, 1, facecolor=figstyle.BLUE, hatch=figstyle.HATCHES[0],
                  edgecolor=figstyle.INK_PRIMARY, label="Recall"),
    plt.Rectangle((0, 0), 1, 1, facecolor=figstyle.ORANGE, hatch=figstyle.HATCHES[1],
                  edgecolor=figstyle.INK_PRIMARY, label="FPR"),
]
fig.legend(handles=handles, loc="upper center", ncol=2, frameon=False,
           bbox_to_anchor=(0.5, 0.99), fontsize=7)
fig.tight_layout(rect=(0, 0, 1, 0.95))
figstyle.save(fig, "fig3a_ablation_separability")
