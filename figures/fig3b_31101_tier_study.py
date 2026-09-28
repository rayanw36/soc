"""
fig3b_31101_tier_study.py -- Fig 3b: on raw HTTP fields for rule 31101,
identity (Tier A: exact User-Agent) separates perfectly; structural
properties (Tier B) do not.

Split out of an earlier combined draft (fig3_two_level_identity.py) --
kept as its own figure with its own claim, rather than paired against the
26-feature ablation panel (now fig3a), which showed a different and
partly-conflicting result (identity removal changing nothing there).
These are two separate checks, on two different representations, and are
captioned as such.

Revision note (FIG-C Task 4): the in-figure footnote text (trivial-
baseline restatement and Tier C reference note) has been removed from
the rendered PDF/PNG and moved to captions.md as the LaTeX \caption{}
body. The trivial baseline is still shown in-figure as a dashed
reference line with an inline label (kept -- it points at a specific
plot element, not caption prose); only the explanatory footnote
paragraph was removed.

Source: newCol/fr_31101_report.md Task 3 table (values transcribed from
that frozen, already-computed table; the underlying evaluation is not
rerun here) and newCol/fr_31101_features.csv (used only to confirm n).
Tier C is not plotted as a third recall/FPR bar -- the FR-31101 report
itself did not evaluate it as a per-alert classifier (Task 2 scopes it
"reference only": a single alert cannot have a "distinct path count").
It is footnoted, sourced from the committed per-alert entity-window
feature CSV, recomputed and checked to match ew_phase3_31101_case_study.md
section 3b's printed value before use.
"""
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

FR_FEATURES = _p("analysis/fr_31101_features.csv")
EW_PER_ALERT = _p("analysis/ew_phase3_31101_per_alert_combined.csv")

print("source: ../fr_31101_report.md Task 3 table (TP/FN/FP/TN transcribed, "
      "recall/FPR/F1 recomputed here from those counts only, as a display "
      "convenience -- not a re-evaluation)")
TIER_COUNTS = {
    "A": (3464, 0, 0, 42),
    "B": (3464, 0, 28, 14),
}
TRIVIAL_COUNTS = (3464, 0, 42, 0)


def recall_fpr(tp, fn, fp, tn):
    return tp / (tp + fn), fp / (fp + tn)


tier_recall_fpr = {t: recall_fpr(*c) for t, c in TIER_COUNTS.items()}
trivial_recall, trivial_fpr = recall_fpr(*TRIVIAL_COUNTS)
for t, (r, fp) in tier_recall_fpr.items():
    print(f"  Tier {t}: recall={r:.4f} FPR={fp:.4f}")
print(f"  trivial baseline: recall={trivial_recall:.4f} FPR={trivial_fpr:.4f}")

fr_df = pd.read_csv(FR_FEATURES)
n_attack_test = ((fr_df.split == "test") & (fr_df.cls == "attack")).sum()
n_benign_test = ((fr_df.split == "test") & (fr_df.cls == "benign")).sum()
assert n_attack_test == 3464 and n_benign_test == 42
print(f"  confirmed against {FR_FEATURES}: test n_attack={n_attack_test}, "
      f"n_benign={n_benign_test}")

ew_df = pd.read_csv(EW_PER_ALERT)
ew_feat = "ew_global_trail60m_distinct_url_count"
ew_a = ew_df[ew_df.label == "attack"][ew_feat].median()
ew_b = ew_df[ew_df.label == "benign"][ew_feat].median()
ew_ratio = ew_a / ew_b
print(f"source: {EW_PER_ALERT}")
print(f"  {ew_feat}: attack median={ew_a}, benign median={ew_b}, "
      f"ratio={ew_ratio:.1f}x (matches ew_phase3_31101_case_study.md 3b: 1,519x)")
assert abs(ew_ratio - 1519) < 1

fig, ax = plt.subplots(figsize=(figstyle.SINGLE_COL_W * 1.15, 3.0))

tiers = ["A", "B"]
tier_labels = ["Tier A\n(identity:\nexact UA)", "Tier B\n(structural)"]
x = np.arange(len(tiers))
w = 0.35
recalls = [tier_recall_fpr[t][0] for t in tiers]
fprs = [tier_recall_fpr[t][1] for t in tiers]

b1 = ax.bar(x - w / 2, recalls, width=w, color=figstyle.BLUE,
            hatch=figstyle.HATCHES[0], edgecolor=figstyle.INK_PRIMARY, zorder=3)
b2 = ax.bar(x + w / 2, fprs, width=w, color=figstyle.ORANGE,
            hatch=figstyle.HATCHES[1], edgecolor=figstyle.INK_PRIMARY, zorder=3)
fpr_labels = {"A": "0.0000\n(0/42)", "B": "0.6667\n(28/42)"}
for bar, v in zip(b1, recalls):
    ax.annotate(f"{v:.4f}", (bar.get_x() + bar.get_width() / 2, v),
                textcoords="offset points", xytext=(0, 3), ha="center",
                va="bottom", fontsize=7)
for bar, t in zip(b2, tiers):
    ax.annotate(fpr_labels[t], (bar.get_x() + bar.get_width() / 2, fprs[tiers.index(t)]),
                textcoords="offset points", xytext=(0, 3), ha="center",
                va="bottom", fontsize=6.5, linespacing=1.3)

ax.axhline(trivial_fpr, color=figstyle.INK_MUTED, lw=1.0, ls="--", zorder=2)
ax.text(1.32, trivial_fpr + 0.03, "trivial \"always-\nattack\" baseline",
        fontsize=6.5, color=figstyle.INK_MUTED, va="bottom", ha="left")

ax.set_xticks(x)
ax.set_xticklabels(tier_labels, fontsize=7.5)
ax.set_ylim(0, 1.3)
ax.set_xlim(-0.6, 2.15)
ax.set_ylabel("rate (rule-31101 held-out test:\nn=3,464 attack / n=42 benign)")
ax.set_title("Raw HTTP tier study, rule 31101\n(FR-31101 check)", fontsize=8.5)

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
figstyle.save(fig, "fig3b_31101_tier_study")
