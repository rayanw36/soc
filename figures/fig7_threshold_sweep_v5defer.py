"""
fig7_threshold_sweep_v5defer.py -- Fig 7: threshold sweep for the deployed
v5+defer production config.

Panel A -- L1 (XGBoost) threshold sweep, KNOWN attacks (rules 31101/31151)
vs. fresh benign, theta_ocsvm held fixed at the deployed value. Both rules
are in the defer set, so the combined decision for the attack side is
L2-only regardless of theta_xgb: recall is exactly flat by construction
(TP=2026, FN=20224 for every one of the 400 swept values -- verified
directly from threshold_sweep.csv, not just asserted). That flatness IS
the finding: rule-31101/31151 detection cannot be tuned via L1 once defer
is active, because L1 never gets a vote for these rules.

FIG-D F2: the flat 9.11% (2026/22250) is the v5+defer COMBINED DECISION's
recall on the KNOWN population (31101 n=20,665 + 31151 n=1,585 combined),
a different scope from two other recall numbers already in this project
that sound similar but are not comparable without a label:
  - 99.96% (eval_set_definition.md block v1): rule 31101's RAW L1 recall
    (XGBoost alone, no defer applied) -- a diagnostic number, not what the
    deployed pipeline achieves, since defer overrides L1 for this rule.
  - ~2% (2.25%, same table): rule 31101's deployed v5+defer recall --
    equal to its L2-only recall, since defer fully suppresses L1's vote.
This panel's 9.11% is neither of those -- it is the volume-weighted BLEND
of TWO very different per-rule L2 recalls: rule 31101 (n=20,665,
L2 recall 2.25%) and rule 31151 (n=1,585, L2 recall 98.49%,
`eval_set_definition.md` block v2's canonical per-rule table). Verified
directly (not assumed) that a specific alternative hypothesis -- that
31151's L1 vote escapes defer while 31101's does not -- is FALSE: live
recomputation against the production models confirms both rules are
100% deferred (agent_criticality==1.0 for all 22,250 known-attack rows;
both rule_ids in the defer set), so 100% of Panel A's known-attack
predictions are L2-only for both rules. The real mechanism is per-rule
L2 recall heterogeneity plus a 13:1 volume imbalance (20,665:1,585)
toward the low-recall rule, not an L1-suppression escape. Arithmetic
check: 20,665 x 2.25% + 1,585 x 98.49% = 465 + 1,561 = 2,026, matching
threshold_sweep.csv's Panel-A TP exactly. Full verification transcript:
fig_followups.md F2.

FPR in this panel is NOT flat (range 18-47 FP of 267 fresh benign rows,
i.e. 6.7%-17.6%) -- checked directly rather than assumed from the
producing script's own docstring, which describes only the attack side as
defer-invariant. The benign population scored here is the WHOLE fresh
Linux benign collection (fnr_tp_threshold_v5defer.py: `benign = Xb.copy()`),
not restricted to rule 31101 benign rows; per Fig 6, only ~78% of that
collection is rule 31101 (31151 has zero benign representation), so the
other ~22% (rules 5501/5502/5402/550/etc.) are NOT deferred and their L1
vote still responds to theta_xgb, moving the aggregate FPR as it sweeps.

Panel B -- L2 (OC-SVM) threshold sweep, NOVEL attacks (5710/5712/550/553/
554/5901/5902/5903) vs. the same fresh benign, theta_xgb held fixed at the
deployed value. Most novel rows keep a live L1 contribution OR'd with the
swept L2 decision -- this panel shows a genuine recall/FPR trade-off.

Source: newCol/threshold_sweep.csv (already-committed sweep output,
columns panel/threshold/tp/fn/fp/tn) -- replotted only, sweep itself is
not rerun. Deployed operating thresholds (vertical reference lines) read
directly from models_v2/thresholds_production_v3.json. Config identity
(models_v2/xgb_model.pkl, ocsvm_nu05.pkl, rule_confound_fixes_v5.json)
per newCol/fnr_tp_threshold_v5defer.py's own docstring -- this is the
per-project figure_inventory.md flags as "current, publication-quality
as-is, no outstanding caveat," replotted here in the manuscript's shared
style rather than reusing the legacy PNG directly.
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
import pandas as pd

SWEEP = _p("analysis/threshold_sweep.csv")
THRESH = _p("models_v2/thresholds_production_v3.json")

df = pd.read_csv(SWEEP)
df["recall"] = df["tp"] / (df["tp"] + df["fn"])
df["fpr"] = df["fp"] / (df["fp"] + df["tn"])

with open(THRESH) as f:
    thr = json.load(f)
theta_xgb, theta_ocsvm = thr["theta_xgb"], thr["theta_ocsvm"]

print(f"source: {SWEEP}")
for panel in ["A_known_L1_sweep", "B_novel_L2_sweep"]:
    sub = df[df.panel == panel]
    print(f"  {panel}: n_rows={len(sub)}, recall range=[{sub.recall.min():.4f}, "
          f"{sub.recall.max():.4f}], fpr range=[{sub.fpr.min():.4f}, {sub.fpr.max():.4f}]")
a = df[df.panel == "A_known_L1_sweep"]
assert a.tp.nunique() == 1 and a.fn.nunique() == 1, "Panel A recall not flat -- check sweep"
print(f"  Panel A recall confirmed flat by construction: TP={a.tp.iloc[0]} FN={a.fn.iloc[0]} "
      f"(constant across all {len(a)} swept thresholds)")
print(f"  Panel A FPR is NOT flat: FP range=[{a.fp.min()}, {a.fp.max()}] of "
      f"{a.fp.iloc[0] + a.tn.iloc[0]} benign rows -- the benign side includes "
      "non-deferred rule populations (see script docstring)")
print(f"source: {THRESH}")
print(f"  theta_xgb={theta_xgb}, theta_ocsvm={theta_ocsvm}")

fig, axes = plt.subplots(1, 2, figsize=(figstyle.DOUBLE_COL_W * 0.95, 3.2))

panel_spec = [
    ("A_known_L1_sweep", "threshold ($\\theta_{xgb}$)", theta_xgb,
     "Panel A: v5+defer combined decision,\nknown attacks (31101+31151 blended)"),
    ("B_novel_L2_sweep", "threshold ($\\theta_{ocsvm}$)", theta_ocsvm,
     "Panel B: L2 sweep, novel attacks\n-- genuine recall/FPR trade-off"),
]
for ax, (panel, xlabel, theta, title) in zip(axes, panel_spec):
    sub = df[df.panel == panel].sort_values("threshold")
    ax.plot(sub.threshold, sub.recall, color=figstyle.BLUE, lw=1.6, label="recall", zorder=3)
    ax.plot(sub.threshold, sub.fpr, color=figstyle.ORANGE, lw=1.6, label="FPR", zorder=3)
    ax.axvline(theta, color=figstyle.INK_PRIMARY, lw=1.0, ls="--", zorder=2)
    ax.set_xlabel(xlabel)
    ax.set_ylim(-0.02, 1.02)
    ax.set_title(title, fontsize=7.8)

recall_a = float(a.tp.iloc[0]) / (float(a.tp.iloc[0]) + float(a.fn.iloc[0]))
axes[0].annotate(
    f"{recall_a*100:.1f}% = blend of rule 31101\n(2.25% of n=20,665) and 31151\n"
    "(98.49% of n=1,585) -- not a\nthird, contradicting recall number",
    xy=(0.5, recall_a), xytext=(0.42, 0.42),
    fontsize=6, color=figstyle.INK_SECONDARY, ha="left",
    arrowprops=dict(arrowstyle="->", color=figstyle.INK_MUTED, lw=0.7),
)

axes[0].set_ylabel("rate")
handles = [
    plt.Line2D([0], [0], color=figstyle.BLUE, lw=1.6, label="recall"),
    plt.Line2D([0], [0], color=figstyle.ORANGE, lw=1.6, label="FPR"),
    plt.Line2D([0], [0], color=figstyle.INK_PRIMARY, lw=1.0, ls="--", label="deployed threshold"),
]
fig.legend(handles=handles, loc="upper center", ncol=3, frameon=False,
           bbox_to_anchor=(0.5, 0.99), fontsize=7)
fig.tight_layout(rect=(0, 0, 1, 0.90))
figstyle.save(fig, "fig7_threshold_sweep_v5defer")
