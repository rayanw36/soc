"""
fig9_cross_detector_lookup.py -- Fig 9: majority-label-per-signature
lookup-table F1 vs. a model baseline (where one exists) vs. a trivial
always-predict-attack baseline, grouped by detector: Wazuh-native,
Suricata (embedded in Wazuh rule 86601), AMiner.

REVISION (FIG9-M Task 1, supersedes the original recall-based version):
the original figure plotted recall only. A trivial always-predict-attack
classifier scores recall=1.000 on every detector regardless of base rate,
so a bare recall comparison cannot distinguish signature-identity
memorization from class imbalance -- this is the same trivial-baseline
problem Fig 3b already handles correctly for rule 31101, and it was not
being handled here. Rebuilt on F1 (which folds in precision, and so does
penalize the trivial baseline's poor precision at low base rates), with
the trivial baseline drawn as its own bar per detector group -- base
rates differ sharply across detectors (74.7% Wazuh-native, 1.9% Suricata,
84.7% AMiner), so a single shared reference line would be wrong; each
group needs its own baseline.

AMINER MODEL BAR (FIG9-M Task 2, changed from the original "n/a"):
no Wazuh-style 26-feature vector exists for AMiner alerts (native fields
are AnalysisComponentName/LogData/AMiner.ID, not Wazuh rule JSON) -- this
is a structural gap, not one the audit chose not to close. What *is* now
shown is a deliberately minimal, identity-free model fit on 5 non-identity
AMiner fields (raw_log_len, log_lines_count, and 3 causal per-source
temporal features) -- built and reported per FIG9-M Task 2, marked with a
dagger in-figure because it is NOT constructed the same way as the
Wazuh-native/Suricata model bars (those include rule/signature-identity
features; this one deliberately excludes all of them). It is the only
"model" bar in this figure that answers a genuinely different question
("how far can non-identity signal alone go") rather than "does adding a
trained model beat the lookup table on the same feature space."

METRIC-SCOPE NOTE (unchanged from the original): full P/R/F1/FPR for
every group (lookup, model, trivial) are committed in
newCol/fig9m_task1_results.json and newCol/fig9m_task2_aminer_model_results.json;
this figure plots F1 only, to keep one comparable metric across all three
detectors and both baselines on one axis.

MODEL BASELINE IS AN AUDIT-TIME RETRAIN, NOT THE DEPLOYED MODEL (Wazuh-
native/Suricata only, unchanged from the original): models_v2/xgb_model.pkl's
predict_proba is degenerate on ait_split.npz's raw (unscaled) X_test --
NOTE, corrected since the original version of this figure: this was
root-caused in REV-C Task 4 to a SCALING bug in the scoring scripts (raw
features fed to a model trained on StandardScaler-transformed ones), not
an XGBoost version mismatch as earlier drafts of this figure claimed;
scored correctly (through models_v2/scaler_v2.pkl + imputer_v2.pkl) the
deployed pickle reproduces F1=0.9945 on the full AIT-ADS eval split,
matching the audit retrain. The Wazuh-native/Suricata "Model" bars here
remain the audit-time retrain (exp4_ablation.py-style, 26 features, theta
selected by max-F1 on the eval split, NOT theta_xgb) because that is what
newCol/xdet_task1_results.json already committed broken out by rule
86601 vs. Wazuh-native; the deployed pickle was not rescored per-subset
for this figure, since the audit-retrain number already used is
independently known (via the correction above) to closely track it.
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

TASK1 = _p("analysis/fig9m_task1_results.json")
TASK2 = _p("analysis/fig9m_task2_aminer_model_results.json")
XDET = _p("analysis/xdet_task1_results.json")

with open(TASK1) as f:
    t1 = json.load(f)
with open(TASK2) as f:
    t2 = json.load(f)
with open(XDET) as f:
    xdet = json.load(f)

print(f"source: {TASK1}, {TASK2}, {XDET}")

rows = {r["detector"]: {} for r in t1["rows"]}
for r in t1["rows"]:
    rows[r["detector"]][r["series"]] = r

groups = ["Wazuh-native", "Suricata", "AMiner"]
group_labels = ["Wazuh-native", "Suricata\n(Wazuh rule 86601)", "AMiner"]

lookup_f1 = [rows[g]["lookup"]["f1"] for g in groups]
trivial_f1 = [rows[g]["trivial"]["f1"] for g in groups]
model_f1 = [
    rows["Wazuh-native"]["model"]["f1"],
    rows["Suricata"]["model"]["f1"],
    t2["f1"],  # AMiner: minimal non-identity model, NOT the same construction
]
aminer_model_is_special = True

n_per_group = [
    xdet["wazuh_native"]["n_eval"],
    xdet["suricata"]["n_eval"],
    xdet["aminer"]["n_eval"],
]
base_rate_per_group = [
    rows["Wazuh-native"]["trivial"]["precision"],
    rows["Suricata"]["trivial"]["precision"],
    rows["AMiner"]["trivial"]["precision"],
]

for g, lf, mf, tf, n, br in zip(groups, lookup_f1, model_f1, trivial_f1, n_per_group, base_rate_per_group):
    print(f"  {g}: n={n:,} base_rate={br:.4f}  lookup F1={lf:.4f}  model F1={mf:.4f}  trivial F1={tf:.4f}"
          f"  (lookup-trivial={lf-tf:+.4f})")

x = np.arange(len(groups))
width = 0.26

fig, ax = plt.subplots(figsize=(figstyle.DOUBLE_COL_W * 0.68, 3.2))

bars_l = ax.bar(x - width, lookup_f1, width, label="Lookup table\n(signature only)",
                 color=figstyle.BLUE, hatch=figstyle.HATCHES[0],
                 edgecolor=figstyle.INK_PRIMARY, zorder=3)
bars_m = ax.bar(x, model_f1, width, label="Model\n(audit-time retrain;\nAMiner: non-identity only†)",
                 color=figstyle.ORANGE, hatch=figstyle.HATCHES[1],
                 edgecolor=figstyle.INK_PRIMARY, zorder=3)
bars_t = ax.bar(x + width, trivial_f1, width, label="Trivial\n(always predict attack)",
                 color=figstyle.INK_MUTED, hatch=figstyle.HATCHES[4],
                 edgecolor=figstyle.INK_PRIMARY, zorder=3, alpha=0.85)

for bars, vals in [(bars_l, lookup_f1), (bars_m, model_f1), (bars_t, trivial_f1)]:
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:.3f}", (b.get_x() + b.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 3),
                    ha="center", va="bottom", fontsize=6.2, color=figstyle.INK_PRIMARY)

# dagger marker on AMiner's model bar (different construction than the other two)
am_idx = groups.index("AMiner")
ax.annotate("†", (bars_m[am_idx].get_x() + bars_m[am_idx].get_width() / 2, model_f1[am_idx]),
            textcoords="offset points", xytext=(15, 8), ha="center", va="bottom",
            fontsize=9, color=figstyle.INK_SECONDARY, fontweight="bold")

ax.set_xticks(x)
ax.set_xticklabels(group_labels, fontsize=7)
ax.set_ylabel("F1 (eval split)")
ax.set_ylim(0, 1.15)
ax.set_axisbelow(True)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.30), ncol=3, frameon=False, fontsize=6.2)
ax.set_title("Signature-identity lookup table vs. model vs. trivial baseline, by detector",
              fontsize=8, pad=40)

fig.tight_layout()
figstyle.save(fig, "fig9_cross_detector_lookup")
