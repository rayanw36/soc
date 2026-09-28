"""
v5_temporal_task0.py -- v5 Temporal-Leakage Check, Task 0: reproduce Table 7.1.

Source of the technique predicate: newCol/verify_labels_lnx.py section 2.3
("ARTIFACT-PATH CONFUSION"), confirmed to match the published Section 6.2
confusion matrix diagonal (6,6,151,6,6) exactly, 100% agreement, 0 mislabeled.
That validates labeled_lnx.csv's `technique` column (time-window assignment)
as path-derived ground truth for the FIM alerts. Under that SAME predicate,
discriminative-rule counts give T1110.001=119 and T1136.001=163 -- matching
the other two n's you named. Predicate: attack-labeled alerts, discriminative
rule set {550,553,554,5710,5712,5901,5902,5903,31101,31104,31151,31516},
grouped by the `technique` column.

Pipeline: 26-feature xgb_model.pkl + ocsvm_nu05.pkl (v5) + rule_confound_fixes_v5.json
defer, at thresholds_production_v3.json (theta_xgb=0.07538, theta_ocsvm=-0.33500).
"""
import os
import sys
import json

import joblib
import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

import shared_features
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, extract_features_v2
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score, score_alert
from label_lnx_timeonly import event_time as lnx_event_time

HERE = "newCol"
MODELS = "models_v2"

DISC_RULES = {"550", "553", "554", "5710", "5712", "5901", "5902", "5903",
              "31101", "31104", "31151", "31516"}
FIM_TECHS = {"T1053.003": "cron", "T1543.002": "systemd", "T1546.004": "shell-rc",
             "T1098.004": "ssh-key"}
OTHER_TECHS = {"T1110.001": "T1110.001", "T1136.001": "T1136.001"}

models = load_production_models()
oc_v5 = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")
models["ocsvm"] = oc_v5
models["ocsvm_version"] = "v5 (ocsvm_nu05.pkl) + defer"
TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])
print(f"theta_xgb={TXG:.5f}  theta_ocsvm={TOC:.5f}  L2={models['ocsvm_version']}")
print(f"confound-fix defer rules: {sorted(r for r,s in models['rule_fixes'].items() if s['mech']=='defer')}\n")

# ---------------------------------------------------------------------------
# Extract 26-feature vectors, event-time ordered, AgentHistory (same as always)
# ---------------------------------------------------------------------------
raw = []
with open(f"{HERE}/collection_lnx_alerts.json") as fh:
    for idx, line in enumerate(fh):
        a = json.loads(line)
        raw.append((idx, lnx_event_time(a)[0], a.get("agent", {}).get("name", "unknown"), a))
order = sorted(range(len(raw)), key=lambda i: (raw[i][1], raw[i][0]))

feats = [None] * len(raw)
hist = {}
for i in order:
    idx, ts, agent, a = raw[i]
    h = hist.setdefault(agent, AgentHistory())
    feats[idx] = extract_features_v2(a, h.compute_features(ts))
    h.add(a, ts)

lab = pd.read_csv(f"{HERE}/labeled_lnx.csv", dtype={"rule_id": str})
assert len(lab) == len(feats)
X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
for c in ("label", "technique", "rule_id"):
    X[c] = lab[c].values

disc = X[(X.label == "attack") & (X.rule_id.isin(DISC_RULES))].copy()
print("Discriminative attack-alert counts by technique (the predicate):")
print(disc.groupby("technique").size().sort_values(ascending=False))
print()


def sc(df):
    return models["scaler"].transform(models["imputer"].transform(df[FEATURE_COLS_V2].values.astype(float)))


def production_decisions(df):
    l1, l2, comb = [], [], []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, models)
        l1.append(r["category"] == "known_attack")
        l2.append(r["ocsvm_anomaly_score"] >= TOC)
        comb.append(r["decision"] != "P4_suppress")
    return np.array(l1, bool), np.array(l2, bool), np.array(comb, bool)


print("=" * 90)
print("REPRODUCED TABLE 7.1 (v5+defer, technique-column predicate)")
print("=" * 90)
rows = []
for tech in list(FIM_TECHS) + list(OTHER_TECHS):
    sub = disc[disc.technique == tech]
    if not len(sub):
        print(f"  {tech}: NO alerts under this predicate")
        continue
    l1, l2, comb = production_decisions(sub)
    n = len(sub)
    print(f"  {tech:<12} n={n:<4} L1={int(l1.sum())}/{n}  L2={int(l2.sum())}/{n}  "
          f"either={int(comb.sum())}/{n}")
    rows.append(dict(technique=tech, n=n, l1_detected=int(l1.sum()), l2_detected=int(l2.sum()),
                      either_detected=int(comb.sum())))

pd.DataFrame(rows).to_csv(f"{HERE}/v5_temporal_task0_reproduction.csv", index=False)
print(f"\nwrote {HERE}/v5_temporal_task0_reproduction.csv")
