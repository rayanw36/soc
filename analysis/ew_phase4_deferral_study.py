"""
ew_phase4_deferral_study.py
=============================
Phase 4, restructured around the deferral result: `models_v2/rule_confound_fixes_v5.json`
routes 4 rule families (31101, 31151, 5710, 5501) away from L1's own verdict on
Linux (agent_criticality==1) and relies on L2 (OC-SVM) alone. This script
establishes WHY each rule is deferred (per-alert L1/L2 baseline), then asks,
per rule, whether EW features can do better than "trust L2 alone" -- honestly,
including reporting when the available data cannot answer that question at all.

No entity-disjoint split exists (Phase 0d: single attacker IP). Split here is
temporal-disjoint WITHIN each collection (train=earlier alerts, test=later),
consistent with the provisional split documented in Phase 3 -- this is still
not the frozen Phase 5a split, and is stated as such.
"""
import os
import sys

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from f1_phaseA_lnx import extract_attack_features, extract_benign_features
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score
from shared_constants_v2 import FEATURE_COLS_V2

models = load_production_models()
TOC, TXG = float(models["theta_ocsvm"]), float(models["theta_xgb"])
oc_v5 = joblib.load(os.path.join(ROOT, "models_v2", "ocsvm_nu05.pkl"))
DEFER = {r for r, s in models["rule_fixes"].items() if s["mech"] == "defer"}

Xa = extract_attack_features()
Xb = extract_benign_features()


def sc(frame):
    return models["scaler"].transform(models["imputer"].transform(frame[FEATURE_COLS_V2].values.astype(float)))


def L2(frame):
    return ocsvm_anomaly_score(oc_v5, sc(frame)) if len(frame) else np.zeros(0)


def L1(frame):
    return models["xgb"].predict_proba(sc(frame))[:, 1] if len(frame) else np.zeros(0)


print("=" * 100)
print("BASELINE: why each defer-mechanism rule is deferred (current v5+defer, per-alert)")
print("=" * 100)
baseline_rows = []
for rid in sorted(str(r) for r in DEFER):
    a = Xa[(Xa.label == "attack") & (Xa.rule_id == rid)]
    b = Xb[Xb.rule_id == rid]
    l2a, l1a = L2(a), L1(a)
    l2b, l1b = L2(b), L1(b)
    row = dict(
        rule=rid, n_attack=len(a), n_benign=len(b),
        l1_recall=float((l1a >= TXG).mean()) if len(a) else float("nan"),
        l2_recall=float((l2a >= TOC).mean()) if len(a) else float("nan"),
        l1_fpr=float((l1b >= TXG).mean()) if len(b) else float("nan"),
        l2_fpr=float((l2b >= TOC).mean()) if len(b) else float("nan"),
    )
    baseline_rows.append(row)
    fpr_str = f"L2 FPR={row['l2_fpr']*100:.2f}%" if len(b) else "L2 FPR=N/A (zero benign alerts of this rule in the collection)"
    print(f"  rule {rid:<8} n_attack={len(a):<7} n_benign={len(b):<5} "
          f"L1 recall={row['l1_recall']*100:6.2f}%  L2 recall={row['l2_recall']*100:6.2f}%  {fpr_str}")

pd.DataFrame(baseline_rows).to_csv(os.path.join(HERE, "ew_phase4_deferral_baseline.csv"), index=False)

print("\n  -> 31151 and 5710 have ZERO benign alerts of that rule in the fresh collection.")
print("     Any EW-vs-L2 FPR comparison for those two rules is NOT EVALUABLE with current")
print("     data -- reported as a hard scope limitation, not worked around. Flagged for Phase 6.")

# ---------------------------------------------------------------------------
# 5501: the one other rule (besides 31101, already done in Phase 3) with both
# attack AND benign representation. EW-augmented arm vs "trust L2 alone".
# ---------------------------------------------------------------------------
print("\n" + "=" * 100)
print("5501 CASE STUDY: EW-augmented arm vs. L2-alone baseline")
print("=" * 100)

aug = pd.read_csv(os.path.join(HERE, "ew_features", "ew_augmented_per_alert.csv"), low_memory=False)
a5501 = aug[(aug.source == "lnx_attack") & (aug.rule_id == 5501) & (aug.label == "attack")].copy()
b5501 = aug[(aug.source == "lnx_benign") & (aug.rule_id == 5501)].copy()
print(f"n_attack={len(a5501)}  n_benign={len(b5501)}")
print(f"user field: attack={a5501['user'].unique().tolist()}  benign={b5501['user'].unique().tolist()}")

# GLOBAL block is testbed-density confounded for EVERY Linux rule (it is
# host-wide, not rule-specific -- see finding below); only the USER block is
# usable here, since 31101 (the volume driver) never carries a user, so
# lnx-dmz's own trailing history is NOT contaminated by the scan burst.
global_medians_check = dict(
    attack=a5501["ew_global_trail60m_alert_count"].median(),
    benign=b5501["ew_global_trail60m_alert_count"].median(),
)
print(f"\nGLOBAL block confound check: ew_global_trail60m_alert_count "
      f"attack median={global_medians_check['attack']:.0f}  benign median={global_medians_check['benign']:.0f} "
      f"-- same {global_medians_check['attack']/global_medians_check['benign']:.0f}x gap as 31101's, "
      f"confirming this is a HOST-WIDE confound affecting every Linux rule, not something specific "
      f"to 31101. GLOBAL-block features excluded from the 5501 classifier for this reason.")

user_feat_cols = [c for c in aug.columns if c.startswith("ew_user_trail60m_")] + ["ew_user_present"]
print(f"\ntraining on {len(user_feat_cols)} USER-block-only EW features (GLOBAL block excluded)")

a5501["ts_parsed"] = pd.to_datetime(a5501["ts"], utc=True, format="ISO8601")
b5501["ts_parsed"] = pd.to_datetime(b5501["ts"], utc=True, format="ISO8601")
a5501 = a5501.sort_values("ts_parsed")
b5501 = b5501.sort_values("ts_parsed")
a5501["y"] = 1
b5501["y"] = 0

n_test_a = max(1, round(len(a5501) * 0.3))
n_test_b = max(1, round(len(b5501) * 0.3))
train = pd.concat([a5501.iloc[:-n_test_a], b5501.iloc[:-n_test_b]])
test = pd.concat([a5501.iloc[-n_test_a:], b5501.iloc[-n_test_b:]])
print(f"provisional temporal split: train n={len(train)} (attack={len(train[train.y==1])}, "
      f"benign={len(train[train.y==0])})  test n={len(test)} (attack={len(test[test.y==1])}, "
      f"benign={len(test[test.y==0])})")

clf = xgb.XGBClassifier(n_estimators=50, max_depth=3, learning_rate=0.1,
                         eval_metric="logloss", random_state=42,
                         reg_lambda=0.5, min_child_weight=1)
clf.fit(train[user_feat_cols].values, train["y"].values)
pred = clf.predict(test[user_feat_cols].values)
proba = clf.predict_proba(test[user_feat_cols].values)[:, 1]
tp = int(((test.y == 1) & (pred == 1)).sum())
fn = int(((test.y == 1) & (pred == 0)).sum())
fp = int(((test.y == 0) & (pred == 1)).sum())
tn = int(((test.y == 0) & (pred == 0)).sum())
test_recall = tp / (tp + fn) if (tp + fn) else float("nan")
test_fpr = fp / (fp + tn) if (fp + tn) else float("nan")
print(f"\nEW (user-block-only) test result: TP={tp} FN={fn} FP={fp} TN={tn}  "
      f"recall={test_recall*100:.1f}%  FPR={test_fpr*100:.1f}%  (n_test={len(test)})")
imp = pd.Series(clf.feature_importances_, index=user_feat_cols).sort_values(ascending=False)
print("top-5 feature importances:\n", imp.head(5).to_string())

print(f"\nCOMPARISON (same rule, same collections, n this small on both sides so read as a "
      f"sanity check not a validated result):")
row5501 = next(r for r in baseline_rows if r["rule"] == "5501")
print(f"  L2-alone baseline (full n): recall={row5501['l2_recall']*100:.2f}%  FPR={row5501['l2_fpr']*100:.2f}%")
print(f"  EW user-block classifier (test split only, n={len(test)}): "
      f"recall={test_recall*100:.1f}%  FPR={test_fpr*100:.1f}%")

print("\nPhase 4 deferral-study script complete.")
