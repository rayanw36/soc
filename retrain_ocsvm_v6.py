"""
retrain_ocsvm_v6.py
===================
v6 TASK 3 -- retrain Layer-2 (OC-SVM) on the expanded benign baseline so it
stops flagging benign rule-31151/5710 traffic as anomalous.

Same hyperparameters as the validated production model: OneClassSVM(kernel='rbf',
gamma='scale', nu=0.05).

Scaler/imputer: REUSED from models_v2 (scaler_v2.pkl / imputer_v2.pkl), NOT
refit. Rationale -- the same scaler feeds the UNCHANGED XGBoost L1 layer and the
v5 decision logic; refitting on the oversampled baseline would shift the feature
space toward 31151/5710 and silently change L1's inputs too. Keeping the scaler
fixed isolates the change to the OC-SVM alone, which is the whole point of v6.

Leakage safety: training excludes the fixed held-out 20% of the ORIGINAL clean
baseline (RandomState(SEED) split), exactly the rows v5/v6 measure FPR on.

    ~/soc_project/.venv/bin/python retrain_ocsvm_v6.py
"""

import json

import numpy as np
import pandas as pd
import joblib
from sklearn.svm import OneClassSVM

from shared_constants_v2 import FEATURE_COLS_V2, SEED

MODELS, RESULTS = "models_v2", "results_v2"
RID = FEATURE_COLS_V2.index("rule_id_encoded")
TARGET_RULES = (31151, 5710)


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


# ---------------------------------------------------------------------------
# 1. Assemble leakage-safe training matrix from the expanded baseline
# ---------------------------------------------------------------------------
hr("1. TRAIN OC-SVM(nu=0.05) ON EXPANDED BASELINE (held-out excluded)")
man = json.load(open(f"{RESULTS}/_benign_v6_manifest.json"))
n_clean = man["n_clean"]
expanded = pd.read_csv(f"{RESULTS}/benign_baseline_v6.csv")[FEATURE_COLS_V2].values
assert len(expanded) == man["n_total"]

perm = np.random.RandomState(SEED).permutation(n_clean)
n_hold = max(1, int(man["held_out_frac"] * n_clean))
held_out_pos = set(perm[:n_hold].tolist())
train_mask = np.ones(len(expanded), dtype=bool)
for p in held_out_pos:                       # held-out rows live in the first n_clean
    train_mask[p] = False
train_raw = expanded[train_mask]
print(f"  expanded baseline rows : {len(expanded)}")
print(f"  held-out (excluded)    : {n_hold}  (identical to the v5 eval split)")
print(f"  training rows          : {len(train_raw)}  "
      f"(= {n_clean - n_hold} clean-train + {man['n_extra_rows']} oversampled copies)")

scaler = joblib.load(f"{MODELS}/scaler_v2.pkl")
imputer = joblib.load(f"{MODELS}/imputer_v2.pkl")
print("  scaler/imputer: REUSED from models_v2 (NOT refit) -- keeps the feature space")
print("  identical to the unchanged XGBoost L1 and v5 logic; only the OC-SVM changes.")

Xtr = scaler.transform(imputer.transform(train_raw)).astype(np.float64)
oc = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(Xtr)
joblib.dump(oc, f"{MODELS}/ocsvm_nu05_v6.pkl")
print(f"  Trained -> {MODELS}/ocsvm_nu05_v6.pkl  (n_support={int(oc.support_.shape[0])})")


# ---------------------------------------------------------------------------
# 2/3. In-sample sanity check: the oversampled 31151/5710 should now score
#      as non-anomalous under the locked production threshold.
# ---------------------------------------------------------------------------
hr("2-3. SANITY CHECK -- added 31151/5710 now scored non-anomalous (in-sample)")
TOC = float(json.load(open(f"{MODELS}/thresholds_production_v3.json"))["theta_ocsvm"])
print(f"  threshold theta_ocsvm = {TOC:.4f} (unchanged; >=theta => flagged anomalous)")


def anom(X):
    return -oc.decision_function(scaler.transform(imputer.transform(np.asarray(X, float))))


rid_tr = np.round(train_raw[:, RID]).astype(int)
old_oc = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")


def anom_old(X):
    return -old_oc.decision_function(scaler.transform(imputer.transform(np.asarray(X, float))))


for r in TARGET_RULES:
    m = rid_tr == r
    if not m.any():
        continue
    new_fl = float((anom(train_raw[m]) >= TOC).mean())
    old_fl = float((anom_old(train_raw[m]) >= TOC).mean())
    print(f"  rule {r:>5} (n={int(m.sum())} train rows): flagged-anomalous "
          f"old L2 = {old_fl*100:5.1f}%  ->  v6 L2 = {new_fl*100:5.1f}%")
print("  (in-sample, so near-trivially low for v6 -- confirms the model LEARNED this")
print("   traffic. Out-of-sample held-out generalization is measured in validate_v6.py.)")
