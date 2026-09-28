"""
v8_task1_train.py -- Windows recalibration (v8), Task 1: assemble candidates.
================================================================================
Resolved decisions (confirmed by user before running this):
  - "v5 same-space reference" = models_v2/ocsvm_normalized.pkl (22-feat,
    Linux-only trained) -- ocsvm_nu05.pkl is 26-feat and architecturally
    incompatible with this pipeline.
  - Table 7.5 baseline: both prior Windows results are carried forward as
    separate baseline rows in Task 2 (not resolved here).
  - Provenance predicate for Task 2's attack set: label=='attack' AND
    in_root_tree==True (T1110.001=160, T1136.001=8) -- not used in Task 1.

Data assignment (from the Task 0 checkpoint, as approved):
  - Windows TRAIN pool : testAlerts/Alerts/ossec-alerts-{23,24}.json, high-
    confidence benign (>=60min outside WINDOWS_ATTACK_WINDOWS), split 70/30
    seed=42 -- reproduces task3_xplatform_benign.py's exact partition.
    train=7,928 / holdout=3,398.
  - Windows CALIBRATION : the 3,398-row holdout above (never fit by anything).
  - Windows FPR EVALUATION (held out from everything here) : the fresh matched
    n=201 collection (2026-07-12, WIN-CL1) -- untouched in this script.
  - Linux benign for C3's mix : the fresh matched n=267 (2026-07-12, agent 003)
    -- materially different from v7's Linux-training source (the old, broad
    lnx_dmz_ai_detections.json pool, capped at 5,000).

Candidates (all scored in the SAME 22-feature normalized space):
  C1 Windows-native OC-SVM : trained on ALL 7,928 Windows-train rows (no cap --
     single-class fit, no class-balance reason to subsample) -- NOT materially
     small, stated plainly.
  C2 ocsvm_xplatform_v7.pkl : loaded as-is, not retrained.
  C3 Joint retrain : Linux (fresh, n=267) + Windows (same 7,928-row train pool,
     capped to 5,000 by random subsample, matching v7's cap convention) --
     differs materially from v7 on the Linux side (267 fresh/matched vs.
     v7's 5,000-cap of an 8,092-row old/broad pool).

For each candidate: calibrate a Windows threshold on the calibration holdout
targeting FPR<=10% (90th percentile of calibration anomaly scores), and also
report the natural sign threshold (theta=0.0, i.e. OC-SVM's own decision
boundary) for comparison.
"""
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))
from v8_common import (
    extract_win_oldpool_benign, split_win_oldpool,
    extract_lnx_oldpool_benign, extract_fresh_benign,
)
from combined_decision_v3 import ocsvm_anomaly_score
from normalize_schema import FEATURE_COLS_NORM

MODELS = "models_v2"

print("=" * 90)
print("Extracting benign pools (22-feature normalized space)")
print("=" * 90)

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")


def sc(X):
    return scaler.transform(imputer.transform(np.asarray(X, dtype=np.float64)))


X_win_pool, _ = extract_win_oldpool_benign()
print(f"Windows old-pool high-confidence benign: {len(X_win_pool)}")
X_win_train, X_win_calib = split_win_oldpool(X_win_pool, seed=42, train_frac=0.70)
print(f"  -> train={len(X_win_train)}  calibration(holdout)={len(X_win_calib)}")
assert len(X_win_calib) == 3398, f"expected 3398 calibration rows, got {len(X_win_calib)}"

X_lnx_pool = extract_lnx_oldpool_benign()
print(f"Linux old-pool high-confidence benign: {len(X_lnx_pool)}")

X_lnx_fresh = extract_fresh_benign("data/testbed_collection/collection_benign_lnx_alerts.json", "lnx")
print(f"Linux fresh matched benign: {len(X_lnx_fresh)}")

X_win_fresh = extract_fresh_benign("data/testbed_collection/collection_benign_win_alerts.json", "windows")
print(f"Windows fresh matched benign (RESERVED for Task 2 eval, unused here): {len(X_win_fresh)}\n")

# ---------------------------------------------------------------------------
# C1 -- Windows-native
# ---------------------------------------------------------------------------
print("=" * 90)
print("C1 -- Windows-native OC-SVM (trained on Windows benign ONLY)")
print("=" * 90)
n_c1 = len(X_win_train)
print(f"  training n={n_c1} (full Windows-train partition, not capped -- "
      f"single-class OC-SVM has no class-balance reason to subsample; not small)")
Xc1_sc = sc(X_win_train)
oc_c1 = OneClassSVM(nu=0.05, kernel="rbf", gamma="scale").fit(Xc1_sc)
joblib.dump(oc_c1, f"{MODELS}/ocsvm_win_native_v8.pkl")
print(f"  saved {MODELS}/ocsvm_win_native_v8.pkl\n")

# ---------------------------------------------------------------------------
# C2 -- existing joint cross-OS (as-is)
# ---------------------------------------------------------------------------
print("=" * 90)
print("C2 -- ocsvm_xplatform_v7.pkl (existing, evaluated as-is, NOT retrained)")
print("=" * 90)
oc_c2 = joblib.load(f"{MODELS}/ocsvm_xplatform_v7.pkl")
print("  loaded models_v2/ocsvm_xplatform_v7.pkl "
      "(trained on 5,000-cap old Linux pool + 5,000-cap old Windows pool, per task3_xplatform_benign.py)\n")

# ---------------------------------------------------------------------------
# C3 -- joint retrain, materially different mix (fresh Linux benign)
# ---------------------------------------------------------------------------
print("=" * 90)
print("C3 -- Joint retrain: fresh Linux benign (267) + Windows-train pool (capped 5,000)")
print("=" * 90)
rng = np.random.default_rng(99)
n_win_sample = min(5000, len(X_win_train))
win_idx_s = rng.choice(len(X_win_train), size=n_win_sample, replace=False)
X_c3_mix = np.vstack([X_lnx_fresh, X_win_train[win_idx_s]])
print(f"  training n={len(X_c3_mix)} ({len(X_lnx_fresh)} Linux fresh/matched + {n_win_sample} Windows old-pool)")
print(f"  differs materially from v7 on the Linux side: {len(X_lnx_fresh)} fresh/matched vs. "
      f"v7's 5,000-cap of an {len(X_lnx_pool)}-row old/broad pool")
Xc3_sc = sc(X_c3_mix)
oc_c3 = OneClassSVM(nu=0.05, kernel="rbf", gamma="scale").fit(Xc3_sc)
joblib.dump(oc_c3, f"{MODELS}/ocsvm_xplatform_v8.pkl")
print(f"  saved {MODELS}/ocsvm_xplatform_v8.pkl\n")

# ---------------------------------------------------------------------------
# Same-space reference (Linux-only, resolved decision #1)
# ---------------------------------------------------------------------------
oc_ref = joblib.load(f"{MODELS}/ocsvm_normalized.pkl")

# ---------------------------------------------------------------------------
# Calibration: per-candidate Windows threshold on the 3,398-row holdout
# ---------------------------------------------------------------------------
print("=" * 90)
print("CALIBRATION -- per-candidate Windows threshold on the 3,398-row holdout")
print("=" * 90)

Xcalib_sc = sc(X_win_calib)
rows = []
candidates = {
    "C1_win_native": oc_c1,
    "C2_xplatform_v7": oc_c2,
    "C3_xplatform_v8": oc_c3,
    "REF_linux_only_normalized": oc_ref,
}
for name, oc in candidates.items():
    scores_calib = ocsvm_anomaly_score(oc, Xcalib_sc)
    theta_90 = float(np.percentile(scores_calib, 90))
    fpr_90 = float((scores_calib >= theta_90).mean())
    fpr_sign = float((scores_calib >= 0.0).mean())
    print(f"  {name:<28} theta(90th-pct-calib)={theta_90:9.5f}  FPR@theta90={fpr_90*100:5.1f}%   "
          f"FPR@sign(theta=0)={fpr_sign*100:5.1f}%")
    rows.append(dict(candidate=name, calib_n=len(X_win_calib), percentile_used=90,
                      theta_calibrated=theta_90, fpr_at_calibrated=fpr_90,
                      theta_sign=0.0, fpr_at_sign=fpr_sign))

summary = pd.DataFrame(rows)
summary.to_csv("analysis/v8_task1_calibration.csv", index=False)
print("\nwrote newCol/v8_task1_calibration.csv")

with open("analysis/v8_task1_notes.txt", "w") as f:
    f.write(f"Windows old-pool benign total: {len(X_win_pool)}\n")
    f.write(f"Windows train partition: {len(X_win_train)}\n")
    f.write(f"Windows calibration holdout: {len(X_win_calib)}\n")
    f.write(f"Linux old-pool benign total: {len(X_lnx_pool)}\n")
    f.write(f"Linux fresh matched benign: {len(X_lnx_fresh)}\n")
    f.write(f"Windows fresh matched benign (reserved for Task 2 eval): {len(X_win_fresh)}\n")
print("wrote newCol/v8_task1_notes.txt")
