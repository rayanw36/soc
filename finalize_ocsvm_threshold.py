"""
finalize_ocsvm_threshold.py
===========================
TASK 1: lock in the production OC-SVM(nu=0.05) threshold.

Reads the diagnostic threshold from anomaly_model_comparison.csv, re-verifies it
against the SAME held-out benign + 43 novel split (reused from
combined_decision_v3.load_eval_split), and writes thresholds_production_v3.json.

Run:  ~/soc_project/.venv/bin/python finalize_ocsvm_threshold.py
"""

import json

import numpy as np
import pandas as pd
import joblib

from combined_decision_v3 import load_eval_split, ocsvm_anomaly_score
from shared_constants_v2 import FEATURE_COLS_V2

MODELS, RESULTS = "models_v2", "results_v2"


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


# ---------------------------------------------------------------------------
hr("1-2. THRESHOLD FROM DIAGNOSTIC (anomaly_model_comparison.csv)")
cmp = pd.read_csv(f"{RESULTS}/anomaly_model_comparison.csv").set_index("model")
row = cmp.loc["OCSVM(nu=0.05)"]
theta_ocsvm = float(row["threshold_10pct"])
diag_recall = float(row["recall_at_10pct_fpr"])
diag_fpr = float(row["achieved_fpr_10"])
diag_f1 = float(row["best_f1"])
diag_recall5 = float(row["recall_at_5pct_fpr"])
print(f"  theta_ocsvm = {theta_ocsvm:.4f}")
print(f"  diagnostic OCSVM(nu=0.05): recall@10%FPR={diag_recall*100:.1f}%  "
      f"FPR={diag_fpr*100:.2f}%  F1={diag_f1:.3f}  recall@5%FPR={diag_recall5*100:.1f}%")
print("\n  [HONESTY FLAG] The task brief cited '76.7% recall' for nu=0.05, but that")
print("  figure belongs to nu=0.10/0.15. nu=0.05 actually achieves 72.1% @10%FPR.")
print("  nu=0.05 was still selected because it has the BEST F1 (0.608) and is the")
print("  ONLY variant stable across the FPR budget (72.1% at BOTH 5% and 10% FPR).")

# ---------------------------------------------------------------------------
hr("3. RE-VERIFY ON THE SAME HELD-OUT BENIGN + 43 NOVEL SPLIT")
ocsvm = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")
scaler = joblib.load(f"{MODELS}/scaler_v2.pkl")
imputer = joblib.load(f"{MODELS}/imputer_v2.pkl")
test_benign, novel = load_eval_split()


def score(Xraw):
    Xs = scaler.transform(imputer.transform(Xraw))
    return ocsvm_anomaly_score(ocsvm, Xs)


ben_s = score(test_benign)
nov_s = score(novel[FEATURE_COLS_V2].values)
recall = float((nov_s >= theta_ocsvm).mean())
fpr = float((ben_s >= theta_ocsvm).mean())
tp = int((nov_s >= theta_ocsvm).sum()); fn = len(nov_s) - tp
fp = int((ben_s >= theta_ocsvm).sum()); tn = len(ben_s) - fp
prec = tp / (tp + fp) if (tp + fp) else 0.0
f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
print(f"  reproduced @ theta_ocsvm={theta_ocsvm:.4f}: recall={recall*100:.1f}%  "
      f"FPR={fpr*100:.2f}%  F1={f1:.3f}   (benign n={len(ben_s)}, novel n={len(nov_s)})")

# ---------------------------------------------------------------------------
hr("4. REPRODUCIBILITY CHECK (vs diagnostic, tolerance 2pp)")
d_recall = abs(recall - diag_recall) * 100
d_fpr = abs(fpr - diag_fpr) * 100
print(f"  |recall - diagnostic| = {d_recall:.2f}pp   |FPR - diagnostic| = {d_fpr:.2f}pp")
if d_recall > 2.0 or d_fpr > 2.0:
    print("\n  *** WARNING: reproduced numbers differ from the diagnostic by >2pp. ***")
    print("  *** STOPPING — investigate reproducibility before locking threshold. ***")
    raise SystemExit(1)
print("  OK — within 2pp tolerance. Threshold is reproducible; locking it in.")

# ---------------------------------------------------------------------------
hr("5. WRITE thresholds_production_v3.json")
with open(f"{MODELS}/thresholds_v2.json") as fh:
    theta_xgb = float(json.load(fh)["theta_global"])     # R2/cost-optimal L1 threshold
print(f"  theta_xgb (from thresholds_v2.json theta_global, R2-optimal) = {theta_xgb:.5f}")

prod = {
    "theta_xgb": theta_xgb,
    "theta_ocsvm": theta_ocsvm,
    "zero_day_layer": "ocsvm_nu05",
    "zero_day_layer_replaced": "memae",
    "ocsvm_recall_at_10pct_fpr": round(recall, 4),
    "ocsvm_fpr_at_threshold": round(fpr, 4),
    "ocsvm_best_f1": round(diag_f1, 4),
    "note_on_recall": ("nu=0.05 achieves 72.1% recall @10%FPR (NOT the 76.7% sometimes "
                       "quoted — that was nu=0.10); chosen for best F1 (0.608) and "
                       "stability across 5%/10% FPR."),
    "known_limitations": [
        "T1548.001 SUID discovery not detected by any tested anomaly model — feature gap, not threshold issue"
    ],
    "novel_attack_sample_size": int(len(novel)),
    "novel_attack_techniques_represented": int(novel.technique.nunique()),
    "novel_attack_techniques_total": 14,
    "validation_status": "provisional — pending re-run of 8 empty attack windows",
}
with open(f"{MODELS}/thresholds_production_v3.json", "w") as fh:
    json.dump(prod, fh, indent=2)
print(f"  Saved {MODELS}/thresholds_production_v3.json")
print(json.dumps(prod, indent=2))
