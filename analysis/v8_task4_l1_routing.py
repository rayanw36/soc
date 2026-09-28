"""
v8_task4_l1_routing.py -- Windows recalibration (v8), Task 4: L1 routing decision.
=====================================================================================
No training. Two routings, scored on the SAME provenance-labeled Windows attack set
(168: T1110.001=160, T1136.001=8) and the SAME fresh held-out Windows benign (n=201)
used throughout Tasks 2-3.

  (a) L2-only  : Windows bypasses L1 entirely -- already computed in Task 2
                 (C1/C2/C3 rows), reused here for the comparison.
  (b) L1+L2    : xgb_normalized.pkl (22-feat) recalibrated on the SAME Windows
                 calibration holdout (n=3,398, old cross-session pool) used to
                 calibrate L2 in Task 1 -- targeting FPR<=10%, same 90th-pct
                 convention -- then combined = L1_recalibrated OR L2_calibrated.

Reports L1's OWN recall/FPR contribution (isolated), then the combined-with-L1
numbers for each of C1/C2/C3 against the L2-only numbers already in
newCol/v8_task2_comparison.csv.
"""
import os
import sys

import joblib
import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

from v8_common import extract_win_oldpool_benign, split_win_oldpool, extract_fresh_benign
from f1_phaseB_normalized_crossplatform import _extract_normalized_session
from combined_decision_v6 import ocsvm_anomaly_score
from normalize_schema import FEATURE_COLS_NORM

MODELS = "models_v2"
HERE = "newCol"


def confusion(y_true, y_pred):
    y_true = np.asarray(y_true, bool)
    y_pred = np.asarray(y_pred, bool)
    tp = int((y_true & y_pred).sum())
    fp = int((~y_true & y_pred).sum())
    tn = int((~y_true & ~y_pred).sum())
    fn = int((y_true & ~y_pred).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=prec, recall=rec, f1=f1, fpr=fpr)


# ---------------------------------------------------------------------------
# 1. Reproduce the SAME Windows calibration holdout (n=3,398) used in Task 1
# ---------------------------------------------------------------------------
X_win_pool, _ = extract_win_oldpool_benign()
_, X_win_calib = split_win_oldpool(X_win_pool, seed=42, train_frac=0.70)
assert len(X_win_calib) == 3398

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")
xgb_norm = joblib.load(f"{MODELS}/xgb_normalized.pkl")


def sc(X):
    return scaler.transform(imputer.transform(np.asarray(X, dtype=np.float64)))


calib_proba = xgb_norm.predict_proba(sc(X_win_calib))[:, 1]
theta_l1_win = float(np.percentile(calib_proba, 90))
fpr_l1_calib = float((calib_proba >= theta_l1_win).mean())
print(f"L1 (xgb_normalized.pkl) recalibrated on Windows calibration holdout (n=3,398):")
print(f"  theta_l1_win (90th-pct) = {theta_l1_win:.5f}   FPR on calibration = {fpr_l1_calib*100:.1f}%\n")

# ---------------------------------------------------------------------------
# 2. Same attack/benign sets as Task 2 (provenance-labeled, fresh held-out)
# ---------------------------------------------------------------------------
lab = pd.read_csv(f"{HERE}/labeled_win.csv", dtype={"rule_id": str})
_prov_base = (lab.label == "attack") & (lab.in_root_tree == True)
prov_mask = _prov_base & lab.technique.isin(["T1110.001", "T1136.001"])
print(f"Provenance-labeled attack rows: {int(prov_mask.sum())} "
      f"(T1110.001={int((prov_mask & (lab.technique=='T1110.001')).sum())}, "
      f"T1136.001={int((prov_mask & (lab.technique=='T1136.001')).sum())})")

Wa22 = _extract_normalized_session(f"{HERE}/collection_win_alerts.json")
Wa22["technique"] = lab["technique"].values
prov22 = Wa22[prov_mask.values].copy()
t1110_mask = (prov22.technique == "T1110.001").values
t1136_mask = (prov22.technique == "T1136.001").values

X_ben_fresh = extract_fresh_benign(f"{HERE}/collection_benign_win_alerts.json", "windows")
assert len(X_ben_fresh) == 201

X_atk_sc = sc(prov22[FEATURE_COLS_NORM].values)
X_ben_sc = sc(X_ben_fresh)

# ---------------------------------------------------------------------------
# 3. L1 alone -- isolated contribution
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("L1 ALONE (recalibrated) -- isolated contribution")
print("=" * 90)
l1_atk_hit = xgb_norm.predict_proba(X_atk_sc)[:, 1] >= theta_l1_win
l1_ben_hit = xgb_norm.predict_proba(X_ben_sc)[:, 1] >= theta_l1_win
y_l1 = np.array([True] * len(l1_atk_hit) + [False] * len(l1_ben_hit))
pred_l1 = np.concatenate([l1_atk_hit, l1_ben_hit])
cm_l1 = confusion(y_l1, pred_l1)
rec_t1110_l1 = f"{int(l1_atk_hit[t1110_mask].sum())} of {int(t1110_mask.sum())}"
rec_t1136_l1 = f"{int(l1_atk_hit[t1136_mask].sum())} of {int(t1136_mask.sum())}"
print(f"  recall T1110.001={rec_t1110_l1}  T1136.001={rec_t1136_l1}  "
      f"overall recall={cm_l1['recall']*100:.1f}%  FPR={cm_l1['fpr']*100:.1f}%  F1={cm_l1['f1']:.4f}")

# ---------------------------------------------------------------------------
# 4. Combined L1+L2 for each candidate, vs L2-only (Task 2)
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(a) L2-only  vs  (b) L1(recalibrated)+L2, per candidate")
print("=" * 90)

calib = pd.read_csv(f"{HERE}/v8_task1_calibration.csv")
theta_map = dict(zip(calib.candidate, calib.theta_calibrated))
task2 = pd.read_csv(f"{HERE}/v8_task2_comparison.csv")

candidates = {
    "C1_win_native": joblib.load(f"{MODELS}/ocsvm_win_native_v8.pkl"),
    "C2_xplatform_v7": joblib.load(f"{MODELS}/ocsvm_xplatform_v7.pkl"),
    "C3_xplatform_v8": joblib.load(f"{MODELS}/ocsvm_xplatform_v8.pkl"),
}

rows = [dict(candidate="L1_alone", routing="L1_only", recall_T1110=rec_t1110_l1, recall_T1136=rec_t1136_l1,
             overall_recall=cm_l1["recall"], fpr=cm_l1["fpr"], f1=cm_l1["f1"])]

for name, oc in candidates.items():
    theta = float(theta_map[name])
    l2_atk = ocsvm_anomaly_score(oc, X_atk_sc) >= theta
    l2_ben = ocsvm_anomaly_score(oc, X_ben_sc) >= theta

    combo_atk = l1_atk_hit | l2_atk
    combo_ben = l1_ben_hit | l2_ben
    y = np.array([True] * len(combo_atk) + [False] * len(combo_ben))
    pred_combo = np.concatenate([combo_atk, combo_ben])
    cm_combo = confusion(y, pred_combo)

    t2row = task2[task2.row == name].iloc[0]
    d_recall = (cm_combo["recall"] - t2row.overall_recall) * 100
    d_fpr = (cm_combo["fpr"] - t2row.fpr) * 100
    verdict = ("L1 adds FPR without meaningful recall" if d_recall <= 1 and d_fpr > 1
               else "L1 adds recall" if d_recall > 1 else "~no change")

    print(f"  {name:<20} L2-only: recall={t2row.overall_recall*100:5.1f}% FPR={t2row.fpr*100:5.1f}% F1={t2row.f1:.4f}"
          f"   |   L1+L2: recall={cm_combo['recall']*100:5.1f}% FPR={cm_combo['fpr']*100:5.1f}% F1={cm_combo['f1']:.4f}"
          f"   |   delta recall={d_recall:+.1f}pp  delta FPR={d_fpr:+.1f}pp  [{verdict}]")

    rows.append(dict(candidate=name, routing="L2_only", recall_T1110=t2row.recall_T1110,
                      recall_T1136=t2row.recall_T1136, overall_recall=t2row.overall_recall,
                      fpr=t2row.fpr, f1=t2row.f1))
    rows.append(dict(candidate=name, routing="L1_recalib_plus_L2",
                      recall_T1110=f"{int(combo_atk[t1110_mask].sum())} of {int(t1110_mask.sum())}",
                      recall_T1136=f"{int(combo_atk[t1136_mask].sum())} of {int(t1136_mask.sum())}",
                      overall_recall=cm_combo["recall"], fpr=cm_combo["fpr"], f1=cm_combo["f1"],
                      delta_recall_pp=d_recall, delta_fpr_pp=d_fpr, verdict=verdict))

out = pd.DataFrame(rows)
out.to_csv(f"{HERE}/v8_task4_l1_routing.csv", index=False)
print(f"\nwrote {HERE}/v8_task4_l1_routing.csv")
