"""
v8_task2_eval.py -- Windows recalibration (v8), Task 2: the headline evaluation.
==================================================================================
Attack set (provenance predicate, confirmed): label=='attack' AND
in_root_tree==True, from newCol/labeled_win.csv. T1110.001=160, T1136.001=8.
This REPLACES the earlier, unrecoverable "241/8" figure (per user decision) --
both Table 7.5 baselines are RE-SCORED under this same predicate so every row
in the comparison table (baselines and candidates alike) uses the identical
168-alert attack set. Only the attack-side n changes for the baselines; their
FPR methodology (model, threshold, benign set) is unchanged from before.

Benign for FPR: the fresh matched Windows collection (n=201, WIN-CL1,
2026-07-12) -- held out from ALL training and calibration in Task 1.

Rows:
  1. Table 7.5 baseline (un-normalized, 26-feat: xgb_model.pkl + ocsvm_nu05_v6.pkl,
     deployed thresholds theta_xgb=0.07538/theta_ocsvm=-0.33500, L1 OR L2 combined)
  2. Table 7.5 baseline (normalized, 22-feat: xgb_normalized.pkl + ocsvm_normalized.pkl,
     phase3-derived thresholds, L1 OR L2 combined) -- this is the "REF" model,
     scored at ITS ORIGINAL deployed-style threshold, not the Task-1 recalibration.
  3. C1 Windows-native OC-SVM (L2-only, Task-1-calibrated theta)
  4. C2 ocsvm_xplatform_v7.pkl (L2-only, Task-1-calibrated theta)
  5. C3 ocsvm_xplatform_v8.pkl (L2-only, Task-1-calibrated theta)

C1/C2/C3 are L2-only per Task 1's scope; L1 routing is Task 4's question, not
scored here.
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

from v8_common import extract_fresh_benign
from f1_phaseB_win import extract_win_attack_features, extract_win_benign_features
from f1_phaseB_normalized_crossplatform import derive_normalized_thresholds, _extract_normalized_session
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score
from shared_constants_v2 import FEATURE_COLS_V2
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
# 1. Provenance-labeled attack set (row-index aligned to labeled_win.csv)
# ---------------------------------------------------------------------------
lab = pd.read_csv(f"{HERE}/labeled_win.csv", dtype={"rule_id": str})
_prov_base = (lab.label == "attack") & (lab.in_root_tree == True)
_n_untech = int((_prov_base & ~lab.technique.isin(["T1110.001", "T1136.001"])).sum())
prov_mask = _prov_base & lab.technique.isin(["T1110.001", "T1136.001"])
print(f"in_root_tree==True & label=='attack': {int(_prov_base.sum())} total "
      f"({_n_untech} have no T1110.001/T1136.001 technique label -- excluded, out of scope)")
print(f"Provenance-labeled attack rows (T1110.001/T1136.001 only): {int(prov_mask.sum())} "
      f"(T1110.001={int((prov_mask & (lab.technique=='T1110.001')).sum())}, "
      f"T1136.001={int((prov_mask & (lab.technique=='T1136.001')).sum())})")

# ---------------------------------------------------------------------------
# 2. Baseline 1 -- un-normalized (26-feat), re-scored under the new predicate
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("BASELINE 1 -- un-normalized 26-feat (xgb_model.pkl + ocsvm_nu05_v6.pkl), deployed thresholds")
print("=" * 90)
models26 = load_production_models()
TXG, TOC = float(models26["theta_xgb"]), float(models26["theta_ocsvm"])

Wa26 = extract_win_attack_features()  # aligned to labeled_win.csv by index
Wb26 = extract_win_benign_features()  # fresh benign, n=201

prov26 = Wa26[prov_mask.values].copy()
prov26["technique"] = lab.loc[prov_mask, "technique"].values


def sc26(df):
    return models26["scaler"].transform(models26["imputer"].transform(df[FEATURE_COLS_V2].values.astype(float)))


def hit26(df):
    if not len(df):
        return np.zeros(0, bool)
    xg = models26["xgb"].predict_proba(sc26(df))[:, 1] >= TXG
    oc = ocsvm_anomaly_score(models26["ocsvm"], sc26(df)) >= TOC
    return xg | oc


pred_atk_b1 = hit26(prov26)
pred_ben_b1 = hit26(Wb26)
y_b1 = np.array([True] * len(prov26) + [False] * len(Wb26))
pred_b1 = np.concatenate([pred_atk_b1, pred_ben_b1])
cm_b1 = confusion(y_b1, pred_b1)

t1110_mask = (prov26.technique == "T1110.001").values
t1136_mask = (prov26.technique == "T1136.001").values
rec_t1110_b1 = f"{int(pred_atk_b1[t1110_mask].sum())} of {int(t1110_mask.sum())}"
rec_t1136_b1 = f"{int(pred_atk_b1[t1136_mask].sum())} of {int(t1136_mask.sum())}"
sat_b1 = pred_ben_b1.mean() > 0.50
print(f"  recall T1110.001={rec_t1110_b1}  T1136.001={rec_t1136_b1}  "
      f"overall recall={cm_b1['recall']*100:.1f}%  FPR={cm_b1['fpr']*100:.1f}%  "
      f"F1={cm_b1['f1']:.4f}  saturated={'YES' if sat_b1 else 'no'}")

# ---------------------------------------------------------------------------
# 3. Baseline 2 -- normalized (22-feat), re-scored under the new predicate
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("BASELINE 2 -- normalized 22-feat (xgb_normalized.pkl + ocsvm_normalized.pkl), phase3-derived thresholds")
print("=" * 90)
nm = derive_normalized_thresholds()
print(f"  theta_xgb_norm={nm['theta_xgb']:.5f}  theta_ocsvm_norm={nm['theta_oc']:.5f}  "
      f"reproduction F1={nm['check']['F1']:.4f} (saved 0.9686)")

Wa22 = _extract_normalized_session(f"{HERE}/collection_win_alerts.json")
Wa22["technique"] = lab["technique"].values
Wb22 = _extract_normalized_session(f"{HERE}/collection_benign_win_alerts.json")

prov22 = Wa22[prov_mask.values].copy()


def sc_nm(df):
    return nm["sca"].transform(nm["imp"].transform(df[FEATURE_COLS_NORM].values.astype(float)))


def hit_nm(df):
    if not len(df):
        return np.zeros(0, bool)
    xg = nm["xgb"].predict_proba(sc_nm(df))[:, 1] >= nm["theta_xgb"]
    oc = (-nm["oc"].decision_function(sc_nm(df))) >= nm["theta_oc"]
    return xg | oc


pred_atk_b2 = hit_nm(prov22)
pred_ben_b2 = hit_nm(Wb22)
y_b2 = np.array([True] * len(prov22) + [False] * len(Wb22))
pred_b2 = np.concatenate([pred_atk_b2, pred_ben_b2])
cm_b2 = confusion(y_b2, pred_b2)

t1110_mask22 = (prov22.technique == "T1110.001").values
t1136_mask22 = (prov22.technique == "T1136.001").values
rec_t1110_b2 = f"{int(pred_atk_b2[t1110_mask22].sum())} of {int(t1110_mask22.sum())}"
rec_t1136_b2 = f"{int(pred_atk_b2[t1136_mask22].sum())} of {int(t1136_mask22.sum())}"
sat_b2 = pred_ben_b2.mean() > 0.50
print(f"  recall T1110.001={rec_t1110_b2}  T1136.001={rec_t1136_b2}  "
      f"overall recall={cm_b2['recall']*100:.1f}%  FPR={cm_b2['fpr']*100:.1f}%  "
      f"F1={cm_b2['f1']:.4f}  saturated={'YES' if sat_b2 else 'no'}")

# ---------------------------------------------------------------------------
# 4. C1 / C2 / C3 -- L2-only, Task-1-calibrated thresholds, fresh held-out benign
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("C1 / C2 / C3 -- L2-only, Task-1-calibrated thresholds, FRESH held-out Windows benign (n=201)")
print("=" * 90)

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")


def sc(X):
    return scaler.transform(imputer.transform(np.asarray(X, dtype=np.float64)))


calib = pd.read_csv(f"{HERE}/v8_task1_calibration.csv")
theta_map = dict(zip(calib.candidate, calib.theta_calibrated))

candidates = {
    "C1_win_native": joblib.load(f"{MODELS}/ocsvm_win_native_v8.pkl"),
    "C2_xplatform_v7": joblib.load(f"{MODELS}/ocsvm_xplatform_v7.pkl"),
    "C3_xplatform_v8": joblib.load(f"{MODELS}/ocsvm_xplatform_v8.pkl"),
}

X_atk_sc = sc(prov22[FEATURE_COLS_NORM].values)
X_ben_fresh = extract_fresh_benign(f"{HERE}/collection_benign_win_alerts.json", "windows")
X_ben_sc = sc(X_ben_fresh)
assert len(X_ben_fresh) == 201, f"expected 201 fresh benign rows, got {len(X_ben_fresh)}"

rows = [
    dict(row="Table7.5_baseline_unnormalized_26feat", recall_T1110=rec_t1110_b1, recall_T1136=rec_t1136_b1,
         overall_recall=cm_b1["recall"], fpr=cm_b1["fpr"], f1=cm_b1["f1"], saturated=sat_b1,
         tp=cm_b1["tp"], fp=cm_b1["fp"], tn=cm_b1["tn"], fn=cm_b1["fn"]),
    dict(row="Table7.5_baseline_normalized_22feat", recall_T1110=rec_t1110_b2, recall_T1136=rec_t1136_b2,
         overall_recall=cm_b2["recall"], fpr=cm_b2["fpr"], f1=cm_b2["f1"], saturated=sat_b2,
         tp=cm_b2["tp"], fp=cm_b2["fp"], tn=cm_b2["tn"], fn=cm_b2["fn"]),
]

for name, oc in candidates.items():
    theta = float(theta_map[name])
    atk_scores = ocsvm_anomaly_score(oc, X_atk_sc)
    ben_scores = ocsvm_anomaly_score(oc, X_ben_sc)
    pred_atk = atk_scores >= theta
    pred_ben = ben_scores >= theta
    y = np.array([True] * len(pred_atk) + [False] * len(pred_ben))
    pred = np.concatenate([pred_atk, pred_ben])
    cm = confusion(y, pred)
    rec_t1110 = f"{int(pred_atk[t1110_mask22].sum())} of {int(t1110_mask22.sum())}"
    rec_t1136 = f"{int(pred_atk[t1136_mask22].sum())} of {int(t1136_mask22.sum())}"
    sat = pred_ben.mean() > 0.50
    print(f"  {name:<20} theta={theta:9.5f}  recall T1110={rec_t1110}  T1136={rec_t1136}  "
          f"overall={cm['recall']*100:5.1f}%  FPR={cm['fpr']*100:5.1f}%  F1={cm['f1']:.4f}  "
          f"saturated={'YES' if sat else 'no'}")
    rows.append(dict(row=name, recall_T1110=rec_t1110, recall_T1136=rec_t1136,
                      overall_recall=cm["recall"], fpr=cm["fpr"], f1=cm["f1"], saturated=sat,
                      tp=cm["tp"], fp=cm["fp"], tn=cm["tn"], fn=cm["fn"]))

out = pd.DataFrame(rows)
out.to_csv(f"{HERE}/v8_task2_comparison.csv", index=False)
print(f"\nwrote {HERE}/v8_task2_comparison.csv")

print("\n" + "=" * 90)
print("COMPARISON TABLE")
print("=" * 90)
print(out[["row", "recall_T1110", "recall_T1136", "fpr", "f1", "saturated"]].to_string(index=False))
