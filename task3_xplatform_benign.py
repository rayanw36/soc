"""
Task 3: Benign-side cross-platform OC-SVM retraining.

Scope: FALSE-POSITIVE side only.
- Builds a high-confidence Windows-benign set (>= 60 min outside ALL attack windows).
- Retrains OC-SVM on Linux benign + 70% Windows benign.
- Tests on 30% held-out Windows benign.
- Compares FPR: old OC-SVM (Linux-only trained) vs new OC-SVM (cross-OS trained).
- Does NOT attempt attack recall from Windows alerts (labels unreliable).

Outputs:
  models_v2/ocsvm_xplatform_v7.pkl
  results_v2/xplatform_benign_test.csv

MANDATORY SCOPE NOTE: This validates only the benign/false-positive side of
cross-platform transfer. No cross-platform F1 or recall number is produced here.
"""
import sys, json, os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict

sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import joblib

ROOT    = Path(__file__).resolve().parent
MODELS  = ROOT / "models_v2"
RESULTS = ROOT / "results_v2"

from normalize_schema import FEATURE_COLS_NORM, NUM_FEATURES_NORM, extract_normalized
from shared_constants import ATTACK_WINDOWS_LNX, WINDOWS_ATTACK_WINDOWS
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, EXPERIMENT_START, EXPERIMENT_END
import shared_features
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, assign_label

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _parse_dt(ts_str: str):
    if not ts_str: return None
    ts_str = str(ts_str).strip()
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f+0000", "%Y-%m-%dT%H:%M:%S.%f+00:00",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z"]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            pass
    return None

# Parse attack windows
def parse_windows_lnx():
    out = []
    for row in ATTACK_WINDOWS_LNX_V2:
        s, e = _parse_dt(row[2]), _parse_dt(row[3])
        if s and e: out.append((s, e))
    return out

def parse_windows_win():
    out = []
    for s_str, e_str in WINDOWS_ATTACK_WINDOWS:
        s = datetime.fromisoformat(s_str.replace("Z", "+00:00"))
        e = datetime.fromisoformat(e_str.replace("Z", "+00:00"))
        out.append((s, e))
    return out

MARGIN = timedelta(minutes=60)
LNX_WINS = parse_windows_lnx()
WIN_WINS  = parse_windows_win()

exp_start = _parse_dt(EXPERIMENT_START)
exp_end   = _parse_dt(EXPERIMENT_END)

# ---------------------------------------------------------------------------
# Step 1: Extract Linux benign features
# ---------------------------------------------------------------------------

print("=== Step 1: Linux benign feature extraction ===", flush=True)

raw_lnx = []
with open(ROOT / "lnx_dmz_ai_detections.json", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if line:
            try: raw_lnx.append(json.loads(line))
            except: pass

raw_lnx.sort(key=lambda r: _parse_dt(str(r.get("timestamp","") or "")) or datetime.min.replace(tzinfo=timezone.utc))

histories_lnx: dict = {}
lnx_benign_feats = []
lnx_benign_ts    = []

for rec in raw_lnx:
    ts = _parse_dt(str(rec.get("timestamp","") or ""))
    if ts is None: continue
    oa = rec.get("original_alert", rec)
    agent = str(oa.get("agent", {}).get("name", "unknown") or "unknown")
    hist  = histories_lnx.setdefault(agent, AgentHistory())
    hfeat = hist.compute_features(ts)
    feats = extract_normalized(oa, hfeat)
    hist.add(oa, ts)

    # Keep only high-confidence benign: outside all windows by >= 60 min
    is_benign = all(ts < (s - MARGIN) or ts > (e + MARGIN) for s, e in LNX_WINS)
    if is_benign:
        lnx_benign_feats.append(feats)
        lnx_benign_ts.append(ts)

X_lnx_benign = np.array(lnx_benign_feats, dtype=np.float64)
print(f"  Linux benign alerts: {len(X_lnx_benign)}", flush=True)

# ---------------------------------------------------------------------------
# Step 2: Extract Windows benign features
# ---------------------------------------------------------------------------

print("\n=== Step 2: Windows benign feature extraction ===", flush=True)

win_alerts_raw = []
for fname in ["ossec-alerts-23.json", "ossec-alerts-24.json"]:
    fpath = ROOT / "testAlerts" / "Alerts" / fname
    with open(fpath, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try: win_alerts_raw.append(json.loads(line))
                except: pass

win_alerts_raw.sort(key=lambda r: _parse_dt(str(r.get("timestamp","") or "")) or datetime.min.replace(tzinfo=timezone.utc))

histories_win: dict = {}
win_benign_feats = []
win_benign_ts    = []
win_total = 0
win_skipped_ts = 0

for rec in win_alerts_raw:
    ts = _parse_dt(str(rec.get("timestamp","") or ""))
    if ts is None:
        win_skipped_ts += 1
        continue
    win_total += 1
    agent = (rec.get("agent", {}).get("name", "")
             or rec.get("data", {}).get("win", {}).get("system", {}).get("computer", "")
             or "unknown")
    hist  = histories_win.setdefault(agent, AgentHistory())
    hfeat = hist.compute_features(ts)
    feats = extract_normalized(rec, hfeat)
    hist.add(rec, ts)

    is_benign = all(ts < (s - MARGIN) or ts > (e + MARGIN) for s, e in WIN_WINS)
    if is_benign:
        win_benign_feats.append(feats)
        win_benign_ts.append(ts)

X_win_benign = np.array(win_benign_feats, dtype=np.float64)
print(f"  Windows total parsed: {win_total}  skipped(no-ts): {win_skipped_ts}", flush=True)
print(f"  Windows benign (>=60min outside attack windows): {len(X_win_benign)}", flush=True)

# ---------------------------------------------------------------------------
# Step 3: Scale features with existing normalized scaler/imputer
# ---------------------------------------------------------------------------

print("\n=== Step 3: Scale with existing scaler/imputer ===", flush=True)

imputer = joblib.load(MODELS / "imputer_normalized.pkl")
scaler  = joblib.load(MODELS / "scaler_normalized.pkl")

X_lnx_sc  = scaler.transform(imputer.transform(X_lnx_benign))
X_win_sc   = scaler.transform(imputer.transform(X_win_benign))

print(f"  Linux benign scaled:   {X_lnx_sc.shape}", flush=True)
print(f"  Windows benign scaled: {X_win_sc.shape}", flush=True)

# ---------------------------------------------------------------------------
# Step 4: Load existing OC-SVM and evaluate baseline FPR
# ---------------------------------------------------------------------------

print("\n=== Step 4: Baseline OC-SVM evaluation (Linux-only trained) ===", flush=True)

ocsvm_old = joblib.load(MODELS / "ocsvm_normalized.pkl")

# Load threshold from phase3 output
# Default: 90th percentile of benign scores = target FPR ≈10%
# Use decision_function threshold; old OC-SVM: theta=-0.00042 (from memory)
# Actually let's compute scores and pick threshold that was used in phase3
# Load normalized_validation.csv for the old FPR
import csv
val_rows = list(csv.DictReader(open(RESULTS / "normalized_validation.csv")))
old_fpr_ait = None
for row in val_rows:
    if "in-dist" in row.get("dataset","").lower() or "ait" in row.get("dataset","").lower():
        old_fpr_ait = row.get("fpr_l2", row.get("fpr", "N/A"))
print(f"  Old OC-SVM in-dist FPR (AIT-ADS): {old_fpr_ait}", flush=True)

# Evaluate old OC-SVM on Linux benign
lnx_scores_old  = ocsvm_old.decision_function(X_lnx_sc)
win_scores_old   = ocsvm_old.decision_function(X_win_sc)

# Use 90th-pct threshold on Linux benign scores (same methodology as phase3)
theta_old_lnx = np.percentile(lnx_scores_old, 10)  # 10th pct = 10% FPR target
print(f"  Old OC-SVM 10th-pct threshold on Linux benign: {theta_old_lnx:.5f}", flush=True)

# But phase3 used a fixed threshold from training; let's use the score sign
# (decision_function > 0 = inlier/benign; < 0 = outlier/anomaly)
# Count FP as: score < 0 on benign data (no threshold tuning needed; OC-SVM is binary by sign)
lnx_fp_old = (lnx_scores_old < 0).sum()
win_fp_old  = (win_scores_old < 0).sum()
lnx_fpr_old = lnx_fp_old / len(lnx_scores_old) if len(lnx_scores_old) else 0
win_fpr_old  = win_fp_old  / len(win_scores_old)  if len(win_scores_old)  else 0

print(f"  Old OC-SVM (sign threshold=0):", flush=True)
print(f"    Linux benign  FPR: {lnx_fp_old}/{len(lnx_scores_old)} = {lnx_fpr_old:.3f}", flush=True)
print(f"    Windows benign FPR: {win_fp_old}/{len(win_scores_old)} = {win_fpr_old:.3f}", flush=True)

# Also try with 90th-pct threshold on Linux benign as calibration
theta_90pct = np.percentile(lnx_scores_old, 10)
lnx_fp_90  = (lnx_scores_old < theta_90pct).sum()
win_fp_90  = (win_scores_old  < theta_90pct).sum()
lnx_fpr_90 = lnx_fp_90 / len(lnx_scores_old)
win_fpr_90 = win_fp_90 / len(win_scores_old)
print(f"\n  Old OC-SVM (90th-pct Linux benign calibration, theta={theta_90pct:.5f}):", flush=True)
print(f"    Linux benign  FPR: {lnx_fp_90}/{len(lnx_scores_old)} = {lnx_fpr_90:.3f}", flush=True)
print(f"    Windows benign FPR: {win_fp_90}/{len(win_scores_old)} = {win_fpr_90:.3f}", flush=True)

# ---------------------------------------------------------------------------
# Step 5: Train/test split of Windows benign
# ---------------------------------------------------------------------------

print("\n=== Step 5: Windows benign split (70% train / 30% test) ===", flush=True)

rng = np.random.default_rng(42)
n_win = len(X_win_sc)
idx   = rng.permutation(n_win)
n_train = int(0.70 * n_win)
win_tr_idx = idx[:n_train]
win_te_idx = idx[n_train:]

X_win_tr = X_win_sc[win_tr_idx]
X_win_te = X_win_sc[win_te_idx]
print(f"  Windows train: {len(X_win_tr)}  test: {len(X_win_te)}", flush=True)

# ---------------------------------------------------------------------------
# Step 6: Retrain OC-SVM on Linux benign + Windows benign train
# ---------------------------------------------------------------------------

print("\n=== Step 6: Retrain OC-SVM (cross-OS benign) ===", flush=True)

from sklearn.svm import OneClassSVM

# Combine Linux benign + Windows benign train
# Cap at 10K per OS to keep training fast and balanced
rng2 = np.random.default_rng(99)

n_lnx_sample = min(5_000, len(X_lnx_sc))
n_win_sample  = min(5_000, len(X_win_tr))

lnx_idx_s = rng2.choice(len(X_lnx_sc), size=n_lnx_sample, replace=False)
win_idx_s  = rng2.choice(len(X_win_tr), size=n_win_sample, replace=False)

X_ocsvm_tr = np.vstack([X_lnx_sc[lnx_idx_s], X_win_tr[win_idx_s]])
print(f"  OC-SVM training set: {len(X_ocsvm_tr)} rows "
      f"({n_lnx_sample} Linux + {n_win_sample} Windows)", flush=True)

ocsvm_new = OneClassSVM(nu=0.05, kernel="rbf", gamma="scale")
ocsvm_new.fit(X_ocsvm_tr)
print(f"  Training complete.", flush=True)

# Save new model
joblib.dump(ocsvm_new, MODELS / "ocsvm_xplatform_v7.pkl")
print(f"  Saved → models_v2/ocsvm_xplatform_v7.pkl", flush=True)

# ---------------------------------------------------------------------------
# Step 7: Evaluate new OC-SVM
# ---------------------------------------------------------------------------

print("\n=== Step 7: Evaluate new OC-SVM (cross-OS) ===", flush=True)

lnx_scores_new = ocsvm_new.decision_function(X_lnx_sc)
win_te_scores_new = ocsvm_new.decision_function(X_win_te)

# Sign threshold (same methodology as old model comparison)
lnx_fp_new  = (lnx_scores_new < 0).sum()
win_fp_new   = (win_te_scores_new < 0).sum()
lnx_fpr_new = lnx_fp_new / len(lnx_scores_new) if len(lnx_scores_new) else 0
win_fpr_new  = win_fp_new  / len(win_te_scores_new) if len(win_te_scores_new) else 0

print(f"  New OC-SVM (sign threshold=0):", flush=True)
print(f"    Linux benign FPR:          {lnx_fp_new}/{len(lnx_scores_new)} = {lnx_fpr_new:.3f}", flush=True)
print(f"    Windows benign (test) FPR: {win_fp_new}/{len(win_te_scores_new)} = {win_fpr_new:.3f}", flush=True)

# Also calibrate using 90th-pct of the training Linux benign
theta_new_90 = np.percentile(lnx_scores_new, 10)
lnx_fp_n90  = (lnx_scores_new < theta_new_90).sum()
win_fp_n90   = (win_te_scores_new < theta_new_90).sum()
lnx_fpr_n90 = lnx_fp_n90 / len(lnx_scores_new)
win_fpr_n90 = win_fp_n90 / len(win_te_scores_new)
print(f"\n  New OC-SVM (90th-pct Linux calibration, theta={theta_new_90:.5f}):", flush=True)
print(f"    Linux benign FPR:          {lnx_fp_n90}/{len(lnx_scores_new)} = {lnx_fpr_n90:.3f}", flush=True)
print(f"    Windows benign (test) FPR: {win_fp_n90}/{len(win_te_scores_new)} = {win_fpr_n90:.3f}", flush=True)

# ---------------------------------------------------------------------------
# Step 8: L1 (XGBoost) on Windows benign (benign-side transfer, independent)
# ---------------------------------------------------------------------------

print("\n=== Step 8: L1 XGBoost on Windows benign ===", flush=True)

xgb = joblib.load(MODELS / "xgb_normalized.pkl")
theta_xgb = 0.07402  # from phase3

X_win_benign_all_sc = X_win_sc  # all Windows benign (not just test split)

xgb_proba_win = xgb.predict_proba(X_win_benign_all_sc)[:, 1]
xgb_pred_win  = (xgb_proba_win >= theta_xgb).astype(int)
win_l1_fp      = xgb_pred_win.sum()
win_l1_fpr     = win_l1_fp / len(xgb_pred_win) if len(xgb_pred_win) else 0
print(f"  L1 XGBoost on Windows benign (all {len(X_win_benign_all_sc)}):", flush=True)
print(f"    FP: {win_l1_fp}  FPR: {win_l1_fpr:.3f}", flush=True)
print(f"    (L1 classifying as attack = FP for benign data)", flush=True)
print(f"    theta_xgb={theta_xgb:.5f}  score range: [{xgb_proba_win.min():.3f}, {xgb_proba_win.max():.3f}]", flush=True)

# L1 on Linux benign (regression guard)
xgb_proba_lnx = xgb.predict_proba(X_lnx_sc)[:, 1]
xgb_pred_lnx  = (xgb_proba_lnx >= theta_xgb).astype(int)
lnx_l1_fp     = xgb_pred_lnx.sum()
lnx_l1_fpr    = lnx_l1_fp / len(xgb_pred_lnx) if len(xgb_pred_lnx) else 0
print(f"\n  L1 XGBoost on Linux benign ({len(X_lnx_sc)} alerts):", flush=True)
print(f"    FP: {lnx_l1_fp}  FPR: {lnx_l1_fpr:.3f}", flush=True)

# ---------------------------------------------------------------------------
# Step 9: Write results CSV
# ---------------------------------------------------------------------------

print("\n=== Step 9: Writing results ===", flush=True)

import csv

rows = [
    {
        "model":        "OC-SVM (Linux-only, ocsvm_normalized.pkl)",
        "eval_set":     "Linux benign (8,093 alerts, >=60min outside attack windows)",
        "n_eval":       len(lnx_scores_old),
        "n_fp":         int(lnx_fp_old),
        "fpr":          f"{lnx_fpr_old:.4f}",
        "threshold":    "sign(score)=0",
        "notes":        "baseline — sign threshold",
    },
    {
        "model":        "OC-SVM (Linux-only, ocsvm_normalized.pkl)",
        "eval_set":     "Linux benign (8,093 alerts)",
        "n_eval":       len(lnx_scores_old),
        "n_fp":         int(lnx_fp_90),
        "fpr":          f"{lnx_fpr_90:.4f}",
        "threshold":    f"90pct-Linux-calibrated={theta_90pct:.5f}",
        "notes":        "baseline — calibrated threshold",
    },
    {
        "model":        "OC-SVM (Linux-only, ocsvm_normalized.pkl)",
        "eval_set":     f"Windows benign ({len(win_scores_old)} alerts, >=60min outside attack windows)",
        "n_eval":       len(win_scores_old),
        "n_fp":         int(win_fp_old),
        "fpr":          f"{win_fpr_old:.4f}",
        "threshold":    "sign(score)=0",
        "notes":        "baseline before cross-OS retraining — sign threshold",
    },
    {
        "model":        "OC-SVM (Linux-only, ocsvm_normalized.pkl)",
        "eval_set":     f"Windows benign ({len(win_scores_old)} alerts)",
        "n_eval":       len(win_scores_old),
        "n_fp":         int(win_fp_90),
        "fpr":          f"{win_fpr_90:.4f}",
        "threshold":    f"90pct-Linux-calibrated={theta_90pct:.5f}",
        "notes":        "baseline before cross-OS retraining — calibrated",
    },
    {
        "model":        "OC-SVM (cross-OS, ocsvm_xplatform_v7.pkl)",
        "eval_set":     f"Linux benign ({len(lnx_scores_new)} alerts) [regression guard]",
        "n_eval":       len(lnx_scores_new),
        "n_fp":         int(lnx_fp_new),
        "fpr":          f"{lnx_fpr_new:.4f}",
        "threshold":    "sign(score)=0",
        "notes":        "regression guard — sign threshold",
    },
    {
        "model":        "OC-SVM (cross-OS, ocsvm_xplatform_v7.pkl)",
        "eval_set":     f"Linux benign ({len(lnx_scores_new)} alerts)",
        "n_eval":       len(lnx_scores_new),
        "n_fp":         int(lnx_fp_n90),
        "fpr":          f"{lnx_fpr_n90:.4f}",
        "threshold":    f"90pct-Linux-calibrated={theta_new_90:.5f}",
        "notes":        "regression guard — calibrated",
    },
    {
        "model":        "OC-SVM (cross-OS, ocsvm_xplatform_v7.pkl)",
        "eval_set":     f"Windows benign hold-out ({len(win_te_scores_new)} alerts, 30% split)",
        "n_eval":       len(win_te_scores_new),
        "n_fp":         int(win_fp_new),
        "fpr":          f"{win_fpr_new:.4f}",
        "threshold":    "sign(score)=0",
        "notes":        "NEW model on held-out Windows benign — sign threshold",
    },
    {
        "model":        "OC-SVM (cross-OS, ocsvm_xplatform_v7.pkl)",
        "eval_set":     f"Windows benign hold-out ({len(win_te_scores_new)} alerts, 30%)",
        "n_eval":       len(win_te_scores_new),
        "n_fp":         int(win_fp_n90),
        "fpr":          f"{win_fpr_n90:.4f}",
        "threshold":    f"90pct-Linux-calibrated={theta_new_90:.5f}",
        "notes":        "NEW model on held-out Windows benign — calibrated",
    },
    {
        "model":        "XGBoost L1 (xgb_normalized.pkl) — UNCHANGED",
        "eval_set":     f"Linux benign ({len(xgb_proba_lnx)} alerts) [regression guard]",
        "n_eval":       len(xgb_proba_lnx),
        "n_fp":         int(lnx_l1_fp),
        "fpr":          f"{lnx_l1_fpr:.4f}",
        "threshold":    f"theta={theta_xgb:.5f}",
        "notes":        "L1 regression guard; L1 not retrained in Task 3",
    },
    {
        "model":        "XGBoost L1 (xgb_normalized.pkl) — UNCHANGED",
        "eval_set":     f"Windows benign ({len(xgb_pred_win)} alerts, ALL)",
        "n_eval":       len(xgb_pred_win),
        "n_fp":         int(win_l1_fp),
        "fpr":          f"{win_l1_fpr:.4f}",
        "threshold":    f"theta={theta_xgb:.5f}",
        "notes":        "L1 on Windows benign — benign-side transfer",
    },
]

with open(RESULTS / "xplatform_benign_test.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print(f"  Wrote results_v2/xplatform_benign_test.csv", flush=True)

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

print("\n" + "="*70, flush=True)
print("CHECKPOINT 3 — Benign-side cross-platform test summary", flush=True)
print("="*70, flush=True)
print(f"\nWindows benign set: {len(X_win_benign)} alerts (>= 60 min outside attack windows)", flush=True)
print(f"Linux benign set:   {len(X_lnx_benign)} alerts (>= 60 min outside attack windows)", flush=True)
print(f"\nOC-SVM FPR comparison (sign threshold, no calibration bias):", flush=True)
print(f"  {'Eval set':<45} {'Old (Linux-only)':>18} {'New (cross-OS)':>16}", flush=True)
print(f"  {'-'*45} {'-'*18} {'-'*16}", flush=True)
print(f"  {'Linux benign (regression guard)':<45} {lnx_fpr_old:>17.1%} {lnx_fpr_new:>15.1%}", flush=True)
print(f"  {'Windows benign (hold-out 30%)':<45} {'N/A (old never seen Win)':>18} {win_fpr_new:>15.1%}", flush=True)
print(f"  {'Windows benign (all, sign=0)':<45} {win_fpr_old:>17.1%} {'(train incl.)':>15}", flush=True)
print(f"\nL1 XGBoost (not retrained):", flush=True)
print(f"  Linux benign FPR:   {lnx_l1_fpr:.1%}  ({lnx_l1_fp}/{len(xgb_pred_lnx)})", flush=True)
print(f"  Windows benign FPR: {win_l1_fpr:.1%}  ({win_l1_fp}/{len(xgb_pred_win)})", flush=True)

print(f"\nSCOPE NOTE: These figures measure false-positive rate on confirmed-benign", flush=True)
print(f"alerts only. No attack recall or F1 is reported from Task 3 —", flush=True)
print(f"cross-platform recall requires re-collection with correct provenance labels.", flush=True)

print(f"\nSaved: models_v2/ocsvm_xplatform_v7.pkl", flush=True)
print(f"       results_v2/xplatform_benign_test.csv", flush=True)
print(f"\nTask 3 complete.", flush=True)
