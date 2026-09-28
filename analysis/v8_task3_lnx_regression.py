"""
v8_task3_lnx_regression.py -- Windows recalibration (v8), Task 3: Linux regression guard.
=============================================================================================
Resolved decision (confirmed by user): the Linux regression guard uses TWO bars,
not one:
  (a) SAME-SPACE: score C1/C2/C3 against ocsvm_normalized.pkl (REF) on IDENTICAL
      Linux inputs (22-feat normalized) at REF's OWN Linux-calibrated threshold
      (theta_ocsvm_norm, re-derived from ait_split.npz via phase3_normalized_v7's
      method -- the same threshold REF has always used for Linux). Applying one
      shared threshold across all four models isolates the model choice as the
      only variable.
  (b) OUTCOME-LEVEL: report against the FROZEN v5 production numbers (the
      26-feature xgb_model.pkl + ocsvm_nu05.pkl + defer pipeline, NOVEL F1=0.8702,
      FPR=10.86%, recall=258/306=84.3%) as a labeled reference row -- explicitly
      NOT apples-to-apples (different feature space, different L1, defer
      mechanism involved). Caveat stated plainly, never silently compared.

Data: NOVEL discriminative rules (5710,5712,550,553,554,5901,5902,5903) from
labeled_lnx.csv, per-technique breakdown (same rule map as Table 7.1 / eval_phase4.py
DISCRIMINATIVE dict) + fresh matched Linux benign (n=267). L2-only scoring, matching
Task 2's scope (L1 routing is Task 4).
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

from v8_common import extract_fresh_benign
from f1_phaseB_normalized_crossplatform import derive_normalized_thresholds
from combined_decision_v6 import ocsvm_anomaly_score
from normalize_schema import extract_normalized, FEATURE_COLS_NORM
from shared_features import AgentHistory
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2
import shared_features
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from label_lnx_timeonly import event_time as lnx_event_time

HERE = "newCol"
MODELS = "models_v2"

# same technique -> discriminative-rule mapping as eval_phase4.py / f1_phaseA_lnx.py
DISCRIMINATIVE = {
    "T1110.001": {"5710", "5712"},
    "T1136.001": {"5901", "5902", "5903", "550", "553", "554"},
    "T1053.003": {"554", "553"},
    "T1543.002": {"554", "553"},
    "T1546.004": {"554", "553"},
    "T1098.004": {"550"},
}
NOVEL_RULES = {"5710", "5712", "550", "553", "554", "5901", "5902", "5903"}


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
# 1. Extract Linux NOVEL attacks, 22-feat normalized, event-time ordered
# ---------------------------------------------------------------------------
print("Extracting Linux attack alerts (22-feat normalized, event-time ordered)...")
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
    feats[idx] = extract_normalized(a, h.compute_features(ts), process_depth=0)
    h.add(a, ts)

lab = pd.read_csv(f"{HERE}/labeled_lnx.csv", dtype={"rule_id": str})
assert len(lab) == len(feats), f"{len(lab)} labels vs {len(feats)} features"
Xa = pd.DataFrame(feats, columns=FEATURE_COLS_NORM)
Xa["label"] = lab["label"].values
Xa["rule_id"] = lab["rule_id"].values

novel = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(NOVEL_RULES))].copy()
print(f"Novel discriminative Linux attacks: {len(novel)}")
print(f"  by rule: {novel.rule_id.value_counts().to_dict()}\n")

X_lnx_fresh_benign = extract_fresh_benign(f"{HERE}/collection_benign_lnx_alerts.json", "lnx")
print(f"Fresh matched Linux benign: {len(X_lnx_fresh_benign)}\n")

# ---------------------------------------------------------------------------
# 2. REF's own Linux-calibrated threshold (phase3-derived, unchanged)
# ---------------------------------------------------------------------------
nm = derive_normalized_thresholds()
theta_lnx = float(nm["theta_oc"])
print(f"Shared Linux threshold (REF's own, phase3-derived): theta_ocsvm_norm={theta_lnx:.5f}\n")

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")


def sc(X):
    return scaler.transform(imputer.transform(np.asarray(X, dtype=np.float64)))


X_novel_sc = sc(novel[FEATURE_COLS_NORM].values)
X_benign_sc = sc(X_lnx_fresh_benign)

candidates = {
    "REF_linux_only_normalized": joblib.load(f"{MODELS}/ocsvm_normalized.pkl"),
    "C1_win_native": joblib.load(f"{MODELS}/ocsvm_win_native_v8.pkl"),
    "C2_xplatform_v7": joblib.load(f"{MODELS}/ocsvm_xplatform_v7.pkl"),
    "C3_xplatform_v8": joblib.load(f"{MODELS}/ocsvm_xplatform_v8.pkl"),
}

# ---------------------------------------------------------------------------
# 3. (a) SAME-SPACE: score all four at the identical shared Linux threshold
# ---------------------------------------------------------------------------
print("=" * 90)
print("(a) SAME-SPACE -- all four models, identical Linux inputs, identical threshold")
print("=" * 90)
rows = []
for name, oc in candidates.items():
    atk_scores = ocsvm_anomaly_score(oc, X_novel_sc)
    ben_scores = ocsvm_anomaly_score(oc, X_benign_sc)
    pred_atk = atk_scores >= theta_lnx
    pred_ben = ben_scores >= theta_lnx

    per_tech = {}
    for tech, rules in DISCRIMINATIVE.items():
        mask = novel.rule_id.isin(rules).values
        if not mask.any():
            continue
        per_tech[tech] = f"{int(pred_atk[mask].sum())} of {int(mask.sum())}"

    y = np.array([True] * len(pred_atk) + [False] * len(pred_ben))
    pred = np.concatenate([pred_atk, pred_ben])
    cm = confusion(y, pred)
    print(f"  {name:<28} overall novel recall={cm['recall']*100:5.1f}%  FPR={cm['fpr']*100:5.1f}%  F1={cm['f1']:.4f}")
    for tech, txt in per_tech.items():
        print(f"      {tech:<12} {txt}")
    rows.append(dict(model=name, **per_tech, overall_recall=cm["recall"], fpr=cm["fpr"], f1=cm["f1"],
                      tp=cm["tp"], fp=cm["fp"], tn=cm["tn"], fn=cm["fn"]))

same_space = pd.DataFrame(rows)
same_space.to_csv(f"{HERE}/v8_task3_same_space.csv", index=False)
print(f"\nwrote {HERE}/v8_task3_same_space.csv")

# ---------------------------------------------------------------------------
# 4. (b) OUTCOME-LEVEL: frozen v5 production reference row (cross-pipeline)
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(b) OUTCOME-LEVEL reference -- frozen v5-defer PRODUCTION numbers (26-feat, CROSS-PIPELINE)")
print("=" * 90)
frozen = dict(model="FROZEN_v5defer_production_26feat", overall_recall=0.8431, fpr=0.1086, f1=0.8702,
              tp=258, fp=29, tn=238, fn=48, note="26-feat xgb_model.pkl+ocsvm_nu05.pkl+defer; "
              "NOT same feature space as the 22-feat models above -- reference only, not directly comparable")
print(f"  {frozen['model']:<32} overall novel recall=84.3%  FPR=10.86%  F1=0.8702  "
      f"[CROSS-PIPELINE -- caveat: different feature space/model entirely]")

# ---------------------------------------------------------------------------
# 5. Tradeoff table: Windows gain (Task 2) vs Linux same-space delta (Task 3a)
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("TRADEOFF TABLE -- Windows F1 gain (Task 2) vs Linux same-space regression (Task 3a)")
print("=" * 90)
task2 = pd.read_csv(f"{HERE}/v8_task2_comparison.csv")
ref_row = same_space[same_space.model == "REF_linux_only_normalized"].iloc[0]
print(f"  REF baseline (same-space): Linux novel recall={ref_row.overall_recall*100:.1f}%  "
      f"Linux FPR={ref_row.fpr*100:.1f}%  Linux F1={ref_row.f1:.4f}")
tradeoff_rows = []
for cname in ["C1_win_native", "C2_xplatform_v7", "C3_xplatform_v8"]:
    t2 = task2[task2.row == cname].iloc[0]
    t3 = same_space[same_space.model == cname].iloc[0]
    d_recall = (t3.overall_recall - ref_row.overall_recall) * 100
    d_fpr = (t3.fpr - ref_row.fpr) * 100
    d_f1 = t3.f1 - ref_row.f1
    flag = "REGRESSION >few pts" if d_recall < -3 else ("IMPROVED" if d_recall > 3 else "~unchanged")
    print(f"  {cname:<20} Windows F1={t2.f1:.4f} (vs REF-style saturated baseline)  |  "
          f"Linux novel recall {ref_row.overall_recall*100:.1f}% -> {t3.overall_recall*100:.1f}% "
          f"(delta {d_recall:+.1f}pp)  Linux FPR {ref_row.fpr*100:.1f}% -> {t3.fpr*100:.1f}% "
          f"(delta {d_fpr:+.1f}pp)  [{flag}]")
    tradeoff_rows.append(dict(candidate=cname, windows_f1=t2.f1, windows_fpr=t2.fpr,
                               linux_novel_recall_before=ref_row.overall_recall,
                               linux_novel_recall_after=t3.overall_recall,
                               linux_recall_delta_pp=d_recall,
                               linux_fpr_before=ref_row.fpr, linux_fpr_after=t3.fpr,
                               linux_fpr_delta_pp=d_fpr, linux_f1_delta=d_f1, flag=flag))

pd.DataFrame(tradeoff_rows).to_csv(f"{HERE}/v8_task3_tradeoff.csv", index=False)
print(f"\nwrote {HERE}/v8_task3_tradeoff.csv")
