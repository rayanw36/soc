import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
"""
Experiment 2 — Feature importance audit on xgb_model.pkl.
Reports gain, weight, and (if shap available) SHAP mean |phi| for top-20 features
with bucket labels from Experiment 1.
"""
import sys, csv, json
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, REPO_ROOT)

import numpy as np
import pickle

MODEL_PATH   = REPO_ROOT + "/models_v2/xgb_model.pkl"
SPLIT_PATH   = REPO_ROOT + "/models_v2/ait_split.npz"
OUT_GAIN     = REPO_ROOT + "/results/rule_memorization_audit/exp2_importance_gain.csv"
OUT_SHAP     = REPO_ROOT + "/results/rule_memorization_audit/exp2_shap_top20.csv"

from shared_constants import FEATURE_COLS_V2

# ---- bucket map from Experiment 1 ----------------------------------------
BUCKET = {
    "desc_len":             "RULE-IDENTITY",
    "rule_level":           "RULE-IDENTITY",
    "rule_id_encoded":      "RULE-IDENTITY",
    "kw_scan":              "RULE-CORRELATED",
    "kw_brute":             "RULE-CORRELATED",
    "kw_password":          "RULE-CORRELATED",
    "kw_denied":            "RULE-CORRELATED",
    "kw_root":              "RULE-CORRELATED",
    "kw_privilege":         "RULE-CORRELATED",
    "kw_sql":               "RULE-CORRELATED",
    "kw_shell":             "RULE-CORRELATED",
    "kw_trojan":            "RULE-CORRELATED",
    "kw_virus":             "RULE-CORRELATED",
    "mitre_tactic_id":      "RULE-CORRELATED",
    "is_auth_failure":      "RULE-CORRELATED",
    "is_web_attack":        "RULE-CORRELATED",
    "agent_criticality":    "RULE-CORRELATED",
    "alert_rate_1min":      "BEHAVIORAL",
    "failed_login_5min":    "RULE-CORRELATED",
    "unique_src_ip_10min":  "BEHAVIORAL",
    "high_sev_ratio_20":    "RULE-CORRELATED",
    "rule_diversity_10min": "RULE-CORRELATED",
    "time_since_last_high": "BEHAVIORAL",
    "scan_preceded":        "RULE-CORRELATED",
    "brute_preceded":       "RULE-CORRELATED",
    "kill_chain_stage":     "RULE-CORRELATED",
}

# ---- load model ------------------------------------------------------------
print("Loading model...", flush=True)
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print(f"  type: {type(model)}", flush=True)

# ---- load eval split -------------------------------------------------------
print("Loading eval split...", flush=True)
data = np.load(SPLIT_PATH, allow_pickle=True)
X_test = data["X_test"]
y_test = data["y_test"]
feat_cols = list(data["feature_cols"])
print(f"  X_test shape: {X_test.shape}  |  y_test shape: {y_test.shape}", flush=True)
print(f"  Feature cols from npz: {feat_cols[:5]} ... {feat_cols[-3:]}", flush=True)

# Verify col order matches FEATURE_COLS_V2
assert feat_cols == FEATURE_COLS_V2, (
    f"Column mismatch!\nnpz:  {feat_cols}\nV2:   {FEATURE_COLS_V2}"
)
print("  Column order verified against FEATURE_COLS_V2 ✓", flush=True)

# ---- Gain + Weight importance from booster ---------------------------------
print("\nExtracting gain/weight importance...", flush=True)
booster = model.get_booster() if hasattr(model, "get_booster") else model

imp_gain   = booster.get_score(importance_type="gain")
imp_weight = booster.get_score(importance_type="weight")
imp_cover  = booster.get_score(importance_type="cover")

# XGBoost uses feature names like "f0", "f1", ... if not set explicitly
# Map fN -> canonical feature name
def resolve_name(key, feat_cols):
    if key.startswith("f") and key[1:].isdigit():
        idx = int(key[1:])
        return feat_cols[idx]
    return key  # already a name

gain_by_feat   = {resolve_name(k, feat_cols): v for k, v in imp_gain.items()}
weight_by_feat = {resolve_name(k, feat_cols): v for k, v in imp_weight.items()}
cover_by_feat  = {resolve_name(k, feat_cols): v for k, v in imp_cover.items()}

# Include zero-importance features
for fn in FEATURE_COLS_V2:
    gain_by_feat.setdefault(fn, 0.0)
    weight_by_feat.setdefault(fn, 0.0)
    cover_by_feat.setdefault(fn, 0.0)

total_gain   = sum(gain_by_feat.values())
total_weight = sum(weight_by_feat.values())

rows = []
for fn in FEATURE_COLS_V2:
    rows.append({
        "feature":       fn,
        "bucket":        BUCKET[fn],
        "gain":          gain_by_feat[fn],
        "gain_pct":      100 * gain_by_feat[fn] / total_gain if total_gain else 0,
        "weight":        weight_by_feat[fn],
        "weight_pct":    100 * weight_by_feat[fn] / total_weight if total_weight else 0,
        "cover":         cover_by_feat[fn],
    })

rows_by_gain = sorted(rows, key=lambda r: -r["gain"])

print("\n### Top 20 features by gain\n")
print(f"{'Rank':<5} {'Feature':<25} {'Bucket':<20} {'Gain %':>8} {'Weight %':>9}")
print("-" * 72)
for rank, r in enumerate(rows_by_gain[:20], 1):
    print(f"  {rank:<3} {r['feature']:<25} {r['bucket']:<20} {r['gain_pct']:>7.2f}% {r['weight_pct']:>8.2f}%")

# ---- Bucket attribution of total gain -------------------------------------
from collections import defaultdict
gain_by_bucket = defaultdict(float)
for r in rows:
    gain_by_bucket[r["bucket"]] += r["gain"]

print("\n### Gain attribution by bucket")
for bkt in ["RULE-IDENTITY", "RULE-CORRELATED", "BEHAVIORAL"]:
    g = gain_by_bucket[bkt]
    print(f"  {bkt:<20}: {g:>12.1f}  ({100*g/total_gain:.2f}%)")

id_corr_gain = gain_by_bucket["RULE-IDENTITY"] + gain_by_bucket["RULE-CORRELATED"]
print(f"\n  RULE-IDENTITY + RULE-CORRELATED: {id_corr_gain:.1f} ({100*id_corr_gain/total_gain:.2f}% of total gain)")
print(f"  BEHAVIORAL                     : {gain_by_bucket['BEHAVIORAL']:.1f} "
      f"({100*gain_by_bucket['BEHAVIORAL']/total_gain:.2f}% of total gain)")

# ---- Write gain CSV -------------------------------------------------------
with open(OUT_GAIN, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["rank","feature","bucket","gain","gain_pct",
                                       "weight","weight_pct","cover"])
    w.writeheader()
    for rank, r in enumerate(rows_by_gain, 1):
        w.writerow({"rank": rank, **r})
print(f"\nWrote gain CSV → {OUT_GAIN}", flush=True)

# ---- SHAP ------------------------------------------------------------------
try:
    import shap
    print("\nSHAP available — computing TreeExplainer on 20K eval sample...", flush=True)
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X_test), size=min(20_000, len(X_test)), replace=False)
    X_sample = X_test[idx]

    explainer = shap.TreeExplainer(model)
    shap_vals = explainer.shap_values(X_sample)

    # For binary classification, shap_values may be list[pos_class] or 2D array
    if isinstance(shap_vals, list):
        sv = shap_vals[1]  # positive class
    else:
        sv = shap_vals

    mean_abs_shap = np.abs(sv).mean(axis=0)  # shape (26,)

    shap_rows = []
    for i, fn in enumerate(FEATURE_COLS_V2):
        shap_rows.append({"feature": fn, "bucket": BUCKET[fn], "mean_abs_shap": mean_abs_shap[i]})

    shap_rows_sorted = sorted(shap_rows, key=lambda r: -r["mean_abs_shap"])
    total_shap = sum(r["mean_abs_shap"] for r in shap_rows)

    print("\n### Top 20 features by mean |SHAP|\n")
    print(f"{'Rank':<5} {'Feature':<25} {'Bucket':<20} {'Mean|SHAP|':>12} {'% total':>9}")
    print("-" * 76)
    for rank, r in enumerate(shap_rows_sorted[:20], 1):
        print(f"  {rank:<3} {r['feature']:<25} {r['bucket']:<20} "
              f"{r['mean_abs_shap']:>12.5f}  {100*r['mean_abs_shap']/total_shap:>7.2f}%")

    shap_by_bucket = defaultdict(float)
    for r in shap_rows:
        shap_by_bucket[r["bucket"]] += r["mean_abs_shap"]

    print("\n### SHAP attribution by bucket")
    for bkt in ["RULE-IDENTITY", "RULE-CORRELATED", "BEHAVIORAL"]:
        s = shap_by_bucket[bkt]
        print(f"  {bkt:<20}: {s:.5f}  ({100*s/total_shap:.2f}%)")
    id_corr_shap = shap_by_bucket["RULE-IDENTITY"] + shap_by_bucket["RULE-CORRELATED"]
    print(f"\n  RULE-IDENTITY + RULE-CORRELATED: {id_corr_shap:.5f} ({100*id_corr_shap/total_shap:.2f}%)")
    print(f"  BEHAVIORAL                     : {shap_by_bucket['BEHAVIORAL']:.5f} "
          f"({100*shap_by_bucket['BEHAVIORAL']/total_shap:.2f}%)")

    with open(OUT_SHAP, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rank","feature","bucket","mean_abs_shap","shap_pct"])
        w.writeheader()
        for rank, r in enumerate(shap_rows_sorted, 1):
            w.writerow({"rank": rank, **r, "shap_pct": f"{100*r['mean_abs_shap']/total_shap:.4f}"})
    print(f"Wrote SHAP CSV → {OUT_SHAP}", flush=True)

except ImportError:
    print("shap not installed — skipping SHAP analysis.", flush=True)

print("\nCheckpoint 2 complete.", flush=True)
