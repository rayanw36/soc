import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
"""
Experiment 3 — Mutual information / lookup-table test.
Builds a majority-label-per-rule-ID lookup table on X_train,
evaluates it on X_test, and reports NMI and rule-31101 distribution.
"""
import sys, csv
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, REPO_ROOT)

import numpy as np
from collections import defaultdict, Counter
from sklearn.metrics import f1_score, normalized_mutual_info_score, classification_report
import json

SPLIT_PATH = REPO_ROOT + "/models_v2/ait_split.npz"
MODEL_PATH  = REPO_ROOT + "/models_v2/xgb_model.pkl"
THRESH_PATH = REPO_ROOT + "/models_v2/thresholds_production_v3.json"
OUT_CSV     = REPO_ROOT + "/results/rule_memorization_audit/exp3_lookup_results.csv"

from shared_constants import FEATURE_COLS_V2

# ---- load split -----------------------------------------------------------
print("Loading split...", flush=True)
data   = np.load(SPLIT_PATH, allow_pickle=True)
X_train = data["X_train"]
y_train = data["y_train"]
X_test  = data["X_test"]
y_test  = data["y_test"]
feat_cols = list(data["feature_cols"])

rid_col = feat_cols.index("rule_id_encoded")
print(f"  rule_id_encoded column index: {rid_col}", flush=True)
print(f"  Train: {X_train.shape}  |  Test: {X_test.shape}", flush=True)

# ---- load XGBoost model to get published F1 for comparison ----------------
import pickle
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

with open(THRESH_PATH) as f:
    thresholds = json.load(f)

theta_xgb = thresholds.get("theta_xgb", 0.0754)
print(f"  Published XGB threshold: {theta_xgb}", flush=True)

xgb_proba = model.predict_proba(X_test)[:, 1]
xgb_pred  = (xgb_proba >= theta_xgb).astype(int)
xgb_f1    = f1_score(y_test, xgb_pred)
print(f"  Published XGB F1 on eval split: {xgb_f1:.4f}", flush=True)

# ---- build majority-label lookup table ------------------------------------
print("\nBuilding majority-label lookup table on X_train...", flush=True)
label_counts = defaultdict(Counter)  # rule_id_encoded -> Counter({0: n, 1: n})
train_rids = X_train[:, rid_col]
for rid_val, y in zip(train_rids, y_train):
    label_counts[rid_val][int(y)] += 1

lookup = {}  # rule_id_encoded float -> majority label (0 or 1)
for rid_val, cnt in label_counts.items():
    lookup[rid_val] = 1 if cnt[1] >= cnt[0] else 0

# stats
n_rules = len(lookup)
n_attack_rules = sum(1 for v in lookup.values() if v == 1)
n_benign_rules = n_rules - n_attack_rules
print(f"  Distinct rule IDs in train: {n_rules}")
print(f"  Rules mapped to attack (1): {n_attack_rules}")
print(f"  Rules mapped to benign (0): {n_benign_rules}")

# ---- evaluate on X_test ---------------------------------------------------
print("\nEvaluating lookup table on X_test...", flush=True)
test_rids = X_test[:, rid_col]
lookup_pred = np.array([lookup.get(rid, 0) for rid in test_rids])

# F1 at default (majority-label output, no threshold)
lookup_f1 = f1_score(y_test, lookup_pred)
print(f"\n  Lookup-table F1:     {lookup_f1:.4f}")
print(f"  XGBoost F1:          {xgb_f1:.4f}")
print(f"  Gap (XGB - lookup):  {xgb_f1 - lookup_f1:.4f}")

print("\n  Lookup-table classification report:")
print(classification_report(y_test, lookup_pred, target_names=["benign","attack"], digits=4))

# ---- NMI between rule_id and label ----------------------------------------
print("Computing NMI(rule_id, label)...", flush=True)
nmi_train = normalized_mutual_info_score(y_train, train_rids.astype(int))
nmi_test  = normalized_mutual_info_score(y_test,  test_rids.astype(int))
print(f"  NMI(rule_id_encoded, label) on train: {nmi_train:.4f}")
print(f"  NMI(rule_id_encoded, label) on test:  {nmi_test:.4f}")

# ---- Rule 31101 distribution ---------------------------------------------
# rule_id_encoded for 31101 is float(31101) = 31101.0
R31101 = 31101.0
print(f"\n### Label distribution within rule 31101")

# Train
mask_train_31 = (train_rids == R31101)
y_train_31 = y_train[mask_train_31]
cnt_train = Counter(y_train_31.tolist())
print(f"  Train: total={mask_train_31.sum():,}  attack={cnt_train[1]:,} ({100*cnt_train[1]/max(mask_train_31.sum(),1):.1f}%)  benign={cnt_train[0]:,}")

# Test
mask_test_31 = (test_rids == R31101)
y_test_31 = y_test[mask_test_31]
cnt_test = Counter(y_test_31.tolist())
print(f"  Test:  total={mask_test_31.sum():,}  attack={cnt_test[1]:,} ({100*cnt_test[1]/max(mask_test_31.sum(),1):.1f}%)  benign={cnt_test[0]:,}")

# How does lookup predict 31101?
lkup_31101 = lookup.get(R31101, None)
print(f"  Lookup maps rule 31101 -> {'attack (1)' if lkup_31101==1 else 'benign (0)' if lkup_31101==0 else 'UNSEEN'}")

# ---- Top rules by attack count in train, with lookup label ---------------
print("\n### Top 10 attack-contributing rules (X_train)")
print(f"  {'Rule ID':>10}  {'Attack':>10}  {'Benign':>10}  {'Atk%':>7}  {'Lookup':>8}")
print("  " + "-"*55)
sorted_rules = sorted(label_counts.items(), key=lambda x: -x[1][1])
for rid_val, cnt in sorted_rules[:10]:
    atk = cnt[1]; ben = cnt[0]; total = atk + ben
    lbl = lookup.get(rid_val, 0)
    rule_int = int(rid_val) if rid_val == int(rid_val) else rid_val
    print(f"  {rule_int:>10}  {atk:>10,}  {ben:>10,}  {100*atk/total:>6.1f}%  {'attack' if lbl==1 else 'benign':>8}")

# ---- Rules that are attack in lookup but appear in benign test set -------
n_unseen = sum(1 for rid in test_rids if rid not in lookup)
print(f"\n  Unseen rule IDs in test (defaulted to benign=0): {n_unseen:,} "
      f"({100*n_unseen/len(test_rids):.2f}%)")

# ---- Write summary CSV ---------------------------------------------------
results = [
    {"metric": "XGBoost F1 (published)", "value": f"{xgb_f1:.4f}"},
    {"metric": "Lookup-table F1 (rule_id only)", "value": f"{lookup_f1:.4f}"},
    {"metric": "Gap (XGB - lookup)", "value": f"{xgb_f1 - lookup_f1:.4f}"},
    {"metric": "NMI(rule_id, label) train", "value": f"{nmi_train:.4f}"},
    {"metric": "NMI(rule_id, label) test", "value": f"{nmi_test:.4f}"},
    {"metric": "Distinct rules in train", "value": str(n_rules)},
    {"metric": "Rules mapped to attack", "value": str(n_attack_rules)},
    {"metric": "Rules mapped to benign", "value": str(n_benign_rules)},
    {"metric": "Rule 31101 train attack%", "value": f"{100*cnt_train[1]/max(mask_train_31.sum(),1):.1f}%"},
    {"metric": "Rule 31101 test attack%", "value": f"{100*cnt_test[1]/max(mask_test_31.sum(),1):.1f}%"},
    {"metric": "Unseen test rule IDs", "value": str(n_unseen)},
]
with open(OUT_CSV, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["metric","value"])
    w.writeheader()
    w.writerows(results)
print(f"\nWrote → {OUT_CSV}", flush=True)
print("Checkpoint 3 complete.", flush=True)
