#!/usr/bin/env python3
"""
REV-C Task 1 -- temporal-split rerun of the lookup-table-vs-model comparison.

Read-only over models_v2/ait_split.npz and newCol/xdet_wazuh_recovered_split.npz
(neither is modified). No new collection. Writes only to newCol/rev_task1_*.

Procedure:
  1. Confirm (again, locally) that models_v2/ait_split.npz's train/test split is
     the stratified-random split produced by phase1_xgboost.py:170-171
     (`train_test_split(X, y, test_size=0.20, stratify=y, random_state=SEED)`).
  2. Reconstruct the 26-dim feature matrix in ORIGINAL alert order by scattering
     ait_split.npz's X_train/X_test back via the recovered idx_train/idx_test
     index arrays (newCol/xdet_wazuh_recovered_split.npz, already verified
     byte-identical to the deployed split -- see that script's own internal
     assertion). This avoids re-parsing 2.6M raw JSON lines and re-deriving the
     AgentHistory-dependent temporal features from scratch; it reuses the exact
     already-computed feature vectors, just re-indexed into time order.
  3. Build a NEW temporal split: sort all 2,600,263 alerts by their true event
     epoch (rule.id-independent, taken from the raw Wazuh timestamp field) and
     take the earliest 80% as train, latest 20% as test -- same 80/20 ratio as
     the deployed split, for comparability.
  4. Rerun the SAME two audits on this temporal split:
       (a) majority-label-per-rule-id lookup table (same code path as
           results/rule_memorization_audit/exp3_lookup_table.py)
       (b) audit-time XGBoost retrain, 26-feature "full" variant, same
           XGB_PARAMS as results/rule_memorization_audit/exp4_ablation.py /
           newCol/xdet_task1_lookup.py Addition A(a) (n_estimators=50,
           max_depth=5, subsample=0.5, learning_rate=0.1, eval_metric=logloss,
           random_state=SEED), threshold calibrated by max-F1 grid search on
           the eval split -- identical calibration procedure used to produce
           the "random split (current)" figures already in the manuscript
           response draft, so the two rows are apples-to-apples.
"""
import json
import sys
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, normalized_mutual_info_score
from xgboost import XGBClassifier
import sklearn, xgboost

SEED = 42
SPLIT_PATH = "models_v2/ait_split.npz"
RECOVERED_PATH = "analysis/xdet_wazuh_recovered_split.npz"
OUT_JSON = "analysis/rev_task1_temporal_results.json"


def prf(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return dict(precision=precision, recall=recall, f1=f1, fpr=fpr,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


def find_best_theta(proba, y_true, n_grid=300):
    best_f1, best_t = 0.0, 0.5
    for t in np.linspace(proba.min() + 1e-6, proba.max() - 1e-6, n_grid):
        f = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_t = f, t
    return float(best_t), float(best_f1)


def main():
    print(f"python-lib versions used for this audit: numpy={np.__version__} "
          f"pandas={pd.__version__} sklearn={sklearn.__version__} xgboost={xgboost.__version__}")

    split = np.load(SPLIT_PATH, allow_pickle=True)
    X_train, y_train = split["X_train"], split["y_train"]
    X_test, y_test = split["X_test"], split["y_test"]
    feat_cols = list(split["feature_cols"])
    rid_col = feat_cols.index("rule_id_encoded")

    rec = np.load(RECOVERED_PATH, allow_pickle=True)
    idx_train, idx_test = rec["idx_train"], rec["idx_test"]
    y_all, rid_all, scn_all, eps_all = rec["y_all"], rec["rid_all"], rec["scn_all"], rec["eps_all"]
    n_total = len(y_all)

    assert np.array_equal(y_all[idx_train], y_train), "recovered idx_train misaligned"
    assert np.array_equal(y_all[idx_test], y_test), "recovered idx_test misaligned"
    print(f"[OK] recovered index arrays verified against models_v2/ait_split.npz "
          f"(random-split reproduction) -- n_total={n_total:,}")

    # ---- reconstruct X_all in original alert order -------------------------
    X_all = np.empty((n_total, X_train.shape[1]), dtype=X_train.dtype)
    X_all[idx_train] = X_train
    X_all[idx_test] = X_test

    # sanity: rid_all should match X_all's rule_id_encoded column exactly
    assert np.array_equal(rid_all.astype(np.float64), X_all[:, rid_col]), \
        "rid_all does not match X_all rule_id_encoded column -- reconstruction bug"
    print("[OK] X_all reconstruction verified against rid_all")

    n_nan_eps = int(np.isnan(eps_all).sum())
    print(f"NaN epochs: {n_nan_eps}")

    # ---- RANDOM split (current, for reference) -----------------------------
    print(f"\n{'='*70}\nRANDOM split (current, models_v2/ait_split.npz) -- for reference\n{'='*70}")
    print(f"  train: n={len(y_train):,} attack={y_train.sum():,} ({100*y_train.mean():.2f}%) "
          f"benign={(y_train==0).sum():,}")
    print(f"  test : n={len(y_test):,} attack={y_test.sum():,} ({100*y_test.mean():.2f}%) "
          f"benign={(y_test==0).sum():,}")

    # ---- NEW temporal split -------------------------------------------------
    print(f"\n{'='*70}\nTEMPORAL split (new) -- earliest 80% train / latest 20% test\n{'='*70}")
    order = np.argsort(eps_all, kind="stable")
    cut = int(n_total * 0.80)
    idx_tr_t = order[:cut]
    idx_te_t = order[cut:]

    df_scn = pd.DataFrame({"scenario": scn_all})
    cut_time = pd.to_datetime(eps_all[order[cut]], unit="s", utc=True)
    print(f"  cut point (epoch): {cut_time.isoformat()}")
    print(f"  train range: {pd.to_datetime(eps_all[idx_tr_t].min(), unit='s', utc=True)} -- "
          f"{pd.to_datetime(eps_all[idx_tr_t].max(), unit='s', utc=True)}")
    print(f"  test  range: {pd.to_datetime(eps_all[idx_te_t].min(), unit='s', utc=True)} -- "
          f"{pd.to_datetime(eps_all[idx_te_t].max(), unit='s', utc=True)}")
    print(f"  train: n={len(idx_tr_t):,} attack={y_all[idx_tr_t].sum():,} "
          f"({100*y_all[idx_tr_t].mean():.2f}%) benign={(y_all[idx_tr_t]==0).sum():,}")
    print(f"  test : n={len(idx_te_t):,} attack={y_all[idx_te_t].sum():,} "
          f"({100*y_all[idx_te_t].mean():.2f}%) benign={(y_all[idx_te_t]==0).sum():,}")
    print("  train scenario composition:")
    for s, c in df_scn.iloc[idx_tr_t]["scenario"].value_counts().items():
        print(f"    {s:16s} {c:>8,}")
    print("  test scenario composition:")
    for s, c in df_scn.iloc[idx_te_t]["scenario"].value_counts().items():
        print(f"    {s:16s} {c:>8,}")

    X_tr_t, y_tr_t = X_all[idx_tr_t], y_all[idx_tr_t]
    X_te_t, y_te_t = X_all[idx_te_t], y_all[idx_te_t]
    rid_tr_t, rid_te_t = rid_all[idx_tr_t], rid_all[idx_te_t]

    # ---- (a) lookup table, temporal split -----------------------------------
    print(f"\n{'-'*70}\n(a) Majority-label-per-rule-id lookup table, TEMPORAL split\n{'-'*70}")
    counts = defaultdict(Counter)
    for rid, y in zip(rid_tr_t, y_tr_t):
        counts[int(rid)][int(y)] += 1
    lookup = {rid: (1 if c[1] >= c[0] else 0) for rid, c in counts.items()}
    lookup_pred = np.array([lookup.get(int(r), 0) for r in rid_te_t])
    lookup_metrics = prf(y_te_t, lookup_pred)
    n_unseen = sum(1 for r in rid_te_t if int(r) not in lookup)
    nmi_train = normalized_mutual_info_score(y_tr_t, rid_tr_t.astype(int))
    nmi_test = normalized_mutual_info_score(y_te_t, rid_te_t.astype(int))
    print(f"  distinct rule IDs in temporal-train: {len(lookup)}")
    print(f"  unseen rule IDs in temporal-test: {n_unseen:,} ({100*n_unseen/len(rid_te_t):.2f}%)")
    print(f"  Lookup F1={lookup_metrics['f1']:.4f} P={lookup_metrics['precision']:.4f} "
          f"R={lookup_metrics['recall']:.4f} FPR={lookup_metrics['fpr']:.4f}")
    print(f"  NMI(rule_id,label) train={nmi_train:.4f} test={nmi_test:.4f}")

    # rule 31101 breakdown under temporal split
    R31101 = 31101
    mask_tr_31 = rid_tr_t.astype(int) == R31101
    mask_te_31 = rid_te_t.astype(int) == R31101
    cnt_tr_31 = Counter(y_tr_t[mask_tr_31].tolist())
    cnt_te_31 = Counter(y_te_t[mask_te_31].tolist())
    print(f"  rule 31101 -- temporal-train: n={mask_tr_31.sum():,} "
          f"attack%={100*cnt_tr_31[1]/max(mask_tr_31.sum(),1):.1f}%")
    print(f"  rule 31101 -- temporal-test:  n={mask_te_31.sum():,} "
          f"attack%={100*cnt_te_31[1]/max(mask_te_31.sum(),1):.1f}%")

    # ---- (b) audit-time XGBoost retrain, temporal split ---------------------
    print(f"\n{'-'*70}\n(b) Audit-time XGBoost retrain (exp4 'full' variant methodology), "
          f"TEMPORAL split\n{'-'*70}")
    XGB_PARAMS = dict(n_estimators=50, max_depth=5, subsample=0.5,
                       learning_rate=0.1, eval_metric="logloss",
                       random_state=SEED, n_jobs=-1)
    model = XGBClassifier(**XGB_PARAMS)
    model.fit(X_tr_t, y_tr_t, verbose=False)
    proba_te_t = model.predict_proba(X_te_t)[:, 1]
    theta_t, f1_cal_t = find_best_theta(proba_te_t, y_te_t)
    pred_t = (proba_te_t >= theta_t).astype(int)
    model_metrics_t = prf(y_te_t, pred_t)
    print(f"  calibrated theta={theta_t:.5f} (max-F1 grid search on temporal-test)")
    print(f"  Model F1={model_metrics_t['f1']:.4f} P={model_metrics_t['precision']:.4f} "
          f"R={model_metrics_t['recall']:.4f} FPR={model_metrics_t['fpr']:.4f}")

    # ---- also rerun both audits on RANDOM split with byte-identical code, ---
    # ---- as an in-run consistency check against the pre-existing figures ----
    print(f"\n{'-'*70}\nConsistency check: rerun (a) and (b) on the RANDOM split in this "
          f"same script/environment\n{'-'*70}")
    rid_tr_r, rid_te_r = rid_all[idx_train], rid_all[idx_test]
    counts_r = defaultdict(Counter)
    for rid, y in zip(rid_tr_r, y_train):
        counts_r[int(rid)][int(y)] += 1
    lookup_r = {rid: (1 if c[1] >= c[0] else 0) for rid, c in counts_r.items()}
    lookup_pred_r = np.array([lookup_r.get(int(r), 0) for r in rid_te_r])
    lookup_metrics_r = prf(y_test, lookup_pred_r)
    print(f"  [random] Lookup F1={lookup_metrics_r['f1']:.4f} (manuscript draft cites 0.9942 "
          f"from results/rule_memorization_audit/exp3_lookup_results.csv)")

    model_r = XGBClassifier(**XGB_PARAMS)
    model_r.fit(X_train, y_train, verbose=False)
    proba_te_r = model_r.predict_proba(X_test)[:, 1]
    theta_r, f1_cal_r = find_best_theta(proba_te_r, y_test)
    pred_r = (proba_te_r >= theta_r).astype(int)
    model_metrics_r = prf(y_test, pred_r)
    print(f"  [random] Model F1={model_metrics_r['f1']:.4f} theta={theta_r:.5f} "
          f"(manuscript draft cites 0.9945 from results/rule_memorization_audit/exp4_ablation_main.csv "
          f"'full' variant)")

    # ---- save ----------------------------------------------------------------
    def jsonable(o):
        if isinstance(o, dict):
            return {str(k): jsonable(v) for k, v in o.items()}
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, (np.bool_,)):
            return bool(o)
        return o

    results = {
        "library_versions": {"numpy": np.__version__, "pandas": pd.__version__,
                              "sklearn": sklearn.__version__, "xgboost": xgboost.__version__},
        "n_total": n_total,
        "random_split": {
            "train_n": int(len(y_train)), "train_attack": int(y_train.sum()),
            "train_attack_pct": float(100 * y_train.mean()),
            "test_n": int(len(y_test)), "test_attack": int(y_test.sum()),
            "test_attack_pct": float(100 * y_test.mean()),
            "lookup_rerun_here": lookup_metrics_r,
            "model_rerun_here": model_metrics_r,
            "model_theta": theta_r,
        },
        "temporal_split": {
            "cut_epoch": float(eps_all[order[cut]]),
            "cut_iso": cut_time.isoformat(),
            "train_n": int(len(idx_tr_t)), "train_attack": int(y_tr_t.sum()),
            "train_attack_pct": float(100 * y_tr_t.mean()),
            "test_n": int(len(idx_te_t)), "test_attack": int(y_te_t.sum()),
            "test_attack_pct": float(100 * y_te_t.mean()),
            "train_scenario_counts": {str(k): int(v) for k, v in df_scn.iloc[idx_tr_t]["scenario"].value_counts().items()},
            "test_scenario_counts": {str(k): int(v) for k, v in df_scn.iloc[idx_te_t]["scenario"].value_counts().items()},
            "lookup": lookup_metrics,
            "lookup_n_signatures_train": len(lookup),
            "lookup_n_unseen_test": n_unseen,
            "lookup_n_unseen_test_pct": float(100 * n_unseen / len(rid_te_t)),
            "nmi_train": float(nmi_train),
            "nmi_test": float(nmi_test),
            "rule31101_train_n": int(mask_tr_31.sum()),
            "rule31101_train_attack_pct": float(100 * cnt_tr_31[1] / max(mask_tr_31.sum(), 1)),
            "rule31101_test_n": int(mask_te_31.sum()),
            "rule31101_test_attack_pct": float(100 * cnt_te_31[1] / max(mask_te_31.sum(), 1)),
            "model": model_metrics_t,
            "model_theta": theta_t,
        },
    }
    with open(OUT_JSON, "w") as f:
        json.dump(jsonable(results), f, indent=2)
    print(f"\nSaved {OUT_JSON}")


if __name__ == "__main__":
    main()
