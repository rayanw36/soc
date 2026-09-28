#!/usr/bin/env python3
"""
REV-C Task 3(b) -- multiseed reruns of every model-fit-dependent headline
number: the three ablation variants (full/no_identity/behav_only, same
methodology as results/rule_memorization_audit/exp4_ablation.py) on the
RANDOM (deployed) split, and the audit-time retrain on the TEMPORAL split
(newCol/rev_task1_temporal_split.py) -- added per explicit instruction,
since a 0.0002 model-vs-lookup gap on a single seed needs its own interval.

10 seeds (0-9) per configuration. Read-only over models_v2/ait_split.npz
and newCol/xdet_wazuh_recovered_split.npz. Writes only to newCol/rev_task3_*.
No modification of any existing artifact.
"""
import json
import math
import statistics
import time

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score
from xgboost import XGBClassifier

SEEDS = list(range(10))
SPLIT_PATH = "models_v2/ait_split.npz"
RECOVERED_PATH = "analysis/xdet_wazuh_recovered_split.npz"
OUT_JSON = "analysis/rev_task3_multiseed_results.json"

RULE_IDENTITY = ["desc_len", "rule_level", "rule_id_encoded"]
BEHAVIORAL = ["alert_rate_1min", "unique_src_ip_10min", "time_since_last_high"]

XGB_PARAMS_BASE = dict(n_estimators=50, max_depth=5, subsample=0.5,
                        learning_rate=0.1, eval_metric="logloss", n_jobs=-1)


def prf(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return dict(precision=precision, recall=recall, f1=f1, fpr=fpr)


def find_best_theta(proba, y_true, n_grid=300):
    best_f1, best_t = 0.0, 0.5
    for t in np.linspace(proba.min() + 1e-6, proba.max() - 1e-6, n_grid):
        f = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_t = f, t
    return float(best_t)


def summarize(runs, key):
    vals = [r[key] for r in runs]
    n = len(vals)
    mean = statistics.mean(vals)
    sd = statistics.stdev(vals) if n > 1 else 0.0
    ci95_halfwidth = 1.96 * sd / math.sqrt(n) if n > 1 else 0.0
    return {"mean": mean, "sd": sd, "ci95_low": mean - ci95_halfwidth,
            "ci95_high": mean + ci95_halfwidth, "min": min(vals), "max": max(vals),
            "values": vals}


def run_seeds(X_train, y_train, X_test, y_test, label):
    runs = []
    for seed in SEEDS:
        t0 = time.time()
        model = XGBClassifier(**XGB_PARAMS_BASE, random_state=seed)
        model.fit(X_train, y_train, verbose=False)
        proba = model.predict_proba(X_test)[:, 1]
        theta = find_best_theta(proba, y_test)
        pred = (proba >= theta).astype(int)
        m = prf(y_test, pred)
        m["theta"] = theta
        runs.append(m)
        print(f"  [{label}] seed={seed} F1={m['f1']:.4f} theta={theta:.5f} "
              f"({time.time()-t0:.1f}s)", flush=True)
    return runs


def main():
    split = np.load(SPLIT_PATH, allow_pickle=True)
    X_train, y_train = split["X_train"], split["y_train"]
    X_test, y_test = split["X_test"], split["y_test"]
    feat_cols = list(split["feature_cols"])
    col_idx = {f: i for i, f in enumerate(feat_cols)}

    def select(X, feats):
        return X[:, [col_idx[f] for f in feats]]

    VARIANTS = {
        "full": feat_cols,
        "no_identity": [f for f in feat_cols if f not in RULE_IDENTITY],
        "behav_only": BEHAVIORAL,
    }
    assert len(VARIANTS["full"]) == 26
    assert len(VARIANTS["no_identity"]) == 23
    assert len(VARIANTS["behav_only"]) == 3

    all_results = {}

    print("=" * 70)
    print("RANDOM split -- 3 ablation variants x 10 seeds")
    print("=" * 70)
    for variant, feats in VARIANTS.items():
        print(f"\n--- variant: {variant} ({len(feats)} features) ---")
        Xtr, Xte = select(X_train, feats), select(X_test, feats)
        runs = run_seeds(Xtr, y_train, Xte, y_test, f"random/{variant}")
        all_results[f"random_{variant}"] = runs

    # ---- temporal split (added per instruction) ----------------------------
    print("\n" + "=" * 70)
    print("TEMPORAL split -- audit-time retrain (full, 26-feat) x 10 seeds")
    print("=" * 70)
    rec = np.load(RECOVERED_PATH, allow_pickle=True)
    idx_train, idx_test = rec["idx_train"], rec["idx_test"]
    y_all, rid_all, eps_all = rec["y_all"], rec["rid_all"], rec["eps_all"]
    n_total = len(y_all)
    assert np.array_equal(y_all[idx_train], y_train)
    assert np.array_equal(y_all[idx_test], y_test)

    X_all = np.empty((n_total, X_train.shape[1]), dtype=X_train.dtype)
    X_all[idx_train] = X_train
    X_all[idx_test] = X_test

    order = np.argsort(eps_all, kind="stable")
    cut = int(n_total * 0.80)
    idx_tr_t, idx_te_t = order[:cut], order[cut:]
    X_tr_t, y_tr_t = X_all[idx_tr_t], y_all[idx_tr_t]
    X_te_t, y_te_t = X_all[idx_te_t], y_all[idx_te_t]
    rid_tr_t, rid_te_t = rid_all[idx_tr_t], rid_all[idx_te_t]

    runs_temporal = run_seeds(X_tr_t, y_tr_t, X_te_t, y_te_t, "temporal/full")
    all_results["temporal_full"] = runs_temporal

    # ---- lookup table on temporal split is deterministic (majority vote,  --
    # ---- no RNG) -- computed once, not seeded, for the gap comparison ------
    from collections import Counter, defaultdict
    counts = defaultdict(Counter)
    for rid, y in zip(rid_tr_t, y_tr_t):
        counts[int(rid)][int(y)] += 1
    lookup = {rid: (1 if c[1] >= c[0] else 0) for rid, c in counts.items()}
    lookup_pred = np.array([lookup.get(int(r), 0) for r in rid_te_t])
    lookup_metrics_temporal = prf(y_te_t, lookup_pred)
    print(f"\n  [temporal] lookup table (deterministic, single value): "
          f"F1={lookup_metrics_temporal['f1']:.4f}")

    # ---- also the RANDOM-split lookup table, for the gap comparison --------
    rid_tr_r, rid_te_r = rid_all[idx_train], rid_all[idx_test]
    counts_r = defaultdict(Counter)
    for rid, y in zip(rid_tr_r, y_train):
        counts_r[int(rid)][int(y)] += 1
    lookup_r = {rid: (1 if c[1] >= c[0] else 0) for rid, c in counts_r.items()}
    lookup_pred_r = np.array([lookup_r.get(int(r), 0) for r in rid_te_r])
    lookup_metrics_random = prf(y_test, lookup_pred_r)
    print(f"  [random] lookup table (deterministic, single value): "
          f"F1={lookup_metrics_random['f1']:.4f}")

    # ---- summarize -----------------------------------------------------------
    summary = {}
    for key, runs in all_results.items():
        summary[key] = {m: summarize(runs, m) for m in ["f1", "precision", "recall", "fpr"]}

    # gap = model F1 (seeded) - lookup F1 (fixed), per seed
    gap_random_full = [r["f1"] - lookup_metrics_random["f1"] for r in all_results["random_full"]]
    gap_temporal = [r["f1"] - lookup_metrics_temporal["f1"] for r in all_results["temporal_full"]]
    summary["gap_random_full_vs_lookup"] = {
        "lookup_f1": lookup_metrics_random["f1"],
        "mean_gap": statistics.mean(gap_random_full),
        "sd_gap": statistics.stdev(gap_random_full),
        "values": gap_random_full,
    }
    summary["gap_temporal_vs_lookup"] = {
        "lookup_f1": lookup_metrics_temporal["f1"],
        "mean_gap": statistics.mean(gap_temporal),
        "sd_gap": statistics.stdev(gap_temporal),
        "values": gap_temporal,
    }

    out = {
        "seeds": SEEDS,
        "raw_runs": all_results,
        "lookup_random": lookup_metrics_random,
        "lookup_temporal": lookup_metrics_temporal,
        "summary": summary,
    }

    def jsonable(o):
        if isinstance(o, dict):
            return {str(k): jsonable(v) for k, v in o.items()}
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, (np.bool_,)):
            return bool(o)
        if isinstance(o, list):
            return [jsonable(x) for x in o]
        return o

    with open(OUT_JSON, "w") as f:
        json.dump(jsonable(out), f, indent=2)
    print(f"\nSaved {OUT_JSON}")


if __name__ == "__main__":
    main()
