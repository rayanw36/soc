#!/usr/bin/env python3
"""
XDET Task 1 (+ Addition A) — per-detector majority-label-per-signature
lookup table, built on train, scored on eval, for:
  - Wazuh-native  (rule.id != 86601, keyed on rule.id)      -- from the
    recovered exact split (newCol/xdet_wazuh_recovered_split.npz)
  - Suricata      (rule.id == 86601, keyed on rule.description) -- same
    recovered split, restricted to the 86601 subset (= Addition A(b))
  - AMiner        (keyed on AnalysisComponentName)          -- from the
    freshly-built split (newCol/xdet_aminer_split.npz)

MODEL COMPARISON NOTE (read before editing): the deployed
models_v2/xgb_model.pkl is UNUSABLE in this environment. Verified
directly: predict_proba on ait_split.npz's X_test tops out at 0.059
(mean 0.0041), entirely below theta_xgb=0.0754, giving TP=0 on every
possible subset -- not a real result, a version-mismatch artifact. This
exact issue was already diagnosed by prior work
(newCol/figures_ms/fig1_lookup_vs_model.py's docstring: "xgboost
model-serialization-version-mismatch warning... explains the degenerate
0.0000 output") and exp4_ablation.py's own docstring ("fresh retrain;
used as baseline since pkl has version mismatch"). Per that established
precedent we do NOT score the deployed pkl; Addition A(a) instead uses
an audit-time retrain that exactly reproduces exp4_ablation.py's "full"
(26-feature) variant -- same XGB_PARAMS, same raw (unscaled) features,
same find_best_theta calibration on the eval split -- then breaks the
SAME eval split out by rule 86601 vs Wazuh-native. This is a fresh
retrain (needed for the per-subset breakdown, which exp4's committed
CSV does not contain), not a retrain of any DEPLOYED model, and its
threshold is an audit-only F1-maximizing calibration, NOT theta_xgb.
This substitution, and the fact that "at the deployed threshold" could
not literally be honored, is stated plainly per the no-fabrication rule.

NMI convention (stated once, used everywhere in this file): sklearn
normalized_mutual_info_score with its DEFAULT average_method='arithmetic'
-- the same call signature already used in
results/rule_memorization_audit/exp3_lookup_table.py. This is the
convention we standardize on for this audit.
"""
import json
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
from collections import Counter, defaultdict

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, normalized_mutual_info_score

sys.path.insert(0, REPO_ROOT)
from shared_constants import FEATURE_COLS_V2, SEED  # noqa: E402

WAZUH_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_wazuh_recovered_split.npz")
AMINER_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_aminer_split.npz")
SPLIT_NPZ = _os.path.join(REPO_ROOT, "models_v2", "ait_split.npz")


def prf_fpr(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return dict(precision=precision, recall=recall, f1=f1, fpr=fpr,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


def build_and_score_lookup(sig_train, y_train, sig_eval, y_eval):
    counts = defaultdict(Counter)
    for s, y in zip(sig_train, y_train):
        counts[s][int(y)] += 1
    lookup = {s: (1 if c[1] >= c[0] else 0) for s, c in counts.items()}
    pred = np.array([lookup.get(s, 0) for s in sig_eval])
    n_unseen = sum(1 for s in sig_eval if s not in lookup)
    metrics = prf_fpr(y_eval, pred)
    metrics["n_signatures_train"] = len(lookup)
    metrics["n_unseen_eval"] = n_unseen
    metrics["n_unseen_eval_pct"] = 100.0 * n_unseen / len(sig_eval) if len(sig_eval) else float("nan")
    return metrics, lookup


def nmi(y, sig):
    return normalized_mutual_info_score(y, np.asarray(sig, dtype=object))


def top_signature_share_of_attacks(sig, y):
    y = np.asarray(y)
    sig = np.asarray(sig, dtype=object)
    attack_mask = y == 1
    if attack_mask.sum() == 0:
        return None, 0.0
    c = Counter(sig[attack_mask])
    top_sig, top_n = c.most_common(1)[0]
    return top_sig, 100.0 * top_n / attack_mask.sum()


def describe_detector(name, sig_subset, y_subset, train_mask, eval_mask):
    """sig_subset / y_subset are ALREADY restricted to this detector's rows
    (e.g. rule.id != 86601 for Wazuh-native). train_mask / eval_mask are
    boolean masks of the SAME length as sig_subset, marking which of those
    rows fall in train vs eval."""
    sig_subset = np.asarray(sig_subset, dtype=object)
    y_subset = np.asarray(y_subset)
    n = len(y_subset)
    n_sig = len(set(sig_subset.tolist()))
    attack_rate = y_subset.mean()
    top_sig, top_share = top_signature_share_of_attacks(sig_subset, y_subset)

    sig_tr, y_tr = sig_subset[train_mask], y_subset[train_mask]
    sig_te, y_te = sig_subset[eval_mask], y_subset[eval_mask]

    lookup_metrics, lookup = build_and_score_lookup(sig_tr, y_tr, sig_te, y_te)
    nmi_train = nmi(y_tr, sig_tr)
    nmi_test = nmi(y_te, sig_te)
    nmi_full = nmi(y_subset, sig_subset)

    print(f"\n{'='*70}\n{name}\n{'='*70}")
    print(f"  alerts total: {n:,}  distinct signatures: {n_sig}  attack rate: {attack_rate:.4f}")
    print(f"  top attack signature: {top_sig!r}  ({top_share:.1f}% of all attack alerts)")
    print(f"  train: {len(y_tr):,}  eval: {len(y_te):,}")
    print(f"  lookup table: P={lookup_metrics['precision']:.4f} R={lookup_metrics['recall']:.4f} "
          f"F1={lookup_metrics['f1']:.4f} FPR={lookup_metrics['fpr']:.4f}")
    print(f"  lookup: TP={lookup_metrics['tp']:,} FP={lookup_metrics['fp']:,} "
          f"TN={lookup_metrics['tn']:,} FN={lookup_metrics['fn']:,}")
    print(f"  distinct signatures in train: {lookup_metrics['n_signatures_train']}  "
          f"unseen-in-eval alerts: {lookup_metrics['n_unseen_eval']:,} "
          f"({lookup_metrics['n_unseen_eval_pct']:.2f}%)")
    print(f"  NMI(signature,label): train={nmi_train:.4f} eval={nmi_test:.4f} full={nmi_full:.4f}")

    return dict(
        name=name, n=n, n_signatures=n_sig, attack_rate=float(attack_rate),
        top_signature=str(top_sig), top_signature_attack_share_pct=top_share,
        n_train=len(y_tr), n_eval=len(y_te),
        lookup=lookup_metrics, nmi_train=nmi_train, nmi_eval=nmi_test, nmi_full=nmi_full,
    )


def main():
    results = {}

    # ---- load recovered Wazuh stream (all 31 rule IDs, exact split) -------
    wz = np.load(WAZUH_NPZ, allow_pickle=True)
    rid_all, rdesc_all, y_all = wz["rid_all"], wz["rdesc_all"], wz["y_all"]
    idx_train, idx_test = wz["idx_train"], wz["idx_test"]
    n_wz = len(y_all)

    is_train_full = np.zeros(n_wz, dtype=bool); is_train_full[idx_train] = True
    is_eval_full = np.zeros(n_wz, dtype=bool); is_eval_full[idx_test] = True

    native_mask = rid_all != 86601
    suricata_mask = rid_all == 86601

    # ---- Wazuh-native (rule.id != 86601) -----------------------------------
    results["wazuh_native"] = describe_detector(
        "WAZUH-NATIVE (30 signatures, rule.id != 86601)",
        rid_all[native_mask], y_all[native_mask],
        is_train_full[native_mask], is_eval_full[native_mask])

    # ---- Suricata (rule.id == 86601, keyed by rule.description) = Addn A(b)
    results["suricata"] = describe_detector(
        "SURICATA (29 signatures, embedded in Wazuh rule 86601, keyed by rule.description)",
        rdesc_all[suricata_mask], y_all[suricata_mask],
        is_train_full[suricata_mask], is_eval_full[suricata_mask])

    # ---- AMiner -------------------------------------------------------
    am = np.load(AMINER_NPZ, allow_pickle=True)
    n_am = len(am["y_all"])
    is_train_am = np.zeros(n_am, dtype=bool); is_train_am[am["idx_train"]] = True
    is_eval_am = np.zeros(n_am, dtype=bool); is_eval_am[am["idx_test"]] = True
    results["aminer"] = describe_detector(
        "AMiner (34 signatures, keyed by AnalysisComponentName)",
        am["name_all"], am["y_all"], is_train_am, is_eval_am)

    # ---- Addition A(a): audit-time model retrain (exp4 "full" variant), --
    # ---- same eval split, broken out by rule 86601 vs Wazuh-native -------
    print(f"\n{'='*70}\nADDITION A(a) -- audit-time XGBoost retrain (exp4_ablation.py 'full' "
          f"variant methodology; deployed pkl is unusable, see script docstring), "
          f"same eval split, broken out by rule 86601 vs Wazuh-native\n{'='*70}")
    from xgboost import XGBClassifier
    from sklearn.metrics import f1_score as _f1

    split = np.load(SPLIT_NPZ, allow_pickle=True)
    X_train_full = split["X_train"]
    y_train_full = split["y_train"]
    X_test_full = split["X_test"]
    y_test_full = split["y_test"]

    # sanity: recovered idx_test must align 1:1, row-for-row, with X_test_full
    assert np.array_equal(y_all[idx_test], y_test_full), \
        "recovered idx_test does not align with ait_split.npz X_test/y_test -- abort"
    assert np.array_equal(y_all[idx_train], y_train_full), \
        "recovered idx_train does not align with ait_split.npz X_train/y_train -- abort"

    XGB_PARAMS = dict(n_estimators=50, max_depth=5, subsample=0.5,
                       learning_rate=0.1, eval_metric="logloss",
                       random_state=SEED, n_jobs=-1)
    model = XGBClassifier(**XGB_PARAMS)
    model.fit(X_train_full, y_train_full, verbose=False)

    proba_test = model.predict_proba(X_test_full)[:, 1]

    def find_best_theta(proba, y_true, n_grid=300):
        best_f1, best_t = 0.0, 0.5
        for t in np.linspace(proba.min() + 1e-6, proba.max() - 1e-6, n_grid):
            f = _f1(y_true, (proba >= t).astype(int), zero_division=0)
            if f > best_f1:
                best_f1, best_t = f, t
        return float(best_t), float(best_f1)

    theta_audit, f1_cal = find_best_theta(proba_test, y_test_full)
    print(f"  audit-time retrain calibrated theta={theta_audit:.5f} (max-F1 on eval split, "
          f"F1={f1_cal:.4f}) -- NOT the deployed theta_xgb=0.07538")
    pred = (proba_test >= theta_audit).astype(int)

    rid_test_aligned = rid_all[idx_test]  # aligned to X_test_full row order
    subset_results = {}
    for label, mask in [
        ("Wazuh-native (rule.id != 86601)", rid_test_aligned != 86601),
        ("Suricata-via-Wazuh (rule.id == 86601)", rid_test_aligned == 86601),
    ]:
        m = prf_fpr(y_test_full[mask], pred[mask])
        print(f"  {label}: n={mask.sum():,}  P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['fpr']:.4f}  "
              f"(TP={m['tp']:,} FP={m['fp']:,} TN={m['tn']:,} FN={m['fn']:,})")
        subset_results[label] = m
    subset_results["theta_audit_retrain"] = theta_audit
    subset_results["note"] = ("audit-time retrain, exp4_ablation.py 'full'-variant "
                               "methodology; deployed xgb_model.pkl is degenerate in this "
                               "environment (see script docstring) and was not usable")
    results["deployed_model_by_subset"] = subset_results

    # ---- Addition A(c): is 86601 population a non-random subset? ----------
    print(f"\n{'='*70}\nADDITION A(c) -- composition of the 86601 (Suricata) population\n{'='*70}")
    scn_all = wz["scn_all"]
    suri_scn = scn_all[suricata_mask]
    suri_y = y_all[suricata_mask]
    print(f"  n={suricata_mask.sum():,}  attack rate={suri_y.mean():.4f}")
    print("  scenario composition:")
    for scn, cnt in Counter(suri_scn.tolist()).most_common():
        print(f"    {scn:16s} {cnt:>8,} ({100*cnt/len(suri_scn):.1f}%)")
    # attack-window label composition (which attack-window categories does
    # the 86601 population fall into, if any)
    results["suricata_composition"] = {
        "n": int(suricata_mask.sum()),
        "attack_rate": float(suri_y.mean()),
        "scenario_counts": {str(k): int(v) for k, v in Counter(suri_scn.tolist()).items()},
    }

    # ---- save everything --------------------------------------------------
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

    out_path = _os.path.join(REPO_ROOT, "analysis", "xdet_task1_results.json")
    with open(out_path, "w") as f:
        json.dump(jsonable(results), f, indent=2)
    print(f"\nSaved {out_path}")


if __name__ == "__main__":
    main()
