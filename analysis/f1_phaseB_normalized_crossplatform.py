"""
f1_phaseB_normalized_crossplatform.py -- REAL cross-platform F1 / FPR.
=======================================================================
Missing item #1, done properly: the actual deployed cross-platform pipeline is
the NORMALIZED 22-feature model (xgb_normalized.pkl / ocsvm_normalized.pkl),
trained EXCLUSIVELY on Linux (AIT-ADS, via ait_split.npz -> v6_to_normalized),
never on Windows data -- i.e. genuine train-Linux/test-Windows transfer. This is
the model Phase 4's Task 3 used. Phase 4 could not compute Windows FPR because no
Windows benign was collected; we now have one (collection_benign_win_alerts.json,
same testbed, same session convention as the Linux benign), so FPR is computable
here for the first time.

This is DIFFERENT from Phase B's un-normalized result (75% FPR): that used the
Linux-trained 26-FEATURE v6 model applied out-of-domain, which is a transfer-
FAILURE measurement, not the cross-platform model. This script is the real one.

Thresholds are re-derived deterministically from ait_split.npz by the exact
phase3_normalized_v7 method (cost-min 10:1 for L1, 90th-percentile-benign for L2),
and checked against the historical validation number (AIT-ADS test F1=0.9686)
before use -- exactly as eval_phase4.py did, just without its Linux-only chdir.
"""
import json
import sys
from datetime import timezone

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from f1_phaseA_lnx import confusion, print_cm
from f1_phaseB_win import WIN_DISCRIMINATIVE, WIN_DISC_RULES, _win_systime
from shared_features import AgentHistory
from normalize_schema import extract_normalized, FEATURE_COLS_NORM, v6_to_normalized

HERE = "newCol"
MODELS = "models_v2"


def derive_normalized_thresholds():
    """Reproduce theta_xgb_norm / theta_ocsvm_norm exactly as phase3_normalized_v7,
    using the SAVED normalized models (no retraining) on the AIT-ADS test split."""
    d = np.load(f"{MODELS}/ait_split.npz", allow_pickle=True)
    Xte = v6_to_normalized(d["X_test"], list(d["feature_cols"]))
    yte = d["y_test"]
    xgb = joblib.load(f"{MODELS}/xgb_normalized.pkl")
    oc = joblib.load(f"{MODELS}/ocsvm_normalized.pkl")
    sca = joblib.load(f"{MODELS}/scaler_normalized.pkl")
    imp = joblib.load(f"{MODELS}/imputer_normalized.pkl")
    Xs = sca.transform(imp.transform(Xte))

    proba = xgb.predict_proba(Xs)[:, 1]
    best_t, best_c = 0.5, float("inf")
    for t in np.linspace(0.01, 0.99, 200):
        pred = (proba >= t).astype(int)
        cost = 10 * ((pred == 0) & (yte == 1)).sum() + ((pred == 1) & (yte == 0)).sum()
        if cost < best_c:
            best_c, best_t = cost, t
    theta_xgb_norm = float(best_t)

    scores = -oc.decision_function(Xs)
    theta_oc_norm = float(np.percentile(scores[yte == 0], 90))

    from sklearn.metrics import f1_score, recall_score
    l1 = proba >= theta_xgb_norm
    l2 = scores >= theta_oc_norm
    comb = (l1 | l2).astype(int)
    chk = dict(F1=f1_score(yte, comb), FNR=1 - recall_score(yte, comb),
               L1_FNR=1 - recall_score(yte, l1.astype(int)))
    return dict(xgb=xgb, oc=oc, sca=sca, imp=imp,
                theta_xgb=theta_xgb_norm, theta_oc=theta_oc_norm, check=chk)


def _extract_normalized_session(path):
    """Load a JSON-lines alert file, order by precise Windows systemTime, extract
    22 normalized features with per-agent AgentHistory built fresh for THIS
    session (process_depth=0, as Phase 4 / training used)."""
    raw = []
    with open(path) as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            ts = _win_systime(a)
            raw.append((idx, ts, a.get("agent", {}).get("name", "win"), a))
    order = sorted(range(len(raw)), key=lambda i: (raw[i][1] is None, raw[i][1], raw[i][0]))
    feats = [None] * len(raw)
    rid_raw = [None] * len(raw)
    hist = {}
    for i in order:
        idx, ts, agent, a = raw[i]
        h = hist.setdefault(agent, AgentHistory())
        feats[idx] = extract_normalized(a, h.compute_features(ts), process_depth=0)
        h.add(a, ts)
        rid_raw[idx] = str(a.get("rule", {}).get("id", ""))
    X = pd.DataFrame(feats, columns=FEATURE_COLS_NORM)
    X["rule_id"] = rid_raw
    return X


def main():
    print("=" * 90)
    print("Re-deriving normalized-model thresholds from ait_split.npz (phase3_normalized_v7 method)")
    print("=" * 90)
    nm = derive_normalized_thresholds()
    print(f"  theta_xgb_norm={nm['theta_xgb']:.5f}  theta_ocsvm_norm={nm['theta_oc']:.5f}")
    print(f"  reproduction check (AIT-ADS test): F1={nm['check']['F1']:.4f} (saved 0.9686)  "
          f"FNR={nm['check']['FNR']*100:.2f}% (saved 0.96%)")
    ok = abs(nm["check"]["F1"] - 0.9686) <= 0.01
    print(f"  -> normalized model reproduction: {'PASS' if ok else 'FAIL'}\n")
    if not ok:
        print("  ABORTING: threshold reproduction did not match the saved validation number; "
              "refusing to report unverified thresholds.")
        return

    # -------------------------------------------------------- attack (labeled_win.csv)
    lab = pd.read_csv(f"{HERE}/labeled_win.csv", dtype={"rule_id": str})
    Wa = _extract_normalized_session(f"{HERE}/collection_win_alerts.json")
    assert len(lab) == len(Wa), f"{len(lab)} labels vs {len(Wa)} features"
    Wa["label"] = lab["label"].values
    Wa["technique"] = lab["technique"].values

    disc = Wa[(Wa.label == "attack") & (Wa.rule_id.isin(WIN_DISC_RULES))].copy()

    # -------------------------------------------------------- benign (fresh collection)
    Wb = _extract_normalized_session(f"{HERE}/collection_benign_win_alerts.json")

    print("=" * 90)
    print("CLASS COUNTS")
    print("=" * 90)
    print(f"  discriminative Windows attack alerts: {len(disc):,}")
    print(f"    by rule: {disc.rule_id.value_counts().to_dict()}")
    print(f"  fresh Windows benign (WIN-CL1): {len(Wb):,}")
    print(f"    by rule: {Wb.rule_id.value_counts().to_dict()}")
    print("  KNOWN-rule subset: NONE (same rationale as Phase B -- no Windows rule id is "
          "in the AIT-ADS/Linux training vocabulary). NOVEL == blended.\n")

    def sc(df):
        return nm["sca"].transform(nm["imp"].transform(df[FEATURE_COLS_NORM].values.astype(float)))

    def l1(df):
        if not len(df):
            return np.zeros(0, bool)
        return nm["xgb"].predict_proba(sc(df))[:, 1] >= nm["theta_xgb"]

    def l2(df):
        if not len(df):
            return np.zeros(0, bool)
        return (-nm["oc"].decision_function(sc(df))) >= nm["theta_oc"]

    b_l1, b_l2 = l1(Wb), l2(Wb)
    d_l1, d_l2 = l1(disc), l2(disc)

    rows = []
    def stash(subset, layer, cm):
        rows.append(dict(platform="windows", pipeline="NORMALIZED_crossplatform", subset=subset, layer=layer, **cm))

    def eval_and_print(subset_name, a1, a2, b1, b2):
        y = np.array([True] * len(a1) + [False] * len(b1))
        for tag, a, b in (("L1", a1, b1), ("L2", a2, b2), ("combined", a1 | a2, b1 | b2)):
            pred = np.concatenate([a, b])
            cm = confusion(y, pred)
            print_cm(f"NORMALIZED {subset_name} / {tag}", cm)
            stash(subset_name, tag, cm)

    print("=" * 90)
    print("REAL CROSS-PLATFORM F1/FPR -- normalized 22-feature model, train-Linux/test-Windows")
    print("fresh Windows benign used for FPR (first time this is computable)")
    print("=" * 90)
    print("\n-- NOVEL == BLENDED (all discriminative) vs fresh benign --")
    eval_and_print("novel_blended", d_l1, d_l2, b_l1, b_l2)

    print("\n-- per technique --")
    for tech, rules in WIN_DISCRIMINATIVE.items():
        mask = disc.rule_id.isin(rules).values
        if not mask.any():
            print(f"  {tech}: no attack alerts"); continue
        eval_and_print(tech, d_l1[mask], d_l2[mask], b_l1, b_l2)

    pd.DataFrame(rows).to_csv(f"{HERE}/phaseB_win_normalized_results.csv", index=False)
    print(f"\nwrote {HERE}/phaseB_win_normalized_results.csv")


if __name__ == "__main__":
    main()
