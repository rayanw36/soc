"""
combined_decision_v6.py
=======================
Single source of truth for the v6 two-layer alert-triage decision.

v6 == v5 decision logic, with ONE change: Layer 2 is the RETRAINED OC-SVM
(ocsvm_nu05_v6.pkl) whose benign baseline up-weights rule-31151/5710 traffic.
That is the only difference -- the defer-to-L2 confound config, thresholds,
XGBoost L1, scaler and imputer are all byte-identical to v5.

    Layer 1 (known attacks) : cost-sensitive XGBoost              (R1/R2, unchanged)
    Layer 2 (zero-day)      : One-Class SVM nu=0.05, v6-retrained  (R3)
    FIX (v5, retained)      : per-rule host-scoped confound defer  (31101/31151/5710/5501)

Why v6: v5's defer-to-L2 only suppressed a confounded benign alert if L2 was
ALSO clean on it. It was for 31101/5501 but NOT 31151 (L2 FPR 74%) or 5710 (60%),
because the OC-SVM itself flagged that benign traffic -- leaving combined FPR at
12.6% (> R4's 10%). Retraining L2 with 31151/5710 up-weighted fixes the L2 side.

Measured effect (validate_v6.py, held-out benign + 43 novel, leakage-safe):
    combined FPR        12.6% -> 7.1%   => R4 (<=10%) NOW MET
    per-rule 31151 FPR  74%   -> 2%
    per-rule 5710  FPR  60%   -> 25%    (partial: 5710 benign genuinely overlaps
                                         the anomalous region -- the new residual)
    R3 TRUE L2 recall   72.1% -> 74.4%  (IMPROVED, no per-technique regression)
    R1 F1 0.9945, R2 FNR 1.08%          (unchanged -- L1 untouched)
    T1548.001 TRUE L2 recall 0% -> 0%   (separate feature gap, not addressed here)

Honest caveat: rule 5501's benign FPR ticks 15.6% -> 18.8% as a side-effect of
retraining L2 (5501 was not up-weighted); it is a small rule and combined FPR
still drops well under target. T1548.001 SUID discovery remains undetected by L2.

score_alert() / load_production_models() keep the v3/v4/v5 signatures (drop-in).

Run directly for a self-test (v5 vs v6):
    ~/soc_project/.venv/bin/python combined_decision_v6.py
"""

import os

import joblib

# Reuse v5 wholesale; the ONLY override is which OC-SVM artifact L2 loads.
from combined_decision_v5 import (
    load_production_models as _load_v5_models,
    score_alert,                       # unchanged: it reads models["ocsvm"]
    _load_fix_config,                  # noqa: F401  (re-exported for parity)
)
from combined_decision_v3 import ocsvm_anomaly_score, load_eval_split  # noqa: F401

OCSVM_V6 = "ocsvm_nu05_v6.pkl"


def load_production_models(models_dir="models_v2"):
    """Same artifacts as v5, but Layer 2 is the v6-retrained OC-SVM.

    Falls back to the v5 OC-SVM if the v6 artifact is missing, so the module
    never silently loses its zero-day layer."""
    art = _load_v5_models(models_dir)
    v6_path = os.path.join(models_dir, OCSVM_V6)
    if os.path.exists(v6_path):
        art["ocsvm"] = joblib.load(v6_path)
        art["ocsvm_version"] = "v6_retrained_31151_5710"
    else:
        art["ocsvm_version"] = "v5_fallback"
    return art


# ---------------------------------------------------------------------------
# Self-test: v5 L2 vs v6 L2 under identical (v5) decision logic
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import numpy as np
    import pandas as pd

    from shared_constants_v2 import FEATURE_COLS_V2

    RID = FEATURE_COLS_V2.index("rule_id_encoded")
    CRIT = FEATURE_COLS_V2.index("agent_criticality")
    P4, P3, P1 = 0, 1, 2

    print("=" * 80)
    print("combined_decision_v6 SELF-TEST  --  v5 L2 vs v6 (retrained) L2")
    print("=" * 80)
    models = load_production_models()
    print(f"L2 version: {models['ocsvm_version']}   defer rules: "
          f"{[r for r, s in models['rule_fixes'].items() if s['mech']=='defer']}")

    oc_v5 = joblib.load("models_v2/ocsvm_nu05.pkl")
    oc_v6 = models["ocsvm"]
    TXG, TOC = models["theta_xgb"], models["theta_ocsvm"]
    DEFER = {r for r, s in models["rule_fixes"].items() if s["mech"] == "defer"}

    test_benign, novel = load_eval_split()

    def sc(X):
        return models["scaler"].transform(models["imputer"].transform(np.asarray(X, float)))

    Xbn, Xnv = sc(test_benign), sc(novel[FEATURE_COLS_V2].values)
    xg_bn = models["xgb"].predict_proba(Xbn)[:, 1]
    rid_bn = np.round(test_benign[:, RID]).astype(int)
    tech = novel.technique.values

    def combined(ocm):
        d = np.full(len(Xbn), P4)
        d[ocsvm_anomaly_score(ocm, Xbn) >= TOC] = P3
        on_lnx = test_benign[:, CRIT] == 1.0
        supp = np.isin(rid_bn, list(DEFER)) & on_lnx
        d[(xg_bn >= TXG) & (~supp)] = P1
        return d

    d5, d6 = combined(oc_v5), combined(oc_v6)
    fpr5, fpr6 = float((d5 != P4).mean()), float((d6 != P4).mean())
    r3_5 = float((ocsvm_anomaly_score(oc_v5, Xnv) >= TOC).mean())
    r3_6 = float((ocsvm_anomaly_score(oc_v6, Xnv) >= TOC).mean())

    print(f"\n  {'Metric':30s} | {'v5':>8s} | {'v6':>8s} | Status")
    print("  " + "-" * 64)
    r4 = "MET (<=10%)" if fpr6 <= 0.10 else "NOT MET (>10%)"
    print(f"  {'Combined FPR (lnx benign)':30s} | {fpr5*100:7.1f}% | {fpr6*100:7.1f}% | R4 {r4}")
    for r in (31101, 31151, 5710, 5501):
        a = float((d5[rid_bn == r] != P4).mean()); b = float((d6[rid_bn == r] != P4).mean())
        print(f"  {'  per-rule FPR '+str(r):30s} | {a*100:7.0f}% | {b*100:7.0f}% | "
              f"{'IMPROVED' if b < a-1e-9 else 'REGRESSED' if b > a+1e-9 else 'SAME'}")
    print(f"  {'R3 TRUE L2 recall (aggregate)':30s} | {r3_5*100:7.1f}% | {r3_6*100:7.1f}% | "
          f"{'IMPROVED' if r3_6 > r3_5+1e-9 else 'MAINTAINED' if abs(r3_6-r3_5)<1e-9 else 'REGRESSED'}")
    for t in sorted(set(tech)):
        m = tech == t
        a = float((ocsvm_anomaly_score(oc_v5, Xnv)[m] >= TOC).mean())
        b = float((ocsvm_anomaly_score(oc_v6, Xnv)[m] >= TOC).mean())
        flag = "  <-- REGRESSED" if (b < a - 1e-9 and m.sum() >= 3) else ""
        print(f"  {'  R3 '+t+f' (n={int(m.sum())})':30s} | {a*100:7.1f}% | {b*100:7.1f}% |{flag}")

    print(f"\n  R4 status: combined FPR {fpr6*100:.1f}%  ->  "
          f"{'MET (<=10%)' if fpr6 <= 0.10 else 'NOT MET (still > 10%)'}")
    print("  Residual now led by rule 5710 (~25%): its benign traffic overlaps the")
    print("  anomalous region, so up-weighting only partially normalises it. T1548.001")
    print("  TRUE L2 recall stays 0% (separate feature gap). See v6_deployment_checklist.md.")
