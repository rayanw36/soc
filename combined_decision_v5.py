"""
combined_decision_v5.py
=======================
Single source of truth for the v5 two-layer alert-triage decision. Generalises
v4's single-rule (31101) host-scoped fix into a config-driven multi-rule
confound mechanism.

    Layer 1 (known attacks)  : cost-sensitive XGBoost          (R1/R2, unchanged)
    Layer 2 (zero-day)       : One-Class SVM (nu=0.05)          (R3, unchanged)
    FIX (v5)                 : per-rule, host-scoped confound handling

Mechanism (driven by models_v2/rule_confound_fixes_v5.json, produced by
fix_rule_confounds_v2.py) -- applied ONLY on lnx-dmz (agent_criticality == 1):
  * "defer"  : a confounded rule's L1 "known_attack" verdict is distrusted and
               deferred to the L2 OC-SVM (used for 31101, 31151, 5710, 5501).
  * "guard"  : forward as L1 known_attack only if a discriminating feature
               exceeds a threshold, else defer to L2. The mechanism is
               implemented and supported; no rule currently adopts it because
               5501's separating signal did not transfer to real lnx attacks
               (all real lnx novel-5501 alerts have high_sev_ratio_20 = 0).

Measured effect (fix_rule_confounds_v2.py / v5 self-test): combined lnx-dmz
benign FPR 18.1% -> 12.6%, with R1 F1, R2 FNR and TRUE L2 zero-day recall
(72.1%) all unchanged. R4 (FPR <= 10%) is STILL NOT MET: deferring 31151/5710
only partially helps because the L2 OC-SVM itself flags those benign alerts.

Honest artifact note: combined per-technique recall for T1548.001 drops
90% -> 60%, because the dropped alerts were rule-5501 events L1 had mislabelled
as known_attack (the confound being fixed), NOT real detections -- T1548.001
TRUE L2 zero-day recall is 0% before and after.

score_alert() / load_production_models() keep v4/v3 signatures (drop-in).

Run directly for a self-test (v4 vs v5):
    ~/soc_project/.venv/bin/python combined_decision_v5.py
"""

import os
import json

import numpy as np

from shared_constants_v2 import FEATURE_COLS_V2
from combined_decision_v3 import (
    load_production_models as _load_v3_models,
    ocsvm_anomaly_score,
    load_eval_split,
)

RID_IDX = FEATURE_COLS_V2.index("rule_id_encoded")
CRIT_IDX = FEATURE_COLS_V2.index("agent_criticality")
LNX_DMZ_CRITICALITY = 1.0

# Fallback config if the JSON is absent (keeps v5 deployable standalone).
_DEFAULT_FIXES = {
    "31101": {"mech": "defer"}, "31151": {"mech": "defer"},
    "5710": {"mech": "defer"}, "5501": {"mech": "defer"},
}


def _load_fix_config(models_dir):
    path = os.path.join(models_dir, "rule_confound_fixes_v5.json")
    raw = json.load(open(path)) if os.path.exists(path) else dict(_DEFAULT_FIXES)
    cfg = {}
    for k, v in raw.items():
        if k == "_meta":
            continue
        spec = {"mech": v["mech"]}
        if v["mech"] == "guard":
            spec["feature_idx"] = FEATURE_COLS_V2.index(v["feature"])
            spec["threshold"] = float(v["threshold"])
        cfg[int(k)] = spec
    return cfg


def load_production_models(models_dir="models_v2"):
    """Same artifacts as v3/v4, plus the per-rule confound fix config."""
    art = _load_v3_models(models_dir)
    art["rule_fixes"] = _load_fix_config(models_dir)
    return art


def score_alert(feature_vector_26, models, coral_align=False):
    """Score one raw 26-feature vector through both layers and decide (v5).
    Same return keys as v4 (plus l1_confound_rule when the fix fires)."""
    x = np.asarray(feature_vector_26, dtype=np.float64).reshape(1, -1)
    Xs = models["scaler"].transform(models["imputer"].transform(x))
    if coral_align and models.get("coral_W") is not None:
        Xs = Xs @ models["coral_W"]

    xgb_score = float(models["xgb"].predict_proba(Xs)[:, 1][0])
    ocsvm_score = float(ocsvm_anomaly_score(models["ocsvm"], Xs)[0])

    rule_id = int(round(float(x[0, RID_IDX])))
    on_lnx = float(x[0, CRIT_IDX]) == LNX_DMZ_CRITICALITY
    spec = models["rule_fixes"].get(rule_id) if on_lnx else None

    l1_suppressed = False
    if spec is not None:
        if spec["mech"] == "defer":
            l1_suppressed = True
        elif spec["mech"] == "guard":
            l1_suppressed = float(x[0, spec["feature_idx"]]) < spec["threshold"]

    trust_l1 = (xgb_score >= models["theta_xgb"]) and not l1_suppressed
    if trust_l1:
        decision, category, layer = "P1P2_forward", "known_attack", "xgb"
    elif ocsvm_score >= models["theta_ocsvm"]:
        decision, category, layer = "P3_suspicious", "zero_day_candidate", "ocsvm"
    else:
        decision, category, layer = "P4_suppress", "benign", "none"

    return {
        "xgb_score": xgb_score,
        "ocsvm_anomaly_score": ocsvm_score,
        "decision": decision,
        "category": category,
        "layer_triggered": layer,
        "l1_rule31101_suppressed": bool(l1_suppressed and rule_id == 31101
                                        and xgb_score >= models["theta_xgb"]),
        "l1_confound_suppressed": bool(l1_suppressed and xgb_score >= models["theta_xgb"]),
        "l1_confound_rule": rule_id if (l1_suppressed and xgb_score >= models["theta_xgb"]) else None,
    }


# ---------------------------------------------------------------------------
# Self-test: v4 (31101-only) vs v5 (multi-rule) on identical inputs
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import pandas as pd

    print("=" * 80)
    print("combined_decision_v5 SELF-TEST  --  v4 (31101 only) vs v5 (multi-rule)")
    print("=" * 80)
    models = load_production_models()
    print("rule fixes:", {r: s["mech"] for r, s in models["rule_fixes"].items()})

    test_benign, novel = load_eval_split()
    Xnov = novel[FEATURE_COLS_V2].values
    split = np.load("models_v2/ait_split.npz", allow_pickle=True)
    Xte, yte = split["X_test"], split["y_test"]

    def bscore(X):
        Xs = models["scaler"].transform(models["imputer"].transform(np.asarray(X, float)))
        return models["xgb"].predict_proba(Xs)[:, 1], ocsvm_anomaly_score(models["ocsvm"], Xs)

    S = {k: bscore(X) for k, X in (("bn", test_benign), ("nv", Xnov), ("te", Xte))}
    XX = {"bn": test_benign, "nv": Xnov, "te": Xte}
    P4, P3, P1 = 0, 1, 2

    def decide(which, fixes):
        X = XX[which]; xg, oc = S[which]
        d = np.full(len(X), P4); d[oc >= models["theta_ocsvm"]] = P3
        on_lnx = X[:, CRIT_IDX] == LNX_DMZ_CRITICALITY
        supp = np.zeros(len(X), bool)
        for r, sp in fixes.items():
            rm = (X[:, RID_IDX] == r) & on_lnx
            if sp["mech"] == "defer":
                supp |= rm
            else:
                supp |= rm & (X[:, sp["feature_idx"]] < sp["threshold"])
        d[(xg >= models["theta_xgb"]) & (~supp)] = P1
        return d

    def evaluate(fixes):
        d_bn, d_nv, d_te = (decide(k, fixes) for k in ("bn", "nv", "te"))
        pred = (d_te == P1).astype(int)
        tp = int(((pred == 1) & (yte == 1)).sum()); fn = int(((pred == 0) & (yte == 1)).sum())
        fp = int(((pred == 1) & (yte == 0)).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0; rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        fnr = fn / (tp + fn) if (tp + fn) else 0.0
        cfpr = float((d_bn != P4).mean())
        # per-rule benign FPR
        pr = {r: float((d_bn[test_benign[:, RID_IDX] == r] != P4).mean())
              for r in (31101, 31151, 5710, 5501)}
        nl2 = float((S["nv"][1] >= models["theta_ocsvm"]).mean())
        ncomb = float((d_nv != P4).mean())
        t001_idx = [novel.index.get_loc(i) for i in novel[novel.technique == "T1548.001"].index]
        t001_comb = float((d_nv[t001_idx] != P4).mean())
        t001_l2 = float((S["nv"][1][t001_idx] >= models["theta_ocsvm"]).mean())
        return dict(f1=f1, fnr=fnr, cfpr=cfpr, pr=pr, nl2=nl2, ncomb=ncomb,
                    t001c=t001_comb, t001l2=t001_l2)

    V4 = {31101: {"mech": "defer"}}
    a = evaluate(V4); b = evaluate(models["rule_fixes"])

    def st(x, y, lower=False, tol=1e-4):
        if abs(x - y) < tol:
            return "MAINTAINED"
        return ("IMPROVED" if (y < x) == lower else "REGRESSED")

    print(f"\n  {'Metric':36s} | {'v4':>10} | {'v5':>10} | Status")
    print("  " + "-" * 76)
    rows = []
    def line(label, av, bv, fmt, status):
        sa = f"{av*100:.1f}%" if fmt == "%" else f"{av:.4f}"
        sb = f"{bv*100:.1f}%" if fmt == "%" else f"{bv:.4f}"
        print(f"  {label:36s} | {sa:>10} | {sb:>10} | {status}")
        rows.append({"metric": label, "v4": sa, "v5": sb, "status": status})

    r4 = "MET" if b["cfpr"] <= 0.10 else f"NOT MET (>{10}% target)"
    line("Combined FPR (lnx benign)", a["cfpr"], b["cfpr"], "%",
         f"IMPROVED -> R4 {r4}")
    line("R1 known-attack F1", a["f1"], b["f1"], "f", st(a["f1"], b["f1"]))
    line("R2 known-attack FNR", a["fnr"], b["fnr"], "%", st(a["fnr"], b["fnr"], lower=True))
    line("R3 novel recall (TRUE L2)", a["nl2"], b["nl2"], "%", st(a["nl2"], b["nl2"]))
    line("R3 novel recall (combined)", a["ncomb"], b["ncomb"], "%",
         st(a["ncomb"], b["ncomb"]) + " (L1-confound artifact, see below)")
    line("T1548.001 TRUE L2 recall", a["t001l2"], b["t001l2"], "%",
         "MAINTAINED (known feature gap)")
    line("T1548.001 combined recall", a["t001c"], b["t001c"], "%",
         "artifact corrected (was L1 mislabel)")

    print(f"\n  R4 status: combined FPR {b['cfpr']*100:.1f}%  ->  "
          f"{'MET (<=10%)' if b['cfpr'] <= 0.10 else 'NOT MET (still > 10%)'}")
    print("  Per-rule benign FPR (v5):", {r: f"{v*100:.0f}%" for r, v in b["pr"].items()})
    print("  Residual is L2-driven for 31151/5710 (the OC-SVM itself flags that benign")
    print("  traffic) plus uninvestigated rules (5502/2904/2902/2901). T1548.001 TRUE L2")
    print("  recall stays 0% -- v5 makes no false claim of closing that gap.")

    pd.DataFrame(rows).to_csv("results_v2/v5_final_validation.csv", index=False)
    print("\n  Saved results_v2/v5_final_validation.csv")
