"""
eval_phase4.py -- PHASE 4: evaluate the v6 model on the genuinely-labeled data.
==============================================================================
Applies the four scoring decisions the user made after Phase 2/3:

  * KNOWN set = rules 31101/31151 ONLY. 5710/5712 (the sshd auth family) were
    ABSENT from ait_ads_seen_all.txt, so they move to NOVEL. Detecting them is
    generalization, not memorization -- that is exactly what Task 2 measures.
  * Per-technique recall is computed on DISCRIMINATIVE alerts only (the rules
    that identify the technique). Incidental alerts (the sudo+PAM triple
    5402/5501/5502 and process noise 80711/1010, emitted by every sudo-using
    technique) are reported SEPARATELY and never merged into recall.
  * FPR is NOT computable: the 90s baselines were idle, so no benign class was
    collected (19 Linux / 3 Windows "benign" alerts are attack side effects,
    not background traffic). FPR is reported as "not computable", never faked.
  * Cross-platform rests on T1110.001 and T1136.001. T1046 is dropped (dead on
    both platforms: 0 Linux detections, Windows T1046 = Security-log noise).

Scoring paths -- reuse the validated artifacts, nothing retrained:
  LINUX  (Tasks 1-2): 26-feature v6 models (xgb_model.pkl + ocsvm_nu05_v6.pkl)
         at the deployed thresholds in thresholds_production_v3.json
         (theta_xgb=0.07538, theta_ocsvm=-0.33500), via
         combined_decision_v6.load_production_models / ocsvm_anomaly_score.
         Features via shared_features.extract_features_v2 with per-agent
         AgentHistory -- the SAME construction load_lnx_detections uses.
  WINDOWS (Task 3): 22-feature normalized models (xgb_normalized.pkl +
         ocsvm_normalized.pkl) via normalize_schema.extract_normalized. Their
         thresholds are not persisted, so they are RE-DERIVED deterministically
         from ait_split.npz by the exact phase3_normalized_v7 method
         (cost-min 10:1 for L1; 90th-percentile-benign for L2) and checked
         against results_v2/normalized_validation.csv before use.

Writes: newCol/eval_results.csv, newCol/eval_summary.md
Run:    ~/soc_project/.venv/bin/python newCol/eval_phase4.py
"""

import os
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
import json
import collections
from datetime import timezone

import numpy as np
import pandas as pd
import joblib

os.chdir(REPO_ROOT)            # models are referenced relatively
sys.path.insert(0, REPO_ROOT)  # so shared_features etc. import

import shared_features
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, extract_features_v2
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score
from normalize_schema import extract_normalized, FEATURE_COLS_NORM

sys.path.insert(0, _os.path.join(REPO_ROOT, "analysis"))
from label_lnx_timeonly import event_time as lnx_event_time   # exact event-time recovery

HERE = "newCol"
MODELS = "models_v2"

# discriminative rules per technique (Phase 2), split known vs novel per user
KNOWN_RULES = {"31101", "31151"}
DISCRIMINATIVE = {
    "T1110.001": {"5710", "5712"},                     # reclassified NOVEL (auth family)
    "T1136.001": {"5901", "5902", "5903", "550", "553", "554"},
    "T1053.003": {"554", "553"},
    "T1543.002": {"554", "553"},
    "T1546.004": {"554", "553"},
    "T1098.004": {"550"},
}
INCIDENTAL = {"5402", "5501", "5502", "80711", "1010", "591", "80730", "31104", "31516"}

# Windows discriminative rules per shared technique (Phase 3). The brute force
# runs as `net use \\IPC$ /user:baduserN wrongpass` (net.exe + pwsh wrapper) and
# raises logon failures; account creation runs as `net user coluser /add`.
# Incidental on Windows: 60106 (logon SUCCESS -- a side effect) and generic
# process-spawn/system-error noise (92052/61102).
WIN_DISCRIMINATIVE = {
    "T1110.001": {"60122", "60204", "92036", "92004"},
    "T1136.001": {"92033", "92039"},
}
WIN_INCIDENTAL = {"60106", "92052", "61102"}


# ---------------------------------------------------------------------------
# Feature extraction for the new Linux collection (26-feat v6, with history)
# ---------------------------------------------------------------------------
def extract_lnx_features():
    """Re-extract the 26 v6 features for every raw lnx alert, in event-time order
    with per-agent AgentHistory, then align to labeled_lnx.csv by file index."""
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
        feats[idx] = extract_features_v2(a, h.compute_features(ts))
        h.add(a, ts)

    lab = pd.read_csv(f"{HERE}/labeled_lnx.csv", dtype={"rule_id": str})
    assert len(lab) == len(feats), f"{len(lab)} labels vs {len(feats)} features"
    X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
    for c in ("label", "technique", "label_confidence", "rule_id"):
        X[c] = lab[c].values
    return X


# ---------------------------------------------------------------------------
# Normalized features for Windows (22-feat, with history) + re-derived thresholds
# ---------------------------------------------------------------------------
def extract_win_normalized():
    raw = []
    with open(f"{HERE}/collection_win_alerts.json") as fh:
        for idx, line in enumerate(fh):
            a = json.loads(line)
            st = a["data"]["win"]["system"]["systemTime"]
            ts = pd.Timestamp(st).to_pydatetime().astimezone(timezone.utc)
            raw.append((idx, ts, a.get("agent", {}).get("name", "win"), a))
    order = sorted(range(len(raw)), key=lambda i: (raw[i][1], raw[i][0]))
    feats = [None] * len(raw)
    hist = {}
    for i in order:
        idx, ts, agent, a = raw[i]
        h = hist.setdefault(agent, AgentHistory())
        feats[idx] = extract_normalized(a, h.compute_features(ts), process_depth=0)
        h.add(a, ts)
    lab = pd.read_csv(f"{HERE}/labeled_win.csv", dtype={"rule_id": str})
    X = pd.DataFrame(feats, columns=FEATURE_COLS_NORM)
    for c in ("label", "technique", "label_confidence", "rule_id"):
        X[c] = lab[c].values
    return X


def derive_normalized_thresholds():
    """Reproduce theta_xgb_norm / theta_ocsvm_norm exactly as phase3_normalized_v7,
    using the SAVED normalized models (no retraining) on the AIT-ADS test split."""
    from normalize_schema import v6_to_normalized
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

    # sanity vs saved normalized_validation.csv (ait_ads_test_norm)
    from sklearn.metrics import f1_score, recall_score
    l1 = proba >= theta_xgb_norm
    l2 = scores >= theta_oc_norm
    comb = (l1 | l2).astype(int)
    chk = dict(F1=f1_score(yte, comb), FNR=1 - recall_score(yte, comb),
               L1_FNR=1 - recall_score(yte, l1.astype(int)))
    return dict(xgb=xgb, oc=oc, sca=sca, imp=imp,
                theta_xgb=theta_xgb_norm, theta_oc=theta_oc_norm, check=chk)


# ---------------------------------------------------------------------------
def rate(x, n):
    return (x / n * 100) if n else float("nan")


def main():
    results = []
    md = ["# Phase 4 -- v6 model evaluation on genuinely-labeled re-collection\n"]
    md.append("_All scoring reuses the validated v6 artifacts; nothing was retrained. "
              "Feature construction matches the deployed pipeline (per-agent history)._\n")

    models = load_production_models()
    TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])
    print(f"deployed thresholds: theta_xgb={TXG:.5f}  theta_ocsvm={TOC:.5f}  "
          f"L2={models['ocsvm_version']}")
    md.append(f"**Deployed thresholds** (thresholds_production_v3.json): "
              f"theta_xgb={TXG:.5f}, theta_ocsvm={TOC:.5f}. "
              f"L2 = {models['ocsvm_version']}.\n")

    X = extract_lnx_features()

    def sc(A):
        return models["scaler"].transform(models["imputer"].transform(np.asarray(A, float)))

    def l1_hit(df):
        if not len(df):
            return np.array([], bool)
        return models["xgb"].predict_proba(sc(df[FEATURE_COLS_V2].values))[:, 1] >= TXG

    def l2_hit(df):
        if not len(df):
            return np.array([], bool)
        return ocsvm_anomaly_score(models["ocsvm"], sc(df[FEATURE_COLS_V2].values)) >= TOC

    # ------------------------------------------------------------------ Task 1
    print("\n" + "=" * 84)
    print("TASK 1 -- KNOWN attacks (rules 31101/31151), Layer 1 XGBoost")
    print("=" * 84)
    known = X[(X.label == "attack") & (X.rule_id.isin(KNOWN_RULES))]
    kl1 = l1_hit(known)
    tp = int(kl1.sum()); fn = len(known) - tp
    print(f"  known-attack alerts : {len(known):,}  (31101={int((known.rule_id=='31101').sum()):,}, "
          f"31151={int((known.rule_id=='31151').sum()):,})")
    print(f"  L1 detected (TP)    : {tp:,}")
    print(f"  L1 missed  (FN)     : {fn:,}")
    print(f"  recall              : {rate(tp,len(known)):.2f}%")
    print(f"  FNR                 : {rate(fn,len(known)):.2f}%")
    print(f"  F1 / FPR            : NOT COMPUTABLE -- no benign class collected "
          f"(idle baselines)")
    md.append("## Task 1 -- Known attacks (31101/31151), Layer 1\n")
    md.append(f"| alerts | TP | FN | recall | FNR | F1 | FPR |\n|--:|--:|--:|--:|--:|--:|--:|\n"
              f"| {len(known):,} | {tp:,} | {fn:,} | {rate(tp,len(known)):.2f}% | "
              f"{rate(fn,len(known)):.2f}% | n/a | n/a |\n")
    md.append("_F1 and FPR require a benign class; none was collected (idle baselines). "
              "FNR = 1 - recall is computable and reported._\n")
    results.append(dict(task="1_known", scope="31101/31151", set="L1", n=len(known),
                        tp=tp, fn=fn, recall=rate(tp, len(known))/100,
                        fnr=rate(fn, len(known))/100, f1="not_computable",
                        fpr="not_computable"))

    # ------------------------------------------------------------------ Task 2
    print("\n" + "=" * 84)
    print("TASK 2 -- NOVEL attacks per technique: L1 (generalization) vs L2 (anomaly)")
    print("=" * 84)
    print("  discriminative alerts only; incidental (sudo/PAM/proc-noise) reported separately\n")
    print(f"  {'technique':<12}{'n':>4}{'L1 rec':>9}{'L2 rec':>9}{'either':>9}   interpretation")
    md.append("## Task 2 -- Novel attacks per technique (discriminative alerts only)\n")
    md.append("Every rule here is absent from training, so L1 recall = generalization "
              "(not memorization); L2 recall = genuine anomaly detection.\n")
    md.append("| technique | n | L1 recall | L2 recall | either | note |\n"
              "|---|--:|--:|--:|--:|---|\n")
    for tech in sorted(DISCRIMINATIVE):
        disc = X[(X.label == "attack") & (X.technique == tech) &
                 (X.rule_id.isin(DISCRIMINATIVE[tech]))]
        if not len(disc):
            continue
        a1, a2 = l1_hit(disc), l2_hit(disc)
        r1, r2 = rate(a1.sum(), len(disc)), rate(a2.sum(), len(disc))
        either = rate((a1 | a2).sum(), len(disc))
        # Every rule here is ABSENT from ait_ads_seen_all.txt, so L1 firing is
        # generalization from correlated features -- never memorization.
        note = ("weakly detected" if max(r1, r2) < 50 else
                "L1 generalizes (rule unseen)" if r1 >= r2 else
                "L2 anomaly-driven")
        print(f"  {tech:<12}{len(disc):>4}{r1:>8.1f}%{r2:>8.1f}%{either:>8.1f}%   {note}")
        md.append(f"| {tech} | {len(disc)} | {r1:.1f}% | {r2:.1f}% | {either:.1f}% | {note} |\n")
        results.append(dict(task="2_novel", scope=tech, set="discriminative",
                            n=len(disc), l1_recall=r1/100, l2_recall=r2/100,
                            either_recall=either/100))
    # incidental, reported separately
    inc = X[(X.label == "attack") & (X.rule_id.isin(INCIDENTAL))]
    ia1, ia2 = l1_hit(inc), l2_hit(inc)
    print(f"\n  incidental (separate): n={len(inc)}  L1={rate(ia1.sum(),len(inc)):.1f}%  "
          f"L2={rate(ia2.sum(),len(inc)):.1f}%  -- NOT merged into recall")
    md.append(f"\n_Incidental alerts (sudo/PAM/process-noise), reported separately, "
              f"never merged: n={len(inc)}, L1={rate(ia1.sum(),len(inc)):.1f}%, "
              f"L2={rate(ia2.sum(),len(inc)):.1f}%._\n")
    results.append(dict(task="2_incidental", scope="5402/5501/5502/80711/1010",
                        set="incidental", n=len(inc),
                        l1_recall=rate(ia1.sum(), len(inc))/100,
                        l2_recall=rate(ia2.sum(), len(inc))/100))

    # ------------------------------------------------------------------ Task c
    print("\n" + "=" * 84)
    print("TASK 1c/2c -- BENIGN / FPR")
    print("=" * 84)
    nb = int((X.label == "benign").sum())
    print(f"  benign-labeled alerts: {nb}  -- all are attack side effects, not background")
    print(f"  FPR: NOT COMPUTABLE -- no benign class collected (idle 90s baselines)")
    md.append("## Task 1c/2c -- FPR\n**Not computable — no benign class collected.** "
              f"The {nb} 'benign' Linux alerts are attack-script side effects (PAM/sudo "
              "during teardown), not background traffic; the 90s baselines were idle.\n")
    results.append(dict(task="c_fpr", scope="linux", set="benign", n=nb,
                        fpr="not_computable"))

    # ------------------------------------------------------------------ Task 3
    print("\n" + "=" * 84)
    print("TASK 3 -- CROSS-PLATFORM (Windows), normalized model, shared techniques")
    print("=" * 84)
    nm = derive_normalized_thresholds()
    print(f"  re-derived thresholds: theta_xgb_norm={nm['theta_xgb']:.5f}  "
          f"theta_ocsvm_norm={nm['theta_oc']:.5f}")
    print(f"  reproduction check (AIT-ADS test): F1={nm['check']['F1']:.4f} "
          f"(saved 0.9686)  FNR={nm['check']['FNR']*100:.2f}% (saved 0.96%)")
    ok = abs(nm["check"]["F1"] - 0.9686) <= 0.01
    print(f"  -> normalized model reproduction: {'PASS' if ok else 'FAIL'}")

    W = extract_win_normalized()

    def wsc(A):
        return nm["sca"].transform(nm["imp"].transform(np.asarray(A, float)))

    def w_l1(df):
        return nm["xgb"].predict_proba(wsc(df[FEATURE_COLS_NORM].values))[:, 1] >= nm["theta_xgb"]

    def w_l2(df):
        return (-nm["oc"].decision_function(wsc(df[FEATURE_COLS_NORM].values))) >= nm["theta_oc"]

    md.append("## Task 3 -- Cross-platform (Windows), first genuinely-labeled result\n")
    md.append(f"Normalized 22-feature model; thresholds re-derived from ait_split.npz "
              f"(theta_xgb_norm={nm['theta_xgb']:.4f}, theta_ocsvm_norm={nm['theta_oc']:.4f}; "
              f"AIT-ADS reproduction F1={nm['check']['F1']:.3f}, {'PASS' if ok else 'FAIL'}). "
              f"process_depth=0 (as in training), though a real Sysmon tree exists.\n")
    md.append("Discriminative alerts only (same rule as Linux); incidental reported separately.\n\n")
    md.append("| technique | n | L1 recall | L2 recall | either |\n|---|--:|--:|--:|--:|\n")
    print(f"\n  discriminative alerts only")
    print(f"  {'technique':<12}{'n':>4}{'L1 rec':>9}{'L2 rec':>9}{'either':>9}")
    for tech in ["T1110.001", "T1136.001"]:
        disc = W[(W.label == "attack") & (W.technique == tech) &
                 (W.rule_id.isin(WIN_DISCRIMINATIVE[tech]))]
        if not len(disc):
            print(f"  {tech}: no attack alerts"); continue
        a1, a2 = w_l1(disc), w_l2(disc)
        r1, r2 = rate(a1.sum(), len(disc)), rate(a2.sum(), len(disc))
        either = rate((a1 | a2).sum(), len(disc))
        print(f"  {tech:<12}{len(disc):>4}{r1:>8.1f}%{r2:>8.1f}%{either:>8.1f}%")
        md.append(f"| {tech} | {len(disc)} | {r1:.1f}% | {r2:.1f}% | {either:.1f}% |\n")
        results.append(dict(task="3_crossplatform", scope=tech, set="windows_normalized",
                            n=len(disc), l1_recall=r1/100, l2_recall=r2/100,
                            either_recall=either/100))
    winc = W[(W.label == "attack") & (W.rule_id.isin(WIN_INCIDENTAL))]
    if len(winc):
        wia1, wia2 = w_l1(winc), w_l2(winc)
        print(f"  incidental (separate): n={len(winc)}  L1={rate(wia1.sum(),len(winc)):.1f}%  "
              f"L2={rate(wia2.sum(),len(winc)):.1f}%  -- NOT merged")
        md.append(f"\n_Windows incidental (logon-success/process-noise), separate: "
                  f"n={len(winc)}, L1={rate(wia1.sum(),len(winc)):.1f}%, "
                  f"L2={rate(wia2.sum(),len(winc)):.1f}%._\n")
    nwb = int((W.label == "benign").sum())
    print(f"\n  Windows FPR: NOT COMPUTABLE -- benign class = {nwb} alerts (idle baselines)")
    md.append(f"\n_Windows FPR not computable: benign class = {nwb} alerts._\n")
    results.append(dict(task="3_fpr", scope="windows", set="benign", n=nwb,
                        fpr="not_computable"))

    # ------------------------------------------------------------------ write
    pd.DataFrame(results).to_csv(f"{HERE}/eval_results.csv", index=False)
    with open(f"{HERE}/eval_summary.md", "w") as f:
        f.write("".join(md))
    print(f"\nwrote {HERE}/eval_results.csv and {HERE}/eval_summary.md")


if __name__ == "__main__":
    main()
