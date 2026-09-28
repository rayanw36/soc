"""
f1_phaseA_lnx.py -- PHASE A: Linux F1 / FPR with the fresh matched-benign collection.
=====================================================================================
Attack side  : labeled_lnx.csv, DISCRIMINATIVE rules only (31101,31151,5710,5712,
               550,553,554,5901,5902,5903), label == "attack".
Benign side  : collection_benign_lnx_alerts.json (267 alerts, agent 003, single
               session on the same testbed) -- ALL labeled benign (y=0), no
               provenance needed.
Features     : shared_features.extract_features_v2 (26-feat v2), per-agent
               AgentHistory, built SEPARATELY for the attack collection (event-time
               ordered, exactly as eval_phase4.py) and for the benign collection
               (its own session, ordered by alert.timestamp).
Pipelines    : (a) RAW      = L1(xgb>=theta) OR L2(ocsvm>=theta), no confound fix.
               (b) PRODUCTION = combined_decision_v6.score_alert() WITH
                   rule_confound_fixes_v5.json (defer 31101/31151/5710/5501 to L2
                   on lnx-dmz).
Prints full confusion matrices + P/R/F1/FPR/FNR for L1 alone, L2 alone, combined,
for RAW and PRODUCTION, and the three-way F1 split (KNOWN / NOVEL / blended).
No files are written here -- Phase C aggregates and writes the final artifacts.
"""

import json
import os
import sys

import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

import shared_features
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, extract_features_v2, parse_timestamp
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score, score_alert
from label_lnx_timeonly import event_time as lnx_event_time

HERE = "newCol"
MODELS = "models_v2"

KNOWN_RULES = {"31101", "31151"}
NOVEL_RULES = {"5710", "5712", "550", "553", "554", "5901", "5902", "5903"}
DISCRIMINATIVE_RULES = KNOWN_RULES | NOVEL_RULES


# ---------------------------------------------------------------------------
def extract_attack_features():
    """Re-extract 26 v6 features for every raw lnx alert in event-time order
    with per-agent AgentHistory, aligned to labeled_lnx.csv by file index."""
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
    for c in ("label", "technique", "rule_id"):
        X[c] = lab[c].values
    return X


def extract_benign_features():
    """Re-extract 26 v6 features for the fresh benign collection, in its own
    session's chronological order with a fresh per-agent AgentHistory."""
    raw = []
    with open(f"{HERE}/collection_benign_lnx_alerts.json") as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            ts = parse_timestamp(a)
            raw.append((idx, ts, a.get("agent", {}).get("name", "unknown"), a))
    order = sorted(range(len(raw)), key=lambda i: (raw[i][1] is None, raw[i][1], raw[i][0]))

    feats = [None] * len(raw)
    hist = {}
    for i in order:
        idx, ts, agent, a = raw[i]
        h = hist.setdefault(agent, AgentHistory())
        feats[idx] = extract_features_v2(a, h.compute_features(ts))
        h.add(a, ts)

    X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
    X["label"] = "benign"
    X["technique"] = ""
    X["rule_id"] = [str(f[FEATURE_COLS_V2.index("rule_id_encoded")]) for f in feats]
    # use the actual textual rule id (not the float-encoded one) for readability
    rid_raw = []
    with open(f"{HERE}/collection_benign_lnx_alerts.json") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            rid_raw.append(str(a.get("rule", {}).get("id", "")))
    X["rule_id"] = rid_raw
    return X


# ---------------------------------------------------------------------------
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
    fnr = fn / (fn + tp) if (fn + tp) else float("nan")
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=prec, recall=rec, f1=f1, fpr=fpr, fnr=fnr)


def print_cm(label, cm):
    print(f"  [{label}] TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}  "
          f"P={cm['precision']*100:.2f}% R={cm['recall']*100:.2f}% F1={cm['f1']:.4f}  "
          f"FPR={cm['fpr']*100:.2f}% FNR={cm['fnr']*100:.2f}%")


# ---------------------------------------------------------------------------
def main():
    models = load_production_models()
    TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])
    print(f"theta_xgb={TXG:.5f}  theta_ocsvm={TOC:.5f}  L2={models['ocsvm_version']}")
    print(f"confound-fix rules (defer): "
          f"{[r for r, s in models['rule_fixes'].items() if s['mech']=='defer']}\n")

    Xa = extract_attack_features()
    Xb = extract_benign_features()

    disc = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(DISCRIMINATIVE_RULES))].copy()
    known = disc[disc.rule_id.isin(KNOWN_RULES)]
    novel = disc[disc.rule_id.isin(NOVEL_RULES)]

    print("=" * 90)
    print("CLASS COUNTS")
    print("=" * 90)
    print(f"  discriminative attack alerts : {len(disc):,}  "
          f"(KNOWN 31101/31151 = {len(known):,}, NOVEL = {len(novel):,})")
    print(f"    by rule: {disc.rule_id.value_counts().to_dict()}")
    print(f"  benign alerts (fresh collection, agent 003) : {len(Xb):,}")
    print(f"    by rule: {Xb.rule_id.value_counts().to_dict()}\n")

    def sc(df):
        return models["scaler"].transform(models["imputer"].transform(df[FEATURE_COLS_V2].values.astype(float)))

    def l1_raw(df):
        if not len(df):
            return np.zeros(0, bool)
        return models["xgb"].predict_proba(sc(df))[:, 1] >= TXG

    def l2_raw(df):
        if not len(df):
            return np.zeros(0, bool)
        return ocsvm_anomaly_score(models["ocsvm"], sc(df)) >= TOC

    def production_decisions(df):
        """Run score_alert() row by row; returns (l1_trust, l2_hit, combined_flagged)."""
        l1, l2, comb = [], [], []
        for _, row in df.iterrows():
            fv = row[FEATURE_COLS_V2].values.astype(float)
            r = score_alert(fv, models)
            trust_l1 = r["category"] == "known_attack"
            hit_l2 = r["ocsvm_anomaly_score"] >= TOC
            flagged = r["decision"] != "P4_suppress"
            l1.append(trust_l1); l2.append(hit_l2); comb.append(flagged)
        return np.array(l1, bool), np.array(l2, bool), np.array(comb, bool)

    # ------------------------------------------------------------------ RAW
    print("=" * 90)
    print("PIPELINE (a) RAW -- L1(xgb>=theta) OR L2(ocsvm>=theta), no confound fix")
    print("=" * 90)

    b_l1_raw, b_l2_raw = l1_raw(Xb), l2_raw(Xb)
    d_l1_raw, d_l2_raw = l1_raw(disc), l2_raw(disc)

    def eval_subset(name, attack_l1, attack_l2, bl1, bl2):
        y = np.array([True] * len(attack_l1) + [False] * len(bl1))
        for tag, a, b in (("L1", attack_l1, bl1), ("L2", attack_l2, bl2),
                          ("combined", attack_l1 | attack_l2, bl1 | bl2)):
            pred = np.concatenate([a, b])
            cm = confusion(y, pred)
            print_cm(f"{name} / {tag}", cm)
            yield tag, cm

    print("\n-- KNOWN (31101/31151) vs benign --")
    k_l1_raw = l1_raw(known); k_l2_raw = l2_raw(known)
    raw_known = dict(eval_subset("RAW KNOWN", k_l1_raw, k_l2_raw, b_l1_raw, b_l2_raw))

    print("\n-- NOVEL (5710/5712/550/553/554/5901/5902/5903) vs benign --")
    n_l1_raw = l1_raw(novel); n_l2_raw = l2_raw(novel)
    raw_novel = dict(eval_subset("RAW NOVEL", n_l1_raw, n_l2_raw, b_l1_raw, b_l2_raw))

    print("\n-- BLENDED (all discriminative) vs benign -- WARNING: base-rate inflated "
          "by web-scan (31101) volume --")
    raw_blended = dict(eval_subset("RAW BLENDED", d_l1_raw, d_l2_raw, b_l1_raw, b_l2_raw))

    print("\n-- per-rule benign FPR, RAW combined vs PRODUCTION combined "
          "(explains the RAW/PRODUCTION gap) --")
    b_comb_raw = b_l1_raw | b_l2_raw
    for rid, cnt in Xb.rule_id.value_counts().items():
        m = (Xb.rule_id == rid).values
        fpr_raw = float(b_comb_raw[m].mean()) * 100
        print(f"    rule {rid:<8} n={cnt:<4} RAW-combined-FPR={fpr_raw:6.1f}%")

    # ------------------------------------------------------------- PRODUCTION
    print("\n" + "=" * 90)
    print("PIPELINE (b) PRODUCTION -- combined_decision_v6.score_alert() WITH confound fix")
    print("=" * 90)

    b_l1_p, b_l2_p, b_comb_p = production_decisions(Xb)
    k_l1_p, k_l2_p, k_comb_p = production_decisions(known)
    n_l1_p, n_l2_p, n_comb_p = production_decisions(novel)
    d_l1_p, d_l2_p, d_comb_p = production_decisions(disc)

    print("\n-- per-rule benign FPR, PRODUCTION combined (post-fix) --")
    for rid, cnt in Xb.rule_id.value_counts().items():
        m = (Xb.rule_id == rid).values
        fpr_p = float(b_comb_p[m].mean()) * 100
        print(f"    rule {rid:<8} n={cnt:<4} PRODUCTION-combined-FPR={fpr_p:6.1f}%")

    print("\n-- per-rule attack recall (KNOWN), RAW L1 vs PRODUCTION combined "
          "(explains the recall collapse) --")
    for rid in sorted(KNOWN_RULES):
        m = (known.rule_id == rid).values
        if not m.any():
            continue
        rec_raw = float(k_l1_raw[m].mean()) * 100
        rec_p = float(k_comb_p[m].mean()) * 100
        print(f"    rule {rid:<8} n={int(m.sum()):<6} RAW-L1-recall={rec_raw:6.2f}%  "
              f"PRODUCTION-combined-recall={rec_p:6.2f}%")

    def eval_subset_prod(name, a_l1, a_l2, a_comb, b_l1, b_l2, b_comb):
        y = np.array([True] * len(a_l1) + [False] * len(b_l1))
        out = {}
        for tag, a, b in (("L1", a_l1, b_l1), ("L2", a_l2, b_l2), ("combined", a_comb, b_comb)):
            pred = np.concatenate([a, b])
            cm = confusion(y, pred)
            print_cm(f"{name} / {tag}", cm)
            out[tag] = cm
        return out

    print("\n-- KNOWN (31101/31151) vs benign --")
    prod_known = eval_subset_prod("PROD KNOWN", k_l1_p, k_l2_p, k_comb_p, b_l1_p, b_l2_p, b_comb_p)

    print("\n-- NOVEL vs benign --")
    prod_novel = eval_subset_prod("PROD NOVEL", n_l1_p, n_l2_p, n_comb_p, b_l1_p, b_l2_p, b_comb_p)

    print("\n-- BLENDED vs benign -- WARNING: base-rate inflated by web-scan (31101) volume --")
    prod_blended = eval_subset_prod("PROD BLENDED", d_l1_p, d_l2_p, d_comb_p, b_l1_p, b_l2_p, b_comb_p)

    # ------------------------------------------------------------------ save
    rows = []
    def stash(pipeline, subset, layer, cm):
        rows.append(dict(platform="linux", pipeline=pipeline, subset=subset, layer=layer, **cm))

    for tag, cm in raw_known.items():
        stash("RAW", "known", tag, cm)
    for tag, cm in raw_novel.items():
        stash("RAW", "novel", tag, cm)
    for tag, cm in raw_blended.items():
        stash("RAW", "blended", tag, cm)
    for tag, cm in prod_known.items():
        stash("PRODUCTION", "known", tag, cm)
    for tag, cm in prod_novel.items():
        stash("PRODUCTION", "novel", tag, cm)
    for tag, cm in prod_blended.items():
        stash("PRODUCTION", "blended", tag, cm)

    pd.DataFrame(rows).to_csv(f"{HERE}/phaseA_lnx_results.csv", index=False)
    print(f"\nwrote {HERE}/phaseA_lnx_results.csv (intermediate; Phase C aggregates the final file)")


if __name__ == "__main__":
    main()
