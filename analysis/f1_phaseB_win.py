"""
f1_phaseB_win.py -- PHASE B: Windows F1 / FPR with the fresh matched-benign collection.
========================================================================================
Attack side  : labeled_win.csv, WIN-DISCRIMINATIVE rules only (both HIGH and LOW
               confidence), label == "attack":
                 T1110.001: 60122, 60204, 92036, 92004
                 T1136.001: 92033, 92039
Benign side  : collection_benign_win_alerts.json (agent WIN-CL1, single session on
               the same testbed) -- ALL labeled benign (y=0), no provenance needed.
Features     : shared_features.extract_features_v2 (26-feat v2) -- the SAME model
               pipeline given for this task (xgb_model.pkl / ocsvm_nu05_v6.pkl /
               thresholds_production_v3.json / rule_confound_fixes_v5.json), NOT
               the separate normalize_schema 22-feat model Phase 4 used for
               Task 3 (that model/thresholds were not supplied for this task).
               "Consistent with Phase 4" is applied to timestamp source only: per-
               agent AgentHistory ordered by the precise Sysmon systemTime field
               (data.win.system.systemTime), exactly as extract_win_normalized did.
KNOWN/NOVEL  : ait_ads_seen_rules.txt (the AIT-ADS training rule vocabulary) contains
               ONLY Linux rule ids -- no Windows rule (60xxx/92xxx) was ever seen in
               training. So for Windows there is NO known-rule subset: every
               discriminative Windows rule is NOVEL by the same seen/unseen
               criterion Phase A used. KNOWN-only F1 is therefore not computable
               (n=0) and reported as such, never fabricated. NOVEL == blended here
               (no base-rate inflation risk the way Linux's 31101 volume creates).
               A per-technique breakdown (T1110.001 vs T1136.001) is also reported
               for extra granularity, matching Phase 4's Task 3 structure.
Because Windows agent criticality ("WIN-CL1") does not substring-match any key in
AGENT_CRITICALITY_MAP (win-dc/win-cli/lnx-dmz), extract_features_v2's
agent_criticality feature evaluates to 0.0 for every Windows alert (both attack and
benign) -- this is a genuine, pre-existing property of shared_features.py, applied
identically to attack and benign sides here, so it cannot bias one class against the
other, but it is flagged because it also means the confound-fix's on_lnx gate
(agent_criticality == 1.0) can never fire on Windows -- RAW and PRODUCTION should be
identical on Windows for that reason. That equality is itself checked below as a
sanity assertion.
"""
import json
import sys
from datetime import timezone

import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from f1_phaseA_lnx import confusion, print_cm  # reuse identical metric helpers
from shared_constants_v2 import FEATURE_COLS_V2
import shared_features
from shared_features import AgentHistory, extract_features_v2, parse_timestamp
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score, score_alert

HERE = "newCol"

WIN_DISCRIMINATIVE = {
    "T1110.001": {"60122", "60204", "92036", "92004"},
    "T1136.001": {"92033", "92039"},
}
WIN_DISC_RULES = set().union(*WIN_DISCRIMINATIVE.values())


def _win_systime(alert):
    try:
        st = alert["data"]["win"]["system"]["systemTime"]
        return pd.Timestamp(st).to_pydatetime().astimezone(timezone.utc)
    except Exception:
        return parse_timestamp(alert)


def extract_win_attack_features():
    raw = []
    with open(f"{HERE}/collection_win_alerts.json") as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            ts = _win_systime(a)
            raw.append((idx, ts, a.get("agent", {}).get("name", "win"), a))
    order = sorted(range(len(raw)), key=lambda i: (raw[i][1] is None, raw[i][1], raw[i][0]))
    feats = [None] * len(raw)
    hist = {}
    for i in order:
        idx, ts, agent, a = raw[i]
        h = hist.setdefault(agent, AgentHistory())
        feats[idx] = extract_features_v2(a, h.compute_features(ts))
        h.add(a, ts)

    lab = pd.read_csv(f"{HERE}/labeled_win.csv", dtype={"rule_id": str})
    assert len(lab) == len(feats), f"{len(lab)} labels vs {len(feats)} features"
    X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
    for c in ("label", "technique", "rule_id", "label_confidence"):
        X[c] = lab[c].values
    return X


def extract_win_benign_features():
    raw = []
    with open(f"{HERE}/collection_benign_win_alerts.json") as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            ts = _win_systime(a)
            raw.append((idx, ts, a.get("agent", {}).get("name", "win"), a))
    order = sorted(range(len(raw)), key=lambda i: (raw[i][1] is None, raw[i][1], raw[i][0]))
    feats = [None] * len(raw)
    hist = {}
    rid_raw = [None] * len(raw)
    for i in order:
        idx, ts, agent, a = raw[i]
        h = hist.setdefault(agent, AgentHistory())
        feats[idx] = extract_features_v2(a, h.compute_features(ts))
        h.add(a, ts)
        rid_raw[idx] = str(a.get("rule", {}).get("id", ""))

    X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
    X["label"] = "benign"
    X["technique"] = ""
    X["rule_id"] = rid_raw
    return X


def main():
    models = load_production_models()
    TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])
    print(f"theta_xgb={TXG:.5f}  theta_ocsvm={TOC:.5f}  L2={models['ocsvm_version']}\n")

    Xa = extract_win_attack_features()
    Xb = extract_win_benign_features()

    crit_a = Xa["agent_criticality"].unique()
    crit_b = Xb["agent_criticality"].unique()
    print(f"agent_criticality observed -- attack: {crit_a}  benign: {crit_b}  "
          f"(0.0 expected: 'WIN-CL1' matches no AGENT_CRITICALITY_MAP key)\n")

    disc = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(WIN_DISC_RULES))].copy()

    print("=" * 90)
    print("CLASS COUNTS")
    print("=" * 90)
    print(f"  discriminative attack alerts : {len(disc):,}")
    print(f"    by rule: {disc.rule_id.value_counts().to_dict()}")
    print(f"    by confidence: {disc.label_confidence.value_counts().to_dict()}")
    print(f"  benign alerts (fresh collection, WIN-CL1) : {len(Xb):,}")
    print(f"    by rule: {Xb.rule_id.value_counts().to_dict()}")
    print(f"  KNOWN-rule subset: NONE -- no Windows rule id (60xxx/92xxx) appears in "
          f"ait_ads_seen_rules.txt (Linux-only training vocabulary). All discriminative "
          f"Windows rules are NOVEL by the same seen/unseen criterion Phase A used.\n")

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
        l1, l2, comb = [], [], []
        for _, row in df.iterrows():
            fv = row[FEATURE_COLS_V2].values.astype(float)
            r = score_alert(fv, models)
            l1.append(r["category"] == "known_attack")
            l2.append(r["ocsvm_anomaly_score"] >= TOC)
            comb.append(r["decision"] != "P4_suppress")
        return np.array(l1, bool), np.array(l2, bool), np.array(comb, bool)

    b_l1_raw, b_l2_raw = l1_raw(Xb), l2_raw(Xb)
    d_l1_raw, d_l2_raw = l1_raw(disc), l2_raw(disc)
    b_l1_p, b_l2_p, b_comb_p = production_decisions(Xb)
    d_l1_p, d_l2_p, d_comb_p = production_decisions(disc)

    # sanity: confound-fix must be a no-op on Windows (agent_criticality != 1.0
    # and none of the WIN rule ids are in rule_confound_fixes_v5.json anyway)
    raw_comb = d_l1_raw | d_l2_raw
    assert np.array_equal(raw_comb, d_comb_p), "confound-fix unexpectedly changed Windows decisions"
    assert np.array_equal(b_l1_raw | b_l2_raw, b_comb_p), "confound-fix unexpectedly changed Windows benign decisions"
    print("sanity check PASSED: RAW combined == PRODUCTION combined on Windows "
          "(confound-fix never fires here, as expected -- WIN rule ids are absent "
          "from rule_confound_fixes_v5.json and agent_criticality != 1.0)\n")

    rows = []

    def stash(pipeline, subset, layer, cm):
        rows.append(dict(platform="windows", pipeline=pipeline, subset=subset, layer=layer, **cm))

    def eval_and_print(pipeline_name, subset_name, a_l1, a_l2, a_comb, b_l1, b_l2, b_comb):
        y = np.array([True] * len(a_l1) + [False] * len(b_l1))
        for tag, a, b in (("L1", a_l1, b_l1), ("L2", a_l2, b_l2), ("combined", a_comb, b_comb)):
            pred = np.concatenate([a, b])
            cm = confusion(y, pred)
            print_cm(f"{pipeline_name} {subset_name} / {tag}", cm)
            stash(pipeline_name, subset_name, tag, cm)

    print("=" * 90)
    print("PIPELINE (a) RAW -- L1(xgb>=theta) OR L2(ocsvm>=theta), no confound fix")
    print("=" * 90)
    print("\n-- NOVEL == BLENDED (all discriminative; KNOWN is empty for Windows) vs benign --")
    eval_and_print("RAW", "novel_blended", d_l1_raw, d_l2_raw, d_l1_raw | d_l2_raw, b_l1_raw, b_l2_raw, b_l1_raw | b_l2_raw)

    print("\n-- per technique --")
    for tech, rules in WIN_DISCRIMINATIVE.items():
        sub = disc[disc.rule_id.isin(rules)]
        if not len(sub):
            print(f"  {tech}: no attack alerts"); continue
        a1, a2 = l1_raw(sub), l2_raw(sub)
        eval_and_print("RAW", tech, a1, a2, a1 | a2, b_l1_raw, b_l2_raw, b_l1_raw | b_l2_raw)

    print("\n" + "=" * 90)
    print("PIPELINE (b) PRODUCTION -- combined_decision_v6.score_alert() (confound-fix is a no-op here)")
    print("=" * 90)
    print("\n-- NOVEL == BLENDED vs benign --")
    eval_and_print("PRODUCTION", "novel_blended", d_l1_p, d_l2_p, d_comb_p, b_l1_p, b_l2_p, b_comb_p)

    print("\n-- per technique --")
    for tech, rules in WIN_DISCRIMINATIVE.items():
        mask = disc.rule_id.isin(rules).values
        if not mask.any():
            print(f"  {tech}: no attack alerts"); continue
        eval_and_print("PRODUCTION", tech, d_l1_p[mask], d_l2_p[mask], d_comb_p[mask], b_l1_p, b_l2_p, b_comb_p)

    pd.DataFrame(rows).to_csv(f"{HERE}/phaseB_win_results.csv", index=False)
    print(f"\nwrote {HERE}/phaseB_win_results.csv (intermediate; Phase C aggregates the final file)")


if __name__ == "__main__":
    main()
