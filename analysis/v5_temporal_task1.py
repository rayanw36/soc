"""
v5_temporal_task1.py -- v5 Temporal-Leakage Check, Task 1: detected-vs-missed autopsy.
Mirrors the v8 FIM-check Task 2, now on v5's L2 FIM detections (26-feature space).
ANALYSIS ONLY.
"""
import os
import sys
import json

import joblib
import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

import shared_features
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, extract_features_v2
from combined_decision_v6 import load_production_models, score_alert
from label_lnx_timeonly import event_time as lnx_event_time

HERE = "newCol"
MODELS = "models_v2"
FIM_TECHS = ["T1053.003", "T1543.002", "T1546.004", "T1098.004"]
TEMPORAL_FEATS = ["alert_rate_1min", "failed_login_5min", "unique_src_ip_10min",
                   "high_sev_ratio_20", "rule_diversity_10min", "time_since_last_high",
                   "scan_preceded", "brute_preceded", "kill_chain_stage"]

models = load_production_models()
oc_v5 = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")
models["ocsvm"] = oc_v5
TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])

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
X = pd.DataFrame(feats, columns=FEATURE_COLS_V2)
for c in ("label", "technique", "rule_id"):
    X[c] = lab[c].values

FIM_DISC_RULES = {"550", "554"}  # 554 -> cron/systemd/shell-rc by path; 550 -> ssh-key by path
fim = X[(X.label == "attack") & (X.technique.isin(FIM_TECHS)) & (X.rule_id.isin(FIM_DISC_RULES))].copy()
print(f"FIM alerts (cron+systemd+shell-rc+ssh-key, discriminative rules only, path-disjoint): n={len(fim)}")
print(fim.technique.value_counts())

l1_hits, l2_hits = [], []
for _, row in fim.iterrows():
    fv = row[FEATURE_COLS_V2].values.astype(float)
    r = score_alert(fv, models)
    l1_hits.append(r["category"] == "known_attack")
    l2_hits.append(r["ocsvm_anomaly_score"] >= TOC)
fim["l1_hit"] = l1_hits
fim["l2_hit"] = l2_hits

print(f"\nL2 detected: {sum(l2_hits)}/{len(fim)}   missed: {len(fim)-sum(l2_hits)}/{len(fim)}")
print(fim[~fim.l2_hit][["technique", "rule_id"]])

det = fim[fim.l2_hit]
miss = fim[~fim.l2_hit]
print(f"\ndetected n={len(det)}  missed n={len(miss)}  "
      f"({'CAUTION: missed n is very small, statistics below are thin' if len(miss) < 5 else ''})")

rows = []
print("\n" + "=" * 100)
print(f"{'feature':<24}{'detected median':>18}{'missed median':>18}   temporal?")
print("=" * 100)
for feat in FEATURE_COLS_V2:
    d_med = det[feat].median()
    m_med = miss[feat].median()
    is_temporal = feat in TEMPORAL_FEATS
    flag = "  <-- TEMPORAL" if is_temporal else ""
    print(f"{feat:<24}{d_med:>18.4f}{m_med:>18.4f}{flag}")
    rows.append(dict(feature=feat, detected_median=d_med, missed_median=m_med, is_temporal=is_temporal))

pd.DataFrame(rows).to_csv(f"{HERE}/v5_temporal_task1_detected_vs_missed.csv", index=False)
print(f"\nwrote {HERE}/v5_temporal_task1_detected_vs_missed.csv")

# also dump the raw missed alert(s) full detail for manual inspection
miss.to_csv(f"{HERE}/v5_temporal_task1_missed_alerts.csv", index=False)
print(f"wrote {HERE}/v5_temporal_task1_missed_alerts.csv")
