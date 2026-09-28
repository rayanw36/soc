"""
v9_pretask_t1136.py -- PRE-TASK: classify T1136.001's temporal signal (endogenous vs exogenous).
Same benign-typical ablation method as v5_temporal_task2.py, applied to T1136.001 (n=163).
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
from shared_features import AgentHistory, extract_features_v2, parse_timestamp
from combined_decision_v6 import load_production_models, score_alert
from label_lnx_timeonly import event_time as lnx_event_time

HERE = "newCol"
MODELS = "models_v2"
TEMPORAL_FEATS = ["alert_rate_1min", "failed_login_5min", "unique_src_ip_10min",
                   "high_sev_ratio_20", "rule_diversity_10min", "time_since_last_high",
                   "scan_preceded", "brute_preceded", "kill_chain_stage"]
T1136_RULES = {"550", "553", "554", "5901", "5902"}

models = load_production_models()
models["ocsvm"] = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")
TOC = float(models["theta_ocsvm"])

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

t1136 = X[(X.label == "attack") & (X.technique == "T1136.001") & (X.rule_id.isin(T1136_RULES))].copy()
print(f"T1136.001 discriminative alerts: n={len(t1136)}  by rule: {t1136.rule_id.value_counts().to_dict()}")
assert len(t1136) == 163, f"expected 163, got {len(t1136)}"

raw_b = []
with open(f"{HERE}/collection_benign_lnx_alerts.json") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        raw_b.append(json.loads(line))
raw_b_ts = [(parse_timestamp(a), a) for a in raw_b]
raw_b_ts.sort(key=lambda r: (r[0] is None, r[0]))
histb = {}
featsb = []
for ts, a in raw_b_ts:
    agent = a.get("agent", {}).get("name", "unknown")
    h = histb.setdefault(agent, AgentHistory())
    featsb.append(extract_features_v2(a, h.compute_features(ts)))
    h.add(a, ts)
Xb = pd.DataFrame(featsb, columns=FEATURE_COLS_V2)
med = Xb[TEMPORAL_FEATS].median()
print("\nbenign-typical medians:")
print(med)


def score(df):
    hits = []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, models)
        hits.append(r["ocsvm_anomaly_score"] >= TOC)
    return np.array(hits, bool)


orig_hit = score(t1136)
ablated = t1136.copy()
for f in TEMPORAL_FEATS:
    ablated[f] = med[f]
ablated_hit = score(ablated)

n = len(t1136)
print(f"\nT1136.001 (create-user): n={n}")
print(f"  recall original      : {int(orig_hit.sum())}/{n} ({orig_hit.mean()*100:.1f}%)")
print(f"  recall benign-typical: {int(ablated_hit.sum())}/{n} ({ablated_hit.mean()*100:.1f}%)")

# per-rule breakdown for extra transparency
print("\nper-rule breakdown:")
for rid in sorted(T1136_RULES, key=int):
    m = (t1136.rule_id == rid).values
    if not m.any():
        continue
    print(f"  rule {rid:<6} n={int(m.sum()):<4} original={int(orig_hit[m].sum())}/{int(m.sum())}  "
          f"benign-typical={int(ablated_hit[m].sum())}/{int(m.sum())}")

pd.DataFrame([dict(technique="T1136.001", n=n,
                    recall_original=int(orig_hit.sum()), recall_benigntyp=int(ablated_hit.sum()))]
             ).to_csv(f"{HERE}/v9_pretask_t1136_ablation.csv", index=False)
print(f"\nwrote {HERE}/v9_pretask_t1136_ablation.csv")
