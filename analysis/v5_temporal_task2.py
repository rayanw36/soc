"""
v5_temporal_task2.py -- v5 Temporal-Leakage Check, Task 2: temporal-ablation scoring.
ANALYSIS ONLY. No training, no pipeline/artifact modification.
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
from combined_decision_v6 import load_production_models, score_alert, ocsvm_anomaly_score
from label_lnx_timeonly import event_time as lnx_event_time
from v8_common import extract_fresh_benign

HERE = "newCol"
MODELS = "models_v2"
FIM_TECHS = ["T1053.003", "T1543.002", "T1546.004", "T1098.004"]
FIM_DISC_RULES = {"550", "554"}
TEMPORAL_FEATS = ["alert_rate_1min", "failed_login_5min", "unique_src_ip_10min",
                   "high_sev_ratio_20", "rule_diversity_10min", "time_since_last_high",
                   "scan_preceded", "brute_preceded", "kill_chain_stage"]
TEMPORAL_IDX = [FEATURE_COLS_V2.index(f) for f in TEMPORAL_FEATS]

models = load_production_models()
oc_v5 = joblib.load(f"{MODELS}/ocsvm_nu05.pkl")
models["ocsvm"] = oc_v5
TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])
print(f"theta_ocsvm={TOC:.5f}\ntemporal features (9): {TEMPORAL_FEATS}\n")

# ---------------------------------------------------------------------------
# Extract FIM alerts (26-feat) -- same as Task 1
# ---------------------------------------------------------------------------
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

fim = X[(X.label == "attack") & (X.technique.isin(FIM_TECHS)) & (X.rule_id.isin(FIM_DISC_RULES))].copy()
print(f"FIM alerts: n={len(fim)}  by technique: {fim.technique.value_counts().to_dict()}\n")

# ---------------------------------------------------------------------------
# Fresh Linux benign -- for the BENIGN-TYPICAL medians and the mirror control
# ---------------------------------------------------------------------------
raw_b = []
with open(f"{HERE}/collection_benign_lnx_alerts.json") as fh:
    for idx, line in enumerate(fh):
        line = line.strip()
        if not line:
            continue
        a = json.loads(line)
        raw_b.append((idx, a))
from shared_features import parse_timestamp
raw_b_ts = [(idx, parse_timestamp(a), a) for idx, a in raw_b]
raw_b_ts.sort(key=lambda r: (r[1] is None, r[1]))
hist_b = {}
feats_b = []
for idx, ts, a in raw_b_ts:
    agent = a.get("agent", {}).get("name", "unknown")
    h = hist_b.setdefault(agent, AgentHistory())
    feats_b.append(extract_features_v2(a, h.compute_features(ts)))
    h.add(a, ts)
Xb = pd.DataFrame(feats_b, columns=FEATURE_COLS_V2)
print(f"fresh Linux benign: n={len(Xb)}")

benign_medians = Xb[TEMPORAL_FEATS].median()
print("\nbenign-typical medians (temporal features):")
print(benign_medians)


def score_batch(df):
    hits = []
    scores = []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, models)
        hits.append(r["ocsvm_anomaly_score"] >= TOC)
        scores.append(r["ocsvm_anomaly_score"])
    return np.array(hits, bool), np.array(scores)


# ---------------------------------------------------------------------------
# Original scores (L2, no ablation)
# ---------------------------------------------------------------------------
orig_hit, orig_score = score_batch(fim)
fim["orig_hit"] = orig_hit

# ---------------------------------------------------------------------------
# (a) ZEROED ablation
# ---------------------------------------------------------------------------
fim_zeroed = fim.copy()
for f in TEMPORAL_FEATS:
    fim_zeroed[f] = 0.0
# time_since_last_high's "no recent high" default is 999, not 0 -- zero here means
# "a high-severity alert just happened" which is the WRONG null value. Use the
# documented default explicitly for that one feature instead of literal 0.
fim_zeroed["time_since_last_high"] = 999.0
zeroed_hit, zeroed_score = score_batch(fim_zeroed)

# ---------------------------------------------------------------------------
# (b) BENIGN-TYPICAL ablation
# ---------------------------------------------------------------------------
fim_benigntyp = fim.copy()
for f in TEMPORAL_FEATS:
    fim_benigntyp[f] = benign_medians[f]
benigntyp_hit, benigntyp_score = score_batch(fim_benigntyp)

# ---------------------------------------------------------------------------
# Per-technique results
# ---------------------------------------------------------------------------
print("\n" + "=" * 100)
print("PER-TECHNIQUE: recall original vs (a) ZEROED vs (b) BENIGN-TYPICAL")
print("=" * 100)
rows = []
for tech in FIM_TECHS:
    m = (fim.technique == tech).values
    n = int(m.sum())
    o = int(orig_hit[m].sum())
    z = int(zeroed_hit[m].sum())
    b = int(benigntyp_hit[m].sum())
    print(f"  {tech:<12} n={n}  original={o}/{n}  zeroed={z}/{n}  benign-typical={b}/{n}")
    rows.append(dict(technique=tech, n=n, recall_original=o, recall_zeroed=z, recall_benigntyp=b))

overall_o, overall_z, overall_b = int(orig_hit.sum()), int(zeroed_hit.sum()), int(benigntyp_hit.sum())
print(f"\n  OVERALL      n={len(fim)}  original={overall_o}/{len(fim)}  "
      f"zeroed={overall_z}/{len(fim)}  benign-typical={overall_b}/{len(fim)}")
rows.append(dict(technique="OVERALL", n=len(fim), recall_original=overall_o,
                  recall_zeroed=overall_z, recall_benigntyp=overall_b))

# ---------------------------------------------------------------------------
# Mirror control: benign alerts with FIM-detected-attack-typical temporal context
# ---------------------------------------------------------------------------
print("\n" + "=" * 100)
print("MIRROR CONTROL -- fresh Linux benign, temporal features set to FIM-detected-attack medians")
print("=" * 100)
det_fim = fim[fim.orig_hit]
attack_medians = det_fim[TEMPORAL_FEATS].median()
print("attack-typical medians (from L2-detected FIM alerts):")
print(attack_medians)

benign_orig_hit, _ = score_batch(Xb)
Xb_poisoned = Xb.copy()
for f in TEMPORAL_FEATS:
    Xb_poisoned[f] = attack_medians[f]
benign_poisoned_hit, _ = score_batch(Xb_poisoned)

n_b = len(Xb)
print(f"\n  benign FPR original (n={n_b}): {int(benign_orig_hit.sum())}/{n_b} "
      f"({benign_orig_hit.mean()*100:.1f}%)")
print(f"  benign FPR with attack-typical temporal context: {int(benign_poisoned_hit.sum())}/{n_b} "
      f"({benign_poisoned_hit.mean()*100:.1f}%)")

rows.append(dict(technique="MIRROR_CONTROL_benign_original", n=n_b,
                  recall_original=int(benign_orig_hit.sum()), recall_zeroed=None, recall_benigntyp=None))
rows.append(dict(technique="MIRROR_CONTROL_benign_poisoned_with_attack_temporal", n=n_b,
                  recall_original=int(benign_poisoned_hit.sum()), recall_zeroed=None, recall_benigntyp=None))

out = pd.DataFrame(rows)
out.to_csv(f"{HERE}/v5_temporal_leakage_ablation.csv", index=False)
print(f"\nwrote {HERE}/v5_temporal_leakage_ablation.csv")
