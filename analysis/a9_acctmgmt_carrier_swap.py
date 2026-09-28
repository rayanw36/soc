"""
a9_acctmgmt_carrier_swap.py -- A9 pre-check: carrier trace for the 12
account-management alerts (rules 5901/5902) that survive benign-typical
TEMPORAL ablation intact (confirmed by v9_pretask_t1136.py: 6/6 and 6/6).

Same method as the ssh-key swap test described in v5_temporal_leakage_report.md
(single/blocked feature substitution on top of the temporal ablation, using
the production-scoring path). ANALYSIS ONLY. No training, no pipeline change.

Scope per A9 instruction: swap only the remaining non-rate, non-identity
block (content/keyword features), not the identity block (rule_id_encoded,
rule_level, mitre_tactic_id, is_auth_failure, is_web_attack, agent_criticality).
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
IDENTITY_FEATS = ["rule_id_encoded", "rule_level", "mitre_tactic_id",
                  "is_auth_failure", "is_web_attack", "agent_criticality"]
CONTENT_FEATS = [f for f in FEATURE_COLS_V2 if f not in TEMPORAL_FEATS and f not in IDENTITY_FEATS]
assert len(TEMPORAL_FEATS) + len(IDENTITY_FEATS) + len(CONTENT_FEATS) == 26
print(f"CONTENT_FEATS ({len(CONTENT_FEATS)}): {CONTENT_FEATS}\n")

ACCTMGMT_RULES = {"5901", "5902"}

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

am = X[(X.label == "attack") & (X.technique == "T1136.001") & (X.rule_id.isin(ACCTMGMT_RULES))].copy()
print(f"account-mgmt alerts: n={len(am)}  by rule: {am.rule_id.value_counts().to_dict()}")
assert len(am) == 12, f"expected 12, got {len(am)}"

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
temporal_med = Xb[TEMPORAL_FEATS].median()
content_med = Xb[CONTENT_FEATS].median()
print("\nbenign-typical CONTENT medians:")
print(content_med)


def score(df):
    hits, scores = [], []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, models)
        hits.append(r["ocsvm_anomaly_score"] >= TOC)
        scores.append(r["ocsvm_anomaly_score"])
    return np.array(hits, bool), np.array(scores)


# Step 0: raw baseline (no ablation)
orig_hit, orig_score = score(am)

# Step 1: temporal -> benign-typical only (reproduces v9_pretask_t1136.py's 12/12 result)
temp_only = am.copy()
for f in TEMPORAL_FEATS:
    temp_only[f] = temporal_med[f]
temp_only_hit, temp_only_score = score(temp_only)

# Step 2: temporal -> benign-typical AND content -> benign-typical
# (identity block, rule_id_encoded/rule_level/etc., left at the alert's real values)
temp_and_content = temp_only.copy()
for f in CONTENT_FEATS:
    temp_and_content[f] = content_med[f]
tc_hit, tc_score = score(temp_and_content)

print("\n" + "=" * 90)
print("per-rule, per-step hit counts (theta_ocsvm = %.5f)" % TOC)
print("=" * 90)
rows = []
for rid in sorted(ACCTMGMT_RULES, key=int):
    m = (am.rule_id == rid).values
    n = int(m.sum())
    o = int(orig_hit[m].sum())
    t = int(temp_only_hit[m].sum())
    c = int(tc_hit[m].sum())
    print(f"  rule {rid:<6} n={n}  original={o}/{n}  temporal-only-ablated={t}/{n}  "
          f"+content-ablated={c}/{n}")
    rows.append(dict(rule_id=rid, n=n, orig_hit=o, temporal_ablated_hit=t,
                      temporal_and_content_ablated_hit=c))

n_all = len(am)
o_all, t_all, c_all = int(orig_hit.sum()), int(temp_only_hit.sum()), int(tc_hit.sum())
print(f"\n  OVERALL n={n_all}  original={o_all}/{n_all}  temporal-only={t_all}/{n_all}  "
      f"+content={c_all}/{n_all}")
rows.append(dict(rule_id="OVERALL", n=n_all, orig_hit=o_all,
                  temporal_ablated_hit=t_all, temporal_and_content_ablated_hit=c_all))

print("\nscore detail (temporal-ablated-only vs +content-ablated), per alert:")
for i in range(n_all):
    print(f"  rule={am.iloc[i].rule_id}  temporal-only score={temp_only_score[i]:+.4f} "
          f"({'HIT' if temp_only_hit[i] else 'miss'})   "
          f"+content score={tc_score[i]:+.4f} ({'HIT' if tc_hit[i] else 'miss'})")

pd.DataFrame(rows).to_csv(f"{HERE}/a9_acctmgmt_carrier_swap.csv", index=False)
print(f"\nwrote {HERE}/a9_acctmgmt_carrier_swap.csv")

# ---------------------------------------------------------------------------
# Follow-up (not in original A9 scope, but required to interpret the negative
# content-swap result honestly): the content swap left scores essentially
# unchanged (+22 to +27, nowhere near theta=-0.335) -- that means the score is
# dominated by something OUTSIDE {temporal, content}. The only block left is
# IDENTITY, which A9 assumed was already ruled out. Test it directly rather
# than accept that assumption.
# ---------------------------------------------------------------------------
identity_med = Xb[IDENTITY_FEATS].median()
print("\n" + "=" * 90)
print("FOLLOW-UP: identity block was excluded from A9 scope by assumption -- testing it directly")
print("=" * 90)
print("benign-typical IDENTITY medians:")
print(identity_med)

full_swap = temp_and_content.copy()
for f in IDENTITY_FEATS:
    full_swap[f] = identity_med[f]
full_hit, full_score = score(full_swap)

identity_only_swap = am.copy()
for f in IDENTITY_FEATS:
    identity_only_swap[f] = identity_med[f]
id_only_hit, id_only_score = score(identity_only_swap)

print(f"\n  identity-only ablated (temporal/content left at real values): "
      f"{int(id_only_hit.sum())}/{n_all}")
print(f"  full benign-typical (temporal+content+identity all ablated): "
      f"{int(full_hit.sum())}/{n_all}")
for i in range(n_all):
    print(f"  rule={am.iloc[i].rule_id}  identity-only score={id_only_score[i]:+.4f} "
          f"({'HIT' if id_only_hit[i] else 'miss'})   "
          f"full-ablated score={full_score[i]:+.4f} ({'HIT' if full_hit[i] else 'miss'})")
