"""
v8_fim_task1.py -- FIM feature-degeneracy check, Task 1: feature-space autopsy.
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

from shared_features import AgentHistory
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2
import shared_features
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from label_lnx_timeonly import event_time as lnx_event_time
from normalize_schema import extract_normalized, FEATURE_COLS_NORM
from v8_common import extract_fresh_benign

HERE = "newCol"
MODELS = "models_v2"

FIM_RULES = {"550", "553", "554"}          # syscheck/FIM family
NONFIM_RULES = {"5710", "5712", "5901", "5902", "5903"}  # auth + account family, NOT syscheck

# ---------------------------------------------------------------------------
# Extract Linux attack alerts, 22-feat, event-time ordered (same convention as v8 Task 3)
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
    feats[idx] = extract_normalized(a, h.compute_features(ts), process_depth=0)
    h.add(a, ts)

lab = pd.read_csv(f"{HERE}/labeled_lnx.csv", dtype={"rule_id": str})
assert len(lab) == len(feats)
Xa = pd.DataFrame(feats, columns=FEATURE_COLS_NORM)
Xa["label"] = lab["label"].values
Xa["rule_id"] = lab["rule_id"].values

fim = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(FIM_RULES))].copy()
nonfim = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(NONFIM_RULES))].copy()
print(f"FIM attack alerts (rules {sorted(FIM_RULES)}): n={len(fim)}  by rule: {fim.rule_id.value_counts().to_dict()}")
print(f"non-FIM attack alerts (rules {sorted(NONFIM_RULES)}): n={len(nonfim)}  by rule: {nonfim.rule_id.value_counts().to_dict()}")

X_benign = extract_fresh_benign(f"{HERE}/collection_benign_lnx_alerts.json", "lnx")
benign_df = pd.DataFrame(X_benign, columns=FEATURE_COLS_NORM)
print(f"fresh Linux benign: n={len(benign_df)}\n")

# ---------------------------------------------------------------------------
# (a) PRE-IMPUTATION: true NaN rate in extract_normalized's own output
# ---------------------------------------------------------------------------
print("=" * 90)
print("(a) PRE-IMPUTATION -- true NaN rate directly out of extract_normalized()")
print("=" * 90)
groups = {"FIM": fim[FEATURE_COLS_NORM], "non-FIM": nonfim[FEATURE_COLS_NORM], "benign": benign_df}
nan_rates = {}
for gname, gdf in groups.items():
    nan_rates[gname] = gdf.isna().mean() * 100
    total_nan = int(gdf.isna().sum().sum())
    print(f"  {gname}: total NaN cells = {total_nan} / {gdf.size} ({total_nan/gdf.size*100:.2f}%)")

# ---------------------------------------------------------------------------
# (b)/(c) POST-IMPUTATION, PRE-SCALING: variance, distinct values, constant count
# ---------------------------------------------------------------------------
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")

print("\n" + "=" * 90)
print("(b)/(c) POST-IMPUTATION, PRE-SCALING -- variance / distinct values / constant-feature count")
print("=" * 90)

imputed = {}
for gname, gdf in groups.items():
    Ximp = imputer.transform(gdf.values.astype(np.float64))
    imputed[gname] = pd.DataFrame(Ximp, columns=FEATURE_COLS_NORM)

const_counts = {}
for gname, gdf in imputed.items():
    var = gdf.var()
    nuniq = gdf.nunique()
    n_const = int(((var < 1e-9) | (nuniq <= 1)).sum())
    const_counts[gname] = n_const
    print(f"  {gname}: {n_const} / {len(FEATURE_COLS_NORM)} features effectively constant "
          f"(variance<1e-9 or 1 distinct value)")

# ---------------------------------------------------------------------------
# Build the master table
# ---------------------------------------------------------------------------
rows = []
for feat in FEATURE_COLS_NORM:
    rows.append(dict(
        feature=feat,
        nan_pct_FIM=nan_rates["FIM"][feat],
        nan_pct_nonFIM=nan_rates["non-FIM"][feat],
        nan_pct_benign=nan_rates["benign"][feat],
        distinct_vals_FIM=int(imputed["FIM"][feat].nunique()),
        variance_FIM=float(imputed["FIM"][feat].var()),
        distinct_vals_nonFIM=int(imputed["non-FIM"][feat].nunique()),
        variance_nonFIM=float(imputed["non-FIM"][feat].var()),
        distinct_vals_benign=int(imputed["benign"][feat].nunique()),
        variance_benign=float(imputed["benign"][feat].var()),
    ))
table = pd.DataFrame(rows)
print("\n" + "=" * 90)
print("FEATURE TABLE")
print("=" * 90)
pd.set_option("display.width", 200)
print(table.to_string(index=False))

# ---------------------------------------------------------------------------
# (d) Vector collapse check
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(d) VECTOR COLLAPSE CHECK")
print("=" * 90)
for gname, gdf in imputed.items():
    n = len(gdf)
    nuniq_vec = len(set(map(tuple, np.round(gdf.values, 6))))
    print(f"  {gname}: {n} alerts -> {nuniq_vec} unique 22-dim vectors "
          f"({nuniq_vec/n*100:.1f}% unique)")

table.to_csv(f"{HERE}/v8_fim_feature_table.csv", index=False)
print(f"\nwrote {HERE}/v8_fim_feature_table.csv")

# stash intermediate for Task 2 reuse
fim.to_pickle(f"{HERE}/_v8_fim_alerts.pkl")
imputed["FIM"].to_pickle(f"{HERE}/_v8_fim_imputed.pkl")
