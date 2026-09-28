"""
v8_fim_task2.py -- FIM feature-degeneracy check, Task 2: explain the identical 12/79 counts.
ANALYSIS ONLY. No training, no pipeline/artifact modification.
"""
import os
import sys

import joblib
import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

from combined_decision_v6 import ocsvm_anomaly_score
from normalize_schema import FEATURE_COLS_NORM

HERE = "newCol"
MODELS = "models_v2"

fim = pd.read_pickle(f"{HERE}/_v8_fim_alerts.pkl").reset_index(drop=True)   # rule_id, label, 22 raw feats
fim_imputed = pd.read_pickle(f"{HERE}/_v8_fim_imputed.pkl").reset_index(drop=True)  # post-imputation

print(f"FIM alerts: n={len(fim)}  by rule: {fim.rule_id.value_counts().to_dict()}\n")

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
X_fim_sc = scaler.transform(fim_imputed[FEATURE_COLS_NORM].values.astype(np.float64))

calib = pd.read_csv(f"{HERE}/v8_task1_calibration.csv")
theta_map = dict(zip(calib.candidate, calib.theta_calibrated))

candidates = {
    "C1_win_native": joblib.load(f"{MODELS}/ocsvm_win_native_v8.pkl"),
    "C2_xplatform_v7": joblib.load(f"{MODELS}/ocsvm_xplatform_v7.pkl"),
    "C3_xplatform_v8": joblib.load(f"{MODELS}/ocsvm_xplatform_v8.pkl"),
}

hits = {}
for name, oc in candidates.items():
    theta = float(theta_map[name])
    scores = ocsvm_anomaly_score(oc, X_fim_sc)
    hits[name] = scores >= theta
    print(f"{name}: theta={theta:.5f}  total detected={int(hits[name].sum())}/{len(fim)}  "
          f"by rule: " + str({r: int(hits[name][(fim.rule_id == r).values].sum()) for r in sorted(fim.rule_id.unique())}))

# ---------------------------------------------------------------------------
# (a) Same alert IDs detected across all three candidates?
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(a) Do the same alert indices get detected across C1/C2/C3?")
print("=" * 90)
idx_c1 = set(np.where(hits["C1_win_native"])[0])
idx_c2 = set(np.where(hits["C2_xplatform_v7"])[0])
idx_c3 = set(np.where(hits["C3_xplatform_v8"])[0])
print(f"  C1 detected indices: {len(idx_c1)}  C2: {len(idx_c2)}  C3: {len(idx_c3)}")
print(f"  C1 == C2 exactly: {idx_c1 == idx_c2}")
print(f"  C1 == C3 exactly: {idx_c1 == idx_c3}")
print(f"  C2 == C3 exactly: {idx_c2 == idx_c3}")
print(f"  intersection (all three agree): {len(idx_c1 & idx_c2 & idx_c3)}")
print(f"  union (any of the three): {len(idx_c1 | idx_c2 | idx_c3)}")
print(f"  C1 only: {sorted(idx_c1 - idx_c2 - idx_c3)}")
print(f"  C2 only: {sorted(idx_c2 - idx_c1 - idx_c3)}")
print(f"  C3 only: {sorted(idx_c3 - idx_c1 - idx_c2)}")

# ---------------------------------------------------------------------------
# (b) Group by unique feature vector: does detected/missed align with vector groups?
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(b) Detection alignment with duplicate-vector groups")
print("=" * 90)
vecs = [tuple(v) for v in np.round(fim_imputed[FEATURE_COLS_NORM].values, 6)]
fim_imputed["_vec"] = vecs
fim["_vec"] = vecs

group_sizes = fim.groupby("_vec").size()
print(f"  {len(group_sizes)} unique vectors among {len(fim)} FIM alerts "
      f"(largest group: {group_sizes.max()} alerts sharing one vector)")

for name in candidates:
    fim[f"_hit_{name}"] = hits[name]

mixed_groups = 0
for vec, grp in fim.groupby("_vec"):
    if len(grp) < 2:
        continue
    for name in candidates:
        if grp[f"_hit_{name}"].nunique() > 1:
            mixed_groups += 1
            break
print(f"  duplicate-vector groups (size>=2) where detection status is NOT unanimous "
      f"(any candidate): {mixed_groups} / {(group_sizes >= 2).sum()} such groups")
print("  -> if 0, whole duplicate-vector blocks are detected or missed together (confirms alignment)")

# ---------------------------------------------------------------------------
# (c) What distinguishes detected vs missed vectors (C2, best candidate)?
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("(c) Detected vs missed -- C2_xplatform_v7 (best candidate), non-constant features only")
print("=" * 90)
NONCONST_FEATS = ["severity_norm", "mitre_tactic_id", "alert_rate_1min", "failed_login_5min",
                   "unique_src_ip_10min", "high_sev_ratio_20", "rule_diversity_10min",
                   "time_since_last_high", "scan_preceded", "brute_preceded",
                   "event_type", "actor_type", "touches_sensitive_path", "cmdline_priv_tokens"]
det = fim[fim["_hit_C2_xplatform_v7"]]
miss = fim[~fim["_hit_C2_xplatform_v7"]]
print(f"  detected n={len(det)}  missed n={len(miss)}\n")
comp_rows = []
for feat in NONCONST_FEATS:
    d_med, m_med = det[feat].median(), miss[feat].median()
    d_uniq, m_uniq = sorted(det[feat].unique().tolist()), sorted(miss[feat].unique().tolist())
    print(f"  {feat:<24} detected: median={d_med:10.3f} vals={d_uniq[:8]}{'...' if len(d_uniq)>8 else ''}")
    print(f"  {'':<24} missed  : median={m_med:10.3f} vals={m_uniq[:8]}{'...' if len(m_uniq)>8 else ''}")
    comp_rows.append(dict(feature=feat, detected_median=d_med, missed_median=m_med))

pd.DataFrame(comp_rows).to_csv(f"{HERE}/v8_fim_task2_detected_vs_missed.csv", index=False)
print(f"\nwrote {HERE}/v8_fim_task2_detected_vs_missed.csv")
