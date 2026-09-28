"""
v8_fim_task3.py -- FIM feature-degeneracy check, Task 3: REF ceiling explanation.
ANALYSIS ONLY. No training, no pipeline/artifact modification.
"""
import os
import sys

import joblib
import numpy as np

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "newCol"))

from combined_decision_v6 import ocsvm_anomaly_score
from normalize_schema import FEATURE_COLS_NORM
from v8_common import extract_fresh_benign

MODELS = "models_v2"
HERE = "newCol"
CEILING = 160.8693082653799  # established in the v8 run

scaler = joblib.load(f"{MODELS}/scaler_normalized.pkl")
imputer = joblib.load(f"{MODELS}/imputer_normalized.pkl")
oc_ref = joblib.load(f"{MODELS}/ocsvm_normalized.pkl")

print("Imputer statistics_ (median per feature, from its fit data):")
for feat, stat in zip(FEATURE_COLS_NORM, imputer.statistics_):
    print(f"  {feat:<24} {stat}")

# ---------------------------------------------------------------------------
# (a) Synthetic all-imputed vector: every feature = its imputation constant
# ---------------------------------------------------------------------------
synth = imputer.statistics_.reshape(1, -1)
synth_sc = scaler.transform(synth)
synth_score = float(ocsvm_anomaly_score(oc_ref, synth_sc)[0])
print(f"\n(a) Synthetic all-imputed-constant vector score: {synth_score:.5f}  "
      f"(ceiling={CEILING:.5f}, distance_from_ceiling={abs(synth_score-CEILING):.5f})")

# ---------------------------------------------------------------------------
# (b) Fresh Linux benign
# ---------------------------------------------------------------------------
X_lnx = extract_fresh_benign(f"{HERE}/collection_benign_lnx_alerts.json", "lnx")
X_lnx_sc = scaler.transform(imputer.transform(X_lnx))
lnx_scores = ocsvm_anomaly_score(oc_ref, X_lnx_sc)
print(f"\n(b) Fresh Linux benign (n={len(X_lnx)}): "
      f"min={lnx_scores.min():.3f}  median={np.median(lnx_scores):.3f}  "
      f"mean={lnx_scores.mean():.3f}  max={lnx_scores.max():.3f}")
print(f"    frac within 0.01 of ceiling: {(np.abs(lnx_scores - CEILING) < 0.01).mean()*100:.1f}%")
print(f"    frac within 1.0 of ceiling:  {(np.abs(lnx_scores - CEILING) < 1.0).mean()*100:.1f}%")

# ---------------------------------------------------------------------------
# (c) Fresh Windows benign
# ---------------------------------------------------------------------------
X_win = extract_fresh_benign(f"{HERE}/collection_benign_win_alerts.json", "windows")
X_win_sc = scaler.transform(imputer.transform(X_win))
win_scores = ocsvm_anomaly_score(oc_ref, X_win_sc)
print(f"\n(c) Fresh Windows benign (n={len(X_win)}): "
      f"min={win_scores.min():.3f}  median={np.median(win_scores):.3f}  "
      f"mean={win_scores.mean():.3f}  max={win_scores.max():.3f}")
print(f"    frac within 0.01 of ceiling: {(np.abs(win_scores - CEILING) < 0.01).mean()*100:.1f}%")
print(f"    frac within 1.0 of ceiling:  {(np.abs(win_scores - CEILING) < 1.0).mean()*100:.1f}%")

# ---------------------------------------------------------------------------
# Also: score a handful of ACTUAL AIT-ADS training-distribution points for reference
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("Reference: AIT-ADS test-split scores (REF's own training-adjacent distribution)")
print("=" * 90)
from normalize_schema import v6_to_normalized
d = np.load(f"{MODELS}/ait_split.npz", allow_pickle=True)
Xte = v6_to_normalized(d["X_test"], list(d["feature_cols"]))
yte = d["y_test"]
Xte_sc = scaler.transform(imputer.transform(Xte))
ait_scores = ocsvm_anomaly_score(oc_ref, Xte_sc)
print(f"  AIT-ADS test benign (n={int((yte==0).sum())}): "
      f"min={ait_scores[yte==0].min():.3f} median={np.median(ait_scores[yte==0]):.3f} "
      f"max={ait_scores[yte==0].max():.3f}")
print(f"  AIT-ADS test attack (n={int((yte==1).sum())}): "
      f"min={ait_scores[yte==1].min():.3f} median={np.median(ait_scores[yte==1]):.3f} "
      f"max={ait_scores[yte==1].max():.3f}")

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
print("\n" + "=" * 90)
print("VERDICT")
print("=" * 90)
imputation_driven = abs(synth_score - CEILING) < 1.0
distribution_shift = (np.abs(lnx_scores - CEILING) < 1.0).mean() > 0.5 and (np.abs(win_scores - CEILING) < 1.0).mean() > 0.5
print(f"  synthetic all-imputed vector at/near ceiling: {imputation_driven}")
print(f"  fresh Linux AND Windows benign cluster tightly at ceiling: {distribution_shift}")
if not imputation_driven and distribution_shift:
    print("  -> DISTRIBUTION-SHIFT-DRIVEN, not imputation-driven. The synthetic median-everything "
          "vector scores near the AIT-ADS training center (low anomaly), while fresh real alerts "
          "from either platform land at the RBF kernel's mathematical ceiling regardless of platform.")
elif imputation_driven:
    print("  -> IMPUTATION-DRIVEN: the median-constant vector itself already sits at the ceiling.")
else:
    print("  -> INCONCLUSIVE / mixed pattern -- see numbers above.")
