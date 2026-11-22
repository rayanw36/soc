"""
build_expanded_benign_baseline_v6.py
====================================
v6 TASK 2 -- build the expanded L2 benign baseline.

Task 1 established that the rule-31151/5710 benign traffic is ALREADY in
benign_baseline_clean.csv (5.3% / 3.5%); the OC-SVM under-represents it not
because it is absent but because it is a small minority dwarfed by rule 31101
(79%). The "fold-in" is therefore an UP-WEIGHTING (oversampling) of the existing
validated benign 31151/5710 rows so the OC-SVM learns their region as normal.

Leakage safety: the v5/v6 evaluation holds out a fixed 20% of
benign_baseline_clean.csv (RandomState(SEED).permutation). We oversample ONLY
rows in the 80% TRAIN portion, never the held-out 20% -- so the v6 FPR is still
measured on traffic the model never saw (in any multiplicity). The held-out rows
appear exactly once each (inside the original 4257), never duplicated.

    ~/soc_project/.venv/bin/python build_expanded_benign_baseline_v6.py
"""

import json

import numpy as np
import pandas as pd

from shared_constants_v2 import FEATURE_COLS_V2, SEED

RESULTS = "results_v2"
RID = FEATURE_COLS_V2.index("rule_id_encoded")
TARGET_RULES = (31151, 5710)

# Knee-point factor (see retrain_ocsvm_v6 / validate_v6): smallest oversample at
# which 31151's held-out FPR reaches its floor (74%->2%) and 5710 plateaus
# (60%->~25%), with R3 maintained/improved. Larger factors add no benefit, only
# duplication distortion -- so we do NOT tune it lower to flatter the FPR.
OVERSAMPLE_FACTOR = 6


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


# ---------------------------------------------------------------------------
# 1-2. Load the existing clean baseline + Task-1 validated additional traffic
# ---------------------------------------------------------------------------
hr("1-2. LOAD clean baseline + validated additional 31151/5710 traffic")
clean = pd.read_csv(f"{RESULTS}/benign_baseline_clean.csv")[FEATURE_COLS_V2].copy()
add = pd.read_csv(f"{RESULTS}/additional_benign_31151_5710.csv")
print(f"  benign_baseline_clean.csv : {len(clean)} rows x {len(FEATURE_COLS_V2)} features")
print(f"  additional (Task 1)       : {len(add)} validated benign 31151/5710 rows")

# ---------------------------------------------------------------------------
# 3. The additional rows already carry the 26 features extracted by
#    shared_features.extract_features_v2() in Task 1 -- reuse them directly
#    (re-extracting would reproduce the identical vectors). Confirm schema.
# ---------------------------------------------------------------------------
hr("3. FEATURE CONSISTENCY")
assert all(c in add.columns for c in FEATURE_COLS_V2), "additional CSV missing feature cols"
print("  additional rows use the SAME 26 features (extract_features_v2 in Task 1) -- OK")

# ---------------------------------------------------------------------------
# 4. Reproduce the fixed held-out split; oversample TRAIN-portion 31151/5710 only
# ---------------------------------------------------------------------------
hr("4. BUILD EXPANDED BASELINE (oversample train-portion minority rules)")
n_clean = len(clean)
perm = np.random.RandomState(SEED).permutation(n_clean)
n_hold = max(1, int(0.20 * n_clean))
held_out_pos = set(perm[:n_hold].tolist())          # positions in `clean` held out for eval
train_pos = [i for i in range(n_clean) if i not in held_out_pos]

clean_rid = clean[FEATURE_COLS_V2[RID]].round().astype(int).values
is_target_train = np.array([(i in set(train_pos)) and (clean_rid[i] in TARGET_RULES)
                            for i in range(n_clean)])
target_train_idx = np.where(is_target_train)[0]

extras = pd.concat([clean.iloc[target_train_idx]] * (OVERSAMPLE_FACTOR - 1),
                   ignore_index=True)
expanded = pd.concat([clean, extras], ignore_index=True)   # first n_clean rows == clean order


def rep(df_or_rid, rule):
    rid = (df_or_rid[FEATURE_COLS_V2[RID]].round().astype(int)
           if isinstance(df_or_rid, pd.DataFrame) else df_or_rid)
    n = len(rid)
    c = int((rid == rule).sum())
    return c, 100 * c / n


print(f"  Original baseline: {n_clean} alerts.")
for r in TARGET_RULES:
    c, p = rep(clean, r)
    ct, _ = rep(clean.iloc[target_train_idx], r)
    print(f"    rule {r}: {c} total ({p:.1f}%), of which {ct} in the 80% train portion "
          f"are oversampled x{OVERSAMPLE_FACTOR}")
added31 = int((clean.iloc[target_train_idx][FEATURE_COLS_V2[RID]].round().astype(int) == 31151).sum()) * (OVERSAMPLE_FACTOR - 1)
added57 = int((clean.iloc[target_train_idx][FEATURE_COLS_V2[RID]].round().astype(int) == 5710).sum()) * (OVERSAMPLE_FACTOR - 1)
print(f"  Added: {added31} (rule 31151 copies) + {added57} (rule 5710 copies) = {len(extras)} rows.")
print(f"  New baseline size: {n_clean} + {len(extras)} = {len(expanded)}.")
c31, p31 = rep(expanded, 31151); c57, p57 = rep(expanded, 5710)
o31, op31 = rep(clean, 31151);  o57, op57 = rep(clean, 5710)
print(f"  New rule-31151 representation: {p31:.1f}% of total (was {op31:.1f}%).")
print(f"  New rule-5710  representation: {p57:.1f}% of total (was {op57:.1f}%).")

# ---------------------------------------------------------------------------
# 5. Save expanded baseline + a manifest so retrain/validate stay leakage-safe
# ---------------------------------------------------------------------------
hr("5. SAVE results_v2/benign_baseline_v6.csv")
expanded[FEATURE_COLS_V2].to_csv(f"{RESULTS}/benign_baseline_v6.csv", index=False)
manifest = {
    "n_clean": int(n_clean),
    "oversample_factor": OVERSAMPLE_FACTOR,
    "oversampled_rules": list(TARGET_RULES),
    "n_extra_rows": int(len(extras)),
    "n_total": int(len(expanded)),
    "seed": int(SEED),
    "held_out_frac": 0.20,
    "note": ("first n_clean rows == benign_baseline_clean.csv order; extras are "
             "duplicates of TRAIN-portion 31151/5710 only. Reproduce the held-out "
             "20% via RandomState(SEED).permutation(n_clean)[:int(0.2*n_clean)] on "
             "the first n_clean rows; those positions are never duplicated."),
}
with open(f"{RESULTS}/_benign_v6_manifest.json", "w") as fh:
    json.dump(manifest, fh, indent=2)
print(f"  Saved results_v2/benign_baseline_v6.csv ({len(expanded)} rows)")
print(f"  Saved results_v2/_benign_v6_manifest.json")
print("\n  NOTE: this is an UP-WEIGHTING of existing validated benign 31151/5710,")
print("  not newly-captured data (see Task 1 verdict). The held-out 20% used to")
print("  measure v6 FPR is untouched and never duplicated -- no leakage.")
