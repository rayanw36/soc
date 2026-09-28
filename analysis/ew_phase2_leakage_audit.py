"""
ew_phase2_leakage_audit.py
===========================
Phase 2 of the Entity-Window experiment: leakage audit of the EW features,
run BEFORE any model is trained on them (Phase 4). Uses only the augmented
per-alert table Phase 1 already produced
(newCol/ew_features/ew_augmented_per_alert.csv) -- no new collection.

Sub-tasks (per the experiment plan):
  b. Mutual information of each EW feature against the label, per platform,
     with a same-methodology MI baseline computed for the known
     RULE-IDENTITY features so "does an EW feature's MI rival rule-identity"
     is an actual same-units comparison, not a vibe check.
  d. Benign-burst mirror-control feasibility search.
  e. Testbed-artifact (gross temporal texture) check.
  c. Counterfactual swap machinery + value distributions (prepared here;
     EXECUTION against a trained model is Phase 4, not this script -- no EW
     model exists yet).
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif

HERE = os.path.dirname(os.path.abspath(__file__))
AUG_PATH = os.path.join(HERE, "ew_features", "ew_augmented_per_alert.csv")

RNG_SEED = 42

df = pd.read_csv(AUG_PATH, low_memory=False)
print(f"loaded {AUG_PATH}: {df.shape}")

EW_COLS = [c for c in df.columns if c.startswith("ew_")]
print(f"{len(EW_COLS)} EW columns")

# Reference RULE-IDENTITY / RULE-CORRELATED features from the original
# 26-feature audit (results/rule_memorization_audit/exp1_feature_classification.py)
# -- used here as the same-units MI baseline.
RULE_IDENTITY_REF = ["rule_id_encoded", "desc_len", "rule_level"]
RULE_CORRELATED_REF = ["mitre_tactic_id", "is_auth_failure", "is_web_attack",
                        "rule_diversity_10min", "high_sev_ratio_20"]

PLATFORM_SOURCES = {
    "lnx": ("lnx_attack", "lnx_benign"),
    "win": ("win_attack", "win_benign"),
}


def compute_mi(sub, cols, y):
    X = sub[cols].astype(float).values
    # mutual_info_classif requires finite values; EW/v2 columns are always
    # fully populated (sentinels, never NaN) by construction, but guard anyway.
    if not np.isfinite(X).all():
        bad = [cols[j] for j in range(len(cols)) if not np.isfinite(X[:, j]).all()]
        raise ValueError(f"non-finite values in columns: {bad}")
    mi = mutual_info_classif(X, y, discrete_features=False, random_state=RNG_SEED)
    return dict(zip(cols, mi))


results = {}
class_balance = {}

for platform, (attack_src, benign_src) in PLATFORM_SOURCES.items():
    sub = df[df["source"].isin([attack_src, benign_src])].copy()
    n_uncertain = (sub["label"] == "uncertain").sum()
    sub = sub[sub["label"] != "uncertain"]
    y = (sub["label"] == "attack").astype(int).values
    n_attack, n_benign = int(y.sum()), int((1 - y).sum())
    class_balance[platform] = dict(n_attack=n_attack, n_benign=n_benign,
                                    n_uncertain_dropped=int(n_uncertain))
    print(f"\n=== {platform}: n_attack={n_attack} n_benign={n_benign} "
          f"(dropped {n_uncertain} uncertain) ===")

    ew_mi = compute_mi(sub, EW_COLS, y)
    ref_mi = compute_mi(sub, RULE_IDENTITY_REF + RULE_CORRELATED_REF, y)

    results[platform] = dict(ew_mi=ew_mi, ref_mi=ref_mi, n=len(sub))

    ref_max = max(ref_mi.values())
    print(f"  RULE-IDENTITY/CORRELATED reference MI (same method): "
          f"max={ref_max:.4f}  ({ {k: round(v,4) for k,v in ref_mi.items()} })")

    ew_sorted = sorted(ew_mi.items(), key=lambda kv: -kv[1])
    print(f"  Top 10 EW features by MI:")
    for feat, mi in ew_sorted[:10]:
        flag = " <-- RIVALS RULE-IDENTITY REF" if mi >= ref_max * 0.8 else ""
        print(f"    {feat:<55} {mi:.4f}{flag}")

# ---------------------------------------------------------------------------
# Conditional MI for the user-pivot block: restricted to rows where the user
# pivot is actually populated, since ~most Linux volume (31101) never has a
# user and would otherwise dilute the MI estimate for reasons unrelated to
# whether the feature is informative when it DOES apply.
# ---------------------------------------------------------------------------
user_block_cols = [c for c in EW_COLS if c.startswith("ew_user_trail60m_")]
cond_results = {}
for platform, (attack_src, benign_src) in PLATFORM_SOURCES.items():
    sub = df[df["source"].isin([attack_src, benign_src])].copy()
    sub = sub[sub["label"] != "uncertain"]
    sub_u = sub[sub["ew_user_present"] == 1.0]
    y_u = (sub_u["label"] == "attack").astype(int).values
    if len(np.unique(y_u)) < 2 or len(sub_u) < 10:
        cond_results[platform] = dict(n=len(sub_u), note="insufficient class diversity / n for MI")
        print(f"\n{platform} (user-present subset): n={len(sub_u)}, "
              f"classes={np.unique(y_u)} -- skipping MI (insufficient)")
        continue
    mi_u = compute_mi(sub_u, user_block_cols, y_u)
    cond_results[platform] = dict(n=len(sub_u), n_attack=int(y_u.sum()),
                                   n_benign=int((1 - y_u).sum()), mi=mi_u)
    print(f"\n{platform} (user-present subset, n={len(sub_u)}, "
          f"attack={int(y_u.sum())} benign={int((1-y_u).sum())}):")
    for feat, mi in sorted(mi_u.items(), key=lambda kv: -kv[1]):
        print(f"    {feat:<55} {mi:.4f}")

# ---------------------------------------------------------------------------
# 2d. Benign-burst mirror-control search
# ---------------------------------------------------------------------------
print("\n\n=== 2d. Benign-burst search ===")
burst_report = {}
for platform, (attack_src, benign_src) in PLATFORM_SOURCES.items():
    for src in (attack_src, benign_src):
        s = df[df["source"] == src]
        ts = pd.to_datetime(s["ts"], utc=True, format="ISO8601").values.astype("datetime64[ns]").astype("int64") / 1e9
        ts = np.sort(ts)
        if len(ts) < 2:
            continue
        bins = np.floor((ts - ts.min()) / 10.0).astype(int)
        counts = np.bincount(bins)
        span_s = float(ts.max() - ts.min())
        burst_report[src] = dict(
            n=len(ts), span_s=span_s,
            max_10s_rate=int(counts.max()),
            median_10s_rate_nonzero=float(np.median(counts[counts > 0])) if (counts > 0).any() else 0.0,
            mean_alerts_per_s=len(ts) / span_s if span_s > 0 else float("nan"),
        )
        print(f"  {src:<15} n={len(ts):<7} span={span_s:>8.1f}s  "
              f"max_10s_rate={counts.max():<6} mean_alerts/s={len(ts)/span_s if span_s>0 else float('nan'):.3f}")

# ---------------------------------------------------------------------------
# 2e. Testbed-artifact check: does the busiest benign 10s bin even reach the
# QUIETEST attack-phase rate?
# ---------------------------------------------------------------------------
print("\n=== 2e. Testbed-artifact check ===")
for platform, (attack_src, benign_src) in PLATFORM_SOURCES.items():
    a = burst_report.get(attack_src, {})
    b = burst_report.get(benign_src, {})
    if a and b:
        ratio = b["max_10s_rate"] / a["max_10s_rate"] if a["max_10s_rate"] else float("nan")
        print(f"  {platform}: attack max_10s_rate={a['max_10s_rate']}, "
              f"benign max_10s_rate={b['max_10s_rate']} (benign reaches "
              f"{100*ratio:.1f}% of attack's peak rate)")

# ---------------------------------------------------------------------------
# 2c. Counterfactual swap machinery (prepared, not executed against a model)
# ---------------------------------------------------------------------------
print("\n=== 2c. Counterfactual swap value distributions (prepared for Phase 4) ===")
KEY_SWAP_FEATURES = [
    "ew_global_trail60m_alert_count", "ew_global_trail60m_max_rate_10s",
    "ew_global_trail60m_distinct_url_count", "ew_global_trail60m_path_repetition_ratio",
    "ew_user_trail60m_auth_failure_count", "ew_user_trail60m_auth_success_after_failure_flag",
    "ew_auth_after_webscan_flag", "ew_acctmgmt_after_auth_flag",
]
swap_medians = {}
for platform, (attack_src, benign_src) in PLATFORM_SOURCES.items():
    a = df[(df["source"] == attack_src) & (df["label"] == "attack")]
    b = df[df["source"] == benign_src]
    swap_medians[platform] = {
        feat: dict(attack_median=float(a[feat].median()), benign_median=float(b[feat].median()))
        for feat in KEY_SWAP_FEATURES
    }
    print(f"\n  {platform}:")
    for feat, v in swap_medians[platform].items():
        print(f"    {feat:<45} attack_median={v['attack_median']:>10.3f}  benign_median={v['benign_median']:>10.3f}")


def swap_to_benign_typical(frame, cols, benign_medians):
    """Counterfactual: replace `cols` with the collection's benign-typical
    (median) values on every row. Used in Phase 4 to test whether a
    detection survives with EW values scrubbed to look ordinary."""
    out = frame.copy()
    for c in cols:
        out[c] = benign_medians[c]
    return out


def swap_to_attack_typical(frame, cols, attack_medians):
    """Mirror control: replace `cols` with attack-typical (median) values on
    every BENIGN row. Used in Phase 4 to test whether FPR explodes."""
    out = frame.copy()
    for c in cols:
        out[c] = attack_medians[c]
    return out


# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
out_dir = os.path.join(HERE)

mi_rows = []
for platform in PLATFORM_SOURCES:
    for feat, mi in results[platform]["ew_mi"].items():
        mi_rows.append(dict(platform=platform, feature=feat, mi=mi, kind="EW"))
    for feat, mi in results[platform]["ref_mi"].items():
        bucket = "RULE-IDENTITY" if feat in RULE_IDENTITY_REF else "RULE-CORRELATED"
        mi_rows.append(dict(platform=platform, feature=feat, mi=mi, kind=bucket))
mi_df = pd.DataFrame(mi_rows).sort_values(["platform", "mi"], ascending=[True, False])
mi_df.to_csv(os.path.join(out_dir, "ew_phase2_mi_results.csv"), index=False)
print(f"\nwrote {os.path.join(out_dir, 'ew_phase2_mi_results.csv')}")

cond_mi_rows = []
for platform, r in cond_results.items():
    if "mi" not in r:
        continue
    for feat, mi in r["mi"].items():
        cond_mi_rows.append(dict(platform=platform, feature=feat, mi=mi, n=r["n"]))
pd.DataFrame(cond_mi_rows).to_csv(os.path.join(out_dir, "ew_phase2_mi_user_conditional.csv"), index=False)

with open(os.path.join(out_dir, "ew_phase2_burst_report.json"), "w") as f:
    json.dump(burst_report, f, indent=2)

with open(os.path.join(out_dir, "ew_phase2_swap_medians.json"), "w") as f:
    json.dump(swap_medians, f, indent=2)

with open(os.path.join(out_dir, "ew_phase2_class_balance.json"), "w") as f:
    json.dump(class_balance, f, indent=2)

print("\nPhase 2 audit script complete.")
