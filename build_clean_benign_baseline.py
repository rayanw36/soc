"""
build_clean_benign_baseline.py
==============================
TASK 3 of the MemAE-inversion fix.

phase2_memae.py trained MemAE on (AIT-ADS benign) + (lnx-dmz benign = everything
outside ATTACK_WINDOWS_LNX).  The lnx-dmz portion is contaminated by sudo / PAM /
AppArmor churn (see investigate_t1548003_contamination.py).  This script rebuilds
a cleaned lnx-dmz benign baseline using the corrected 14-window list and explicit
contamination exclusions, fully auditable via a diff file.

NOTE on scope: the AIT-ADS benign portion (706k web-traffic alerts from
ait_split.npz) is NOT contaminated and is huge, so it is left untouched and
re-attached at train time by phase2_memae_v2.py.  This CSV is the *lnx-dmz*
benign portion -- the part that actually carried the contamination -- cleaned.
This isolates the effect of the fix.

Run:  ~/soc_project/.venv/bin/python build_clean_benign_baseline.py
"""

import json
from datetime import timedelta

import numpy as np
import pandas as pd

# corrected 14-window list
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2
import shared_features
# make load/label helpers use the corrected windows
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import (
    _parse_iso, _get, AgentHistory, extract_features_v2,
    parse_timestamp, assign_label, assign_phase,
)

LNX_FILE = "lnx_dmz_ai_detections.json"
RESULTS = "results_v2"

# contamination rule families (the "sudo/PAM/AppArmor churn" named in the report)
SUDO_IDS = {"5401", "5402", "5403"}        # failed/successful sudo, sudo violation
PAM_FAIL_IDS = {"5503"}                     # PAM: user login failed
APPARMOR_IDS = {"52002"}                    # AppArmor DENIED
NOISE_IDS = SUDO_IDS | PAM_FAIL_IDS | APPARMOR_IDS
BUFFER_S = 60                               # +/- buffer around every window edge


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


# ---------------------------------------------------------------------------
# Load every lnx alert (full history -- matches what phase2 trained on),
# carrying rule.id + description so the diff is auditable.
# ---------------------------------------------------------------------------
hr("LOAD lnx-dmz ALERTS (full history) WITH CORRECTED 14-WINDOW LABELS")
recs = []
with open(LNX_FILE, errors="ignore") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        oa = rec.get("original_alert", rec)
        ts = parse_timestamp(rec.get("timestamp")) or parse_timestamp(oa)
        if ts is None:
            continue
        recs.append((ts, oa, _get(oa, "agent", "name", default="unknown")))
recs.sort(key=lambda r: r[0])

# window edges for buffer test
edges = []
for _, _, s, e in ATTACK_WINDOWS_LNX_V2:
    edges.append(_parse_iso(s)); edges.append(_parse_iso(e))
spans = [(_parse_iso(s), _parse_iso(e)) for _, _, s, e in ATTACK_WINDOWS_LNX_V2]


def near_edge(ts):
    return any(abs((ts - edge).total_seconds()) <= BUFFER_S for edge in edges)


def in_window(ts):
    return any(s <= ts <= e for s, e in spans)


histories = {}
rows = []
for ts, oa, agent in recs:
    hist = histories.setdefault(agent, AgentHistory())
    hfeat = hist.compute_features(ts)
    feats = extract_features_v2(oa, hfeat)
    hist.add(oa, ts)
    rows.append(dict(
        timestamp=ts,
        rule_id=str(_get(oa, "rule", "id", default="") or ""),
        rule_description=str(_get(oa, "rule", "description", default="") or ""),
        label=assign_label(ts, ATTACK_WINDOWS_LNX_V2),
        phase=assign_phase(ts),
        **dict(zip(FEATURE_COLS_V2, feats)),
    ))
df = pd.DataFrame(rows)
print(f"  total lnx alerts: {len(df)}")
print(f"  labelled attack (in any of 14 windows): {(df.label==1).sum()}")
print(f"  labelled benign                       : {(df.label==0).sum()}")


# ---------------------------------------------------------------------------
# Original benign pool (phase2 definition: label==0 with corrected windows)
# then apply contamination exclusions.
# ---------------------------------------------------------------------------
hr("APPLY CONTAMINATION EXCLUSIONS")
benign = df[df.label == 0].copy()
N = len(benign)

reason = []
for _, r in benign.iterrows():
    rid = r["rule_id"]
    if rid in SUDO_IDS:
        reason.append("sudo_churn (5401/5402/5403)")
    elif rid in PAM_FAIL_IDS:
        reason.append("pam_login_failed (5503)")
    elif rid in APPARMOR_IDS:
        reason.append("apparmor_denied (52002)")
    elif near_edge(r["timestamp"]):
        reason.append(f"within_{BUFFER_S}s_of_window_edge")
    else:
        reason.append("")          # keep
benign["removal_reason"] = reason

removed = benign[benign.removal_reason != ""].copy()
clean = benign[benign.removal_reason == ""].copy()
M = len(removed)

print(f"  Original benign pool: {N}")
print(f"  After exclusions    : {len(clean)}")
print(f"  Removed             : {M}  ({100*M/max(N,1):.1f}%)")
print("\n  Removed breakdown by reason:")
for rsn, c in removed.removal_reason.value_counts().items():
    print(f"      {c:5d}  {rsn}")
# narrow comparison: what the task's literal [5402,5403]-only rule would remove
narrow = (benign.rule_id.isin({"5402", "5403"})).sum()
print(f"\n  (For reference, the narrow [5402,5403]-only rule would remove just {narrow}.")
print(f"   We additionally remove 5401 sudo-fail, 5503 PAM-fail and 52002 AppArmor")
print(f"   because the report explicitly names 'sudo/PAM/AppArmor churn' -- every")
print(f"   removal is itemised in benign_baseline_diff.csv for audit.)")


# ---------------------------------------------------------------------------
# Save outputs
# ---------------------------------------------------------------------------
hr("SAVE CLEANED BASELINE + DIFF")
clean_out = clean[FEATURE_COLS_V2].copy()
clean_out.to_csv(f"{RESULTS}/benign_baseline_clean.csv", index=False)
print(f"  Saved {RESULTS}/benign_baseline_clean.csv  "
      f"({len(clean_out)} rows x {len(FEATURE_COLS_V2)} features)")

diff_out = removed[["timestamp", "rule_id", "rule_description", "removal_reason"]].copy()
diff_out.to_csv(f"{RESULTS}/benign_baseline_diff.csv", index=False)
print(f"  Saved {RESULTS}/benign_baseline_diff.csv  ({len(diff_out)} removed alerts)")

# tiny manifest so the next script knows the sizes without recomputing
with open(f"{RESULTS}/_benign_clean_manifest.json", "w") as fh:
    json.dump({"original_benign_pool": int(N), "clean_benign": int(len(clean)),
               "removed": int(M), "removed_pct": round(100*M/max(N, 1), 1),
               "narrow_5402_5403_only": int(narrow)}, fh, indent=2)
print(f"  Saved {RESULTS}/_benign_clean_manifest.json")
