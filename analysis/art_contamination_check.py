"""
art_contamination_check.py -- ART-C Task 3/4: path-match benign-window FIM
alerts (and the specific 29 v5-defer false positives) against the exact
persistence-artifact paths/names recovered from newCol/audit_lnxdmz.log
(Task 1), and compute inter-arrival intervals for the affected rules
(Task 4). ANALYSIS ONLY -- no retraining, no new collection, reuses the
existing production scoring path exactly as f1_phaseA_v5defer.py does.
"""
import json
import sys

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from f1_phaseA_lnx import extract_benign_features
from combined_decision_v6 import load_production_models, score_alert
from shared_constants_v2 import FEATURE_COLS_V2

HERE = "newCol"

# --- Task 1 artifact list (round 6 fully confirmed, round 5 T1136.001 leg
#     confirmed, from newCol/audit_lnxdmz.log; see art_contamination_check.md
#     Task 1 for the exact line-number citations) -----------------------
ARTIFACT_EXACT = {
    "/etc/cron.d/col_cron": "T1053.003 (cron)",
    "/etc/systemd/system/col_svc.service": "T1543.002 (systemd)",
    "/etc/profile.d/col_profile.sh": "T1546.004 (shell-rc)",
    "/root/.ssh/authorized_keys": "T1098.004 (ssh-keys)",  # exact path, but
    # content-tagged (COLLECTNOVEL marker) -- see md for the distinction
}
ARTIFACT_DIR_PREFIXES = {
    "/etc/cron.d/": "T1053.003 (cron) -- directory class",
    "/etc/systemd/system/": "T1543.002 (systemd) -- directory class",
    "/etc/profile.d/": "T1546.004 (shell-rc) -- directory class",
    "/root/.ssh/": "T1098.004 (ssh-keys) -- directory class",
    "/home/coluser": "T1136.001 (create-user) -- directory class",
}
ACCOUNT_NAME = "coluser"
CONTENT_MARKER = "COLLECTNOVEL"  # tag used to surgically sed-delete the ssh key line

# --- load production v5-defer models (identical config to f1_phaseA_v5defer.py) --
models = load_production_models()
oc_v5 = joblib.load("models_v2/ocsvm_nu05.pkl")
models_v5 = dict(models)
models_v5["ocsvm"] = oc_v5

Xb = extract_benign_features()

raw = []
with open(f"{HERE}/collection_benign_lnx_alerts.json") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        raw.append(json.loads(line))
assert len(raw) == len(Xb), f"{len(raw)} raw alerts vs {len(Xb)} feature rows"


def production_fp(df):
    fp = []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, models_v5)
        fp.append(r["decision"] != "P4_suppress")  # benign set -> any positive is FP
    return np.array(fp, bool)


fp_flags = production_fp(Xb)
print(f"total benign alerts: {len(Xb)}   total FPs (production v5-defer combined): {int(fp_flags.sum())}")

rows = []
for i, a in enumerate(raw):
    rid = a.get("rule", {}).get("id")
    sc = a.get("syscheck", {})
    path = sc.get("path")
    full_log = a.get("full_log", "") or ""
    blob = json.dumps(a)

    bucket = "unrelated"
    matched_artifact = ""

    if path:
        if path in ARTIFACT_EXACT:
            bucket = "exact_match"
            matched_artifact = ARTIFACT_EXACT[path]
        else:
            for prefix, label in ARTIFACT_DIR_PREFIXES.items():
                if path.startswith(prefix):
                    bucket = "directory_class_only"
                    matched_artifact = label
                    break

    references_account = ACCOUNT_NAME in blob
    references_content_marker = CONTENT_MARKER in blob
    if references_account or references_content_marker:
        bucket = "exact_match"
        matched_artifact = (matched_artifact + " + ") if matched_artifact else ""
        matched_artifact += "account_name_or_marker_reference"

    rows.append(dict(
        idx=i,
        rule_id=rid,
        timestamp=a.get("timestamp"),
        syscheck_path=path,
        syscheck_event=sc.get("event"),
        is_fp=bool(fp_flags[i]),
        bucket=bucket,
        matched_artifact=matched_artifact,
    ))

df = pd.DataFrame(rows)
df.to_csv(f"{HERE}/art_contamination_paths.csv", index=False)
print(f"wrote {HERE}/art_contamination_paths.csv")

print("\n=== bucket counts, ALL benign alerts (n=%d) ===" % len(df))
print(df.bucket.value_counts())

print("\n=== bucket counts, FIM-rule alerts only (550/553/554) ===")
fim = df[df.rule_id.isin(["550", "553", "554"])]
print(fim[["rule_id", "timestamp", "syscheck_path", "syscheck_event", "is_fp", "bucket"]]
      .to_string(index=False))

print("\n=== bucket counts, the 29 v5-defer FALSE POSITIVES specifically ===")
fps = df[df.is_fp]
print(f"n FPs = {len(fps)}")
print(fps.bucket.value_counts())
print(fps[["rule_id", "timestamp", "syscheck_path", "bucket"]].to_string(index=False))

print("\n=== Task 4: inter-arrival intervals, rules 550/553/554 (chronological) ===")
fim_sorted = fim.sort_values("timestamp")
ts = pd.to_datetime(fim_sorted["timestamp"])
deltas = ts.diff().dt.total_seconds().tolist()
for (_, row), d in zip(fim_sorted.iterrows(), deltas):
    print(f"  {row.timestamp}  rule={row.rule_id:<5} path={row.syscheck_path:<40} "
          f"delta_from_prev={'' if d is None or pd.isna(d) else f'{d:.3f}s'}")

print("\n=== Task 3d: any benign alert (any rule) referencing account name '%s' ===" % ACCOUNT_NAME)
acct_hits = df[df.matched_artifact.str.contains("account_name", na=False)]
print(f"n = {len(acct_hits)}")
