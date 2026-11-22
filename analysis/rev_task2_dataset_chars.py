#!/usr/bin/env python3
"""
REV-C Task 2 -- dataset characterisation numbers. Read-only over
newCol/xdet_wazuh_recovered_split.npz (per-alert rule.id/rule.description
already recovered by prior work) and data/ait_ads/raw/*_aminer.json.
Writes newCol/rev_dataset_characterisation.csv and rev_dataset_table.tex.
"""
import glob
import json
import os
from collections import Counter

import numpy as np
import pandas as pd

rec = np.load("analysis/xdet_wazuh_recovered_split.npz", allow_pickle=True)
rid_all, rdesc_all, y_all = rec["rid_all"], rec["rdesc_all"], rec["y_all"]
n_total = len(y_all)

df = pd.DataFrame({"rid": rid_all.astype(int), "rdesc": rdesc_all, "y": y_all})

# ---- top-10 rules by volume ------------------------------------------------
vol = df.groupby("rid").size().sort_values(ascending=False)
rows = []
for rid, n in vol.head(10).items():
    sub = df[df["rid"] == rid]
    n_desc = sub["rdesc"].nunique()
    if rid == 86601:
        desc = f"Suricata: Alert - <varies, {n_desc} distinct signatures under this rule.id>"
    else:
        # genuine Wazuh rules: description should be constant per rule.id;
        # verify, then use it, flagging if not actually constant.
        desc = sub["rdesc"].mode().iloc[0]
        if n_desc > 1:
            desc = f"{desc} [NOTE: {n_desc} distinct description strings seen for this rule.id]"
    atk = int(sub["y"].sum())
    ben = int(n - atk)
    rows.append({
        "rule_id": rid, "description": desc, "total_alerts": int(n),
        "attack_count": atk, "benign_count": ben,
        "attack_share_pct": round(100 * atk / n, 2),
    })

top10 = pd.DataFrame(rows)
print("=== Top 10 rules by volume ===")
print(top10.to_string(index=False))

# ---- AMiner distinct signature count (independent re-derivation) ----------
aminer_files = sorted(glob.glob("data/ait_ads/raw/*_aminer.json"))
aminer_names = Counter()
n_aminer = 0
for fp in aminer_files:
    with open(fp, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec_a = json.loads(line)
            except json.JSONDecodeError:
                continue
            n_aminer += 1
            name = (rec_a.get("AnalysisComponent") or {}).get("AnalysisComponentName")
            aminer_names[name] += 1
print(f"\nAMiner: n={n_aminer:,}  distinct AnalysisComponentName={len(aminer_names)}")

# ---- reconciliation numbers -------------------------------------------------
n_wazuh_total = n_total
n_86601 = int((df["rid"] == 86601).sum())
n_wazuh_native = n_wazuh_total - n_86601
n_rule_ids = df["rid"].nunique()
n_suricata_sigs = df.loc[df["rid"] == 86601, "rdesc"].nunique()

print(f"\nWazuh total: {n_wazuh_total:,}")
print(f"  rule.id==86601 (Suricata-via-Wazuh): {n_86601:,}  ({n_suricata_sigs} distinct rule.description)")
print(f"  Wazuh-native (rule.id!=86601): {n_wazuh_native:,}")
print(f"Distinct rule.id values (Wazuh's own namespace): {n_rule_ids}")

# ---- write CSV --------------------------------------------------------------
top10.to_csv("analysis/rev_dataset_characterisation.csv", index=False)
print("\nSaved newCol/rev_dataset_characterisation.csv")
