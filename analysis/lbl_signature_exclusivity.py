#!/usr/bin/env python3
"""
LBL Task 2c -- per-detector signature exclusivity (attack-only / benign-only
/ both), with volumes. Read-only over newCol/xdet_wazuh_recovered_split.npz
and newCol/xdet_aminer_split.npz (both already-verified label sources,
themselves built from data/ait_ads/labels.csv via the same time-window
merge_asof join -- see newCol/lbl_provenance.md Task 1e). Also reports
per-detector alert/attack counts for Task 1b.
"""
import numpy as np
import pandas as pd
from collections import Counter

wz = np.load("analysis/xdet_wazuh_recovered_split.npz", allow_pickle=True)
rid_all, rdesc_all, y_all, scn_all = wz["rid_all"], wz["rdesc_all"], wz["y_all"], wz["scn_all"]
native_mask = rid_all != 86601
suricata_mask = rid_all == 86601

am = np.load("analysis/xdet_aminer_split.npz", allow_pickle=True)
am_name, am_y = am["name_all"], am["y_all"]


def exclusivity(sig, y, label):
    df = pd.DataFrame({"sig": sig, "y": y})
    g = df.groupby("sig")["y"].agg(["sum", "count"])
    g["attack"] = g["sum"].astype(int)
    g["benign"] = (g["count"] - g["sum"]).astype(int)
    attack_only = g[(g["attack"] > 0) & (g["benign"] == 0)]
    benign_only = g[(g["attack"] == 0) & (g["benign"] > 0)]
    both = g[(g["attack"] > 0) & (g["benign"] > 0)]
    n_total = len(df)
    print(f"\n=== {label} ===")
    print(f"  n_alerts={n_total:,}  n_signatures={len(g)}  attack_rate={y.mean():.4f}")
    print(f"  attack-only signatures: {len(attack_only):>3}  covering {attack_only['count'].sum():>10,} alerts "
          f"({100*attack_only['count'].sum()/n_total:.2f}%)")
    print(f"  benign-only signatures: {len(benign_only):>3}  covering {benign_only['count'].sum():>10,} alerts "
          f"({100*benign_only['count'].sum()/n_total:.2f}%)")
    print(f"  mixed (both) signatures: {len(both):>3}  covering {both['count'].sum():>10,} alerts "
          f"({100*both['count'].sum()/n_total:.2f}%)")
    return dict(n_total=n_total, n_sig=len(g),
                attack_only_n_sig=len(attack_only), attack_only_alerts=int(attack_only["count"].sum()),
                benign_only_n_sig=len(benign_only), benign_only_alerts=int(benign_only["count"].sum()),
                both_n_sig=len(both), both_alerts=int(both["count"].sum()),
                attack_only_table=attack_only.sort_values("count", ascending=False),
                benign_only_table=benign_only.sort_values("count", ascending=False),
                both_table=both.sort_values("count", ascending=False))


r_native = exclusivity(rid_all[native_mask], y_all[native_mask], "Wazuh-native (rule.id != 86601)")
r_suricata = exclusivity(rdesc_all[suricata_mask], y_all[suricata_mask], "Suricata (rule.description, rule.id==86601)")
r_aminer = exclusivity(am_name, am_y, "AMiner (AnalysisComponentName)")

print("\n\n=== Wazuh-native attack-only rule table ===")
print(r_native["attack_only_table"][["attack", "benign", "count"]].to_string())
print("\n=== Wazuh-native benign-only rule table (top 15 by volume) ===")
print(r_native["benign_only_table"][["attack", "benign", "count"]].head(15).to_string())
print("\n=== Wazuh-native mixed rule table ===")
print(r_native["both_table"][["attack", "benign", "count"]].to_string())

print("\n\n=== Suricata attack-only signature table ===")
print(r_suricata["attack_only_table"][["attack", "benign", "count"]].to_string())
print("\n=== Suricata benign-only signature table (top 15 by volume) ===")
print(r_suricata["benign_only_table"][["attack", "benign", "count"]].head(15).to_string())
print("\n=== Suricata mixed signature table ===")
print(r_suricata["both_table"][["attack", "benign", "count"]].to_string())

print("\n\n=== AMiner attack-only signature table ===")
print(r_aminer["attack_only_table"][["attack", "benign", "count"]].to_string())
print("\n=== AMiner benign-only signature table ===")
print(r_aminer["benign_only_table"][["attack", "benign", "count"]].to_string())
print("\n=== AMiner mixed signature table ===")
print(r_aminer["both_table"][["attack", "benign", "count"]].to_string())

# ---- per-scenario AMiner attack-rate sanity check (is the high attack rate real?) --
df_am = pd.DataFrame({"scn": am["scn_all"], "y": am_y})
print("\n\n=== AMiner attack rate per scenario (sanity check on the high overall rate) ===")
print(df_am.groupby("scn")["y"].agg(["mean", "count"]).to_string())
