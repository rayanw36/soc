#!/usr/bin/env python3
"""
PURITY-V Task 1 -- volume-weighted class-purity distribution per detector,
replacing lbl_provenance.md #2c's binary exclusive/mixed partition (which
used purity==1.0 as its only "exclusive" threshold and buried 31101's
99.98%-attack, 68.5%-of-volume signature in a "mixed" bucket).

Read-only over newCol/xdet_wazuh_recovered_split.npz and
newCol/xdet_aminer_split.npz (both already-verified label sources, see
newCol/lbl_provenance.md Task 1e). No new collection, no retraining.
"""
import numpy as np
import pandas as pd

BANDS = [
    ("=1.0 (exclusive)", 1.0, 1.0 + 1e-12),
    ("[0.99, 1.0)", 0.99, 1.0),
    ("[0.95, 0.99)", 0.95, 0.99),
    ("[0.90, 0.95)", 0.90, 0.95),
    ("[0.75, 0.90)", 0.75, 0.90),
    ("<0.75", 0.0, 0.75),
]


def purity_table(sig, y, label):
    df = pd.DataFrame({"sig": sig, "y": y})
    g = df.groupby("sig")["y"].agg(["sum", "count"])
    g["attack"] = g["sum"].astype(int)
    g["benign"] = (g["count"] - g["sum"]).astype(int)
    g["n"] = g["count"].astype(int)
    g["p_attack"] = g["attack"] / g["n"]
    g["p_benign"] = g["benign"] / g["n"]
    g["purity"] = g[["p_attack", "p_benign"]].max(axis=1)
    g["direction"] = np.where(g["p_attack"] >= g["p_benign"], "attack-leaning", "benign-leaning")

    n_total = len(df)
    print(f"\n{'='*70}\n{label}  (n={n_total:,}, n_signatures={len(g)})\n{'='*70}")

    band_rows = []
    for name, lo, hi in BANDS:
        mask = (g["purity"] >= lo) & (g["purity"] < hi)
        vol = int(g.loc[mask, "n"].sum())
        n_sig = int(mask.sum())
        pct = 100 * vol / n_total if n_total else 0.0
        print(f"  {name:<18} n_sig={n_sig:>3}  volume={vol:>10,}  ({pct:6.2f}%)")
        band_rows.append(dict(band=name, n_sig=n_sig, volume=vol, pct=pct))

    exposure_99 = g.loc[g["purity"] >= 0.99, "n"].sum()
    exposure_99_pct = 100 * exposure_99 / n_total if n_total else 0.0
    print(f"\n  >>> purity >= 0.99 (label-proxy exposure): {exposure_99:,} / {n_total:,} "
          f"= {exposure_99_pct:.2f}%")

    top5 = g.sort_values("n", ascending=False).head(5)
    print(f"\n  Top 5 signatures by volume:")
    for sig_name, row in top5.iterrows():
        print(f"    {str(sig_name)[:70]:<70} n={row['n']:>10,}  purity={row['purity']:.4f}  {row['direction']}")

    return dict(label=label, n_total=n_total, n_signatures=len(g),
                bands=band_rows, exposure_99_pct=exposure_99_pct,
                top5=top5[["n", "purity", "direction", "attack", "benign"]].to_dict(orient="index"))


wz = np.load("analysis/xdet_wazuh_recovered_split.npz", allow_pickle=True)
rid_all, rdesc_all, y_all = wz["rid_all"], wz["rdesc_all"], wz["y_all"]
native_mask = rid_all != 86601
suricata_mask = rid_all == 86601

am = np.load("analysis/xdet_aminer_split.npz", allow_pickle=True)

results = {}
results["wazuh_native"] = purity_table(rid_all[native_mask], y_all[native_mask], "Wazuh-native (rule.id)")
results["suricata"] = purity_table(rdesc_all[suricata_mask], y_all[suricata_mask], "Suricata (rule.description, rule 86601)")
results["aminer"] = purity_table(am["name_all"], am["y_all"], "AMiner (AnalysisComponentName)")

import json


def jsonable(o):
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    return o


with open("analysis/purity_task1_results.json", "w") as f:
    json.dump(jsonable(results), f, indent=2)
print("\nSaved newCol/purity_task1_results.json")
