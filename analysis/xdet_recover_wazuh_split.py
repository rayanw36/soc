#!/usr/bin/env python3
"""
XDET support script — recover the exact train/test partition used to build
models_v2/ait_split.npz, WITHOUT recomputing the 26-dim feature vectors
(not needed: sklearn's stratified train_test_split only depends on
array length + the y values in original order, not on X). We reconstruct
y_all in original alert order via the same labels.csv/merge_asof logic as
phase1_xgboost.py:load_ait_ads, verify it reproduces y_train/y_test from
the saved split EXACTLY, and use the recovered index arrays to align
per-alert rule.id / rule.description (needed for Addition A / Task 1
Suricata-within-Wazuh analysis, which the 26-dim feature matrix cannot
provide because rule_id_encoded collapses all Suricata signatures under
rule 86601 to one value).

No retraining. No modification of any existing file. Read-only over
data/ait_ads/raw/*_wazuh.json and labels.csv.
"""
import glob
import json
import os
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, REPO_ROOT)
from shared_features import parse_timestamp  # noqa: E402
from shared_constants import SEED  # noqa: E402

RAW_DIR = _os.path.join(REPO_ROOT, "data", "ait_ads", "raw")
LABELS_CSV = _os.path.join(REPO_ROOT, "data", "ait_ads", "labels.csv")
SPLIT_PATH = _os.path.join(REPO_ROOT, "models_v2", "ait_split.npz")
OUT_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_wazuh_recovered_split.npz")


def main():
    labels = pd.read_csv(LABELS_CSV)
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*_wazuh.json")))
    assert files, "no wazuh files found"

    all_eps, all_scn, all_rid, all_rdesc = [], [], [], []
    for fp in files:
        scenario = os.path.basename(fp).replace("_wazuh.json", "")
        n = 0
        with open(fp, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = parse_timestamp(alert)
                rule = alert.get("rule") or {}
                all_eps.append(ts.timestamp() if ts is not None else np.nan)
                all_scn.append(scenario)
                all_rid.append(rule.get("id"))
                all_rdesc.append(rule.get("description"))
                n += 1
        print(f"  {scenario:16s} {n:>8,} alerts", flush=True)

    n_total = len(all_eps)
    print(f"Total alerts read: {n_total:,}", flush=True)

    df = pd.DataFrame({
        "epoch": all_eps,
        "scenario": all_scn,
    })
    df["label"] = 0
    for scenario, wins in labels.groupby("scenario"):
        mask = df["scenario"] == scenario
        if not mask.any():
            continue
        sub = df.loc[mask, ["epoch"]].copy().reset_index()
        sub = sub.sort_values("epoch")
        w = wins.sort_values("start")[["start", "end"]].reset_index(drop=True)
        merged = pd.merge_asof(
            sub, w.rename(columns={"start": "epoch"}),
            on="epoch", direction="backward",
        )
        is_attack = (merged["epoch"] <= merged["end"]) & merged["end"].notna()
        idx = merged.loc[is_attack.values, "index"].values
        df.loc[idx, "label"] = 1

    y_all = df["label"].values.astype(int)
    rid_all = np.array([int(r) if r is not None else -1 for r in all_rid], dtype=np.int64)
    rdesc_all = np.array(all_rdesc, dtype=object)

    print(f"Attack ratio (recomputed): {y_all.mean():.4f} "
          f"(attack={y_all.sum():,}, benign={(y_all==0).sum():,})", flush=True)

    # Recover the exact split via the SAME call signature as phase1_xgboost.py
    idx_all = np.arange(n_total)
    idx_train, idx_test, y_train_chk, y_test_chk = train_test_split(
        idx_all, y_all, test_size=0.20, stratify=y_all, random_state=SEED)

    # Verify against the saved split
    saved = np.load(SPLIT_PATH, allow_pickle=True)
    y_train_saved = saved["y_train"]
    y_test_saved = saved["y_test"]

    match_train = np.array_equal(y_train_chk, y_train_saved)
    match_test = np.array_equal(y_test_chk, y_test_saved)
    print(f"y_train shapes: recomputed={y_train_chk.shape} saved={y_train_saved.shape} match={match_train}")
    print(f"y_test  shapes: recomputed={y_test_chk.shape}  saved={y_test_saved.shape}  match={match_test}")

    if not (match_train and match_test):
        print("[FATAL] Recovered split does NOT match saved ait_split.npz. "
              "Aborting — do not trust downstream index alignment.", flush=True)
        sys.exit(1)

    print("[OK] Recovered split is byte-identical to models_v2/ait_split.npz. "
          "Index alignment is trustworthy.", flush=True)

    np.savez_compressed(
        OUT_NPZ,
        idx_train=idx_train, idx_test=idx_test,
        y_all=y_all, rid_all=rid_all, rdesc_all=rdesc_all,
        scn_all=np.array(all_scn, dtype=object),
        eps_all=np.array(all_eps, dtype=np.float64),
    )
    print(f"Saved {OUT_NPZ}", flush=True)


if __name__ == "__main__":
    main()
