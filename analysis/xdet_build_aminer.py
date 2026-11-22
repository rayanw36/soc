#!/usr/bin/env python3
"""
XDET support script — stream all *_aminer.json files, label via the same
labels.csv time-window / merge_asof discipline as the Wazuh loader
(phase1_xgboost.py:load_ait_ads), and produce a fresh 80/20 stratified
split (same SEED, same test_size, since AMiner was never part of the
original ait_split.npz — there is no split to "recover" for it, so this
is disclosed as a freshly-constructed split, not a recovery).

No feature extraction (AMiner never went through extract_features_v2 in
any deployed pipeline — nothing to recover). Schema-independent: only
epoch timestamp, scenario, and AnalysisComponentName (the signature key)
are used, per the XDET brief.
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
from shared_constants import SEED  # noqa: E402


def _aminer_epoch(alert):
    """AMiner records have no top-level timestamp (unlike Wazuh's
    '@timestamp'); the detection time lives under LogData.
    DetectionTimestamp (falls back to Timestamps[0])."""
    ld = alert.get("LogData") or {}
    for key in ("DetectionTimestamp", "Timestamps"):
        vals = ld.get(key)
        if vals:
            try:
                return float(vals[0])
            except (TypeError, ValueError, IndexError):
                continue
    return np.nan

RAW_DIR = _os.path.join(REPO_ROOT, "data", "ait_ads", "raw")
LABELS_CSV = _os.path.join(REPO_ROOT, "data", "ait_ads", "labels.csv")
OUT_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_aminer_split.npz")


def main():
    labels = pd.read_csv(LABELS_CSV)
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*_aminer.json")))
    assert files, "no aminer files found"

    all_eps, all_scn, all_name = [], [], []
    for fp in files:
        scenario = os.path.basename(fp).replace("_aminer.json", "")
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
                ep = _aminer_epoch(alert)
                comp = (alert.get("AnalysisComponent") or {}).get("AnalysisComponentName")
                all_eps.append(ep)
                all_scn.append(scenario)
                all_name.append(comp)
                n += 1
        print(f"  {scenario:16s} {n:>8,} alerts", flush=True)

    n_total = len(all_eps)
    print(f"Total AMiner alerts read: {n_total:,}", flush=True)

    df = pd.DataFrame({"epoch": all_eps, "scenario": all_scn})
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
    name_all = np.array(all_name, dtype=object)
    scn_all = np.array(all_scn, dtype=object)
    eps_all = np.array(all_eps, dtype=np.float64)

    print(f"Attack ratio: {y_all.mean():.4f} "
          f"(attack={y_all.sum():,}, benign={(y_all==0).sum():,})", flush=True)
    print(f"Distinct AnalysisComponentName values: {len(set(all_name))}", flush=True)

    idx_all = np.arange(n_total)
    idx_train, idx_test = train_test_split(
        idx_all, test_size=0.20, stratify=y_all, random_state=SEED)

    np.savez_compressed(
        OUT_NPZ,
        idx_train=idx_train, idx_test=idx_test,
        y_all=y_all, name_all=name_all, scn_all=scn_all, eps_all=eps_all,
    )
    print(f"Saved {OUT_NPZ}", flush=True)
    print("NOTE: this is a freshly-constructed 80/20 stratified split "
          "(same test_size/SEED convention as the Wazuh split), NOT a "
          "recovery of any existing deployed split -- AMiner was never "
          "part of models_v2/ait_split.npz.", flush=True)


if __name__ == "__main__":
    main()
