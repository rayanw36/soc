#!/usr/bin/env python3
"""
XDET-V Task 1 -- is AMiner's dominant signature ("AMiner: New request
method in Apache Access log.") a labelling artefact (like Wazuh rule
31101) or a genuine detector?

Same test discipline as fr_31101_report.md, adapted to AMiner's schema:
extract non-identity features from the raw Apache access-log line AMiner
embeds in RawLogData, label via the same labels.csv time-window method
used throughout this audit, and check whether attack- and
benign-labelled alerts of this one signature are distinguishable on
those features. No model retrained beyond what's needed for a simple
separability check; distributions are reported directly given the small
benign n.
"""
import glob
import json
import re
import sys
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
from collections import Counter

import numpy as np
import pandas as pd

sys.path.insert(0, REPO_ROOT)

RAW_DIR = _os.path.join(REPO_ROOT, "data", "ait_ads", "raw")
LABELS_CSV = _os.path.join(REPO_ROOT, "data", "ait_ads", "labels.csv")
SIG = "AMiner: New request method in Apache Access log."

APACHE_RE = re.compile(
    r'^(?:\S+\s+)?(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+)(?:\s+(?P<path>\S+)\s+(?P<proto>\S+))?" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_apache_line(raw):
    if raw is None:
        return {}
    m = APACHE_RE.match(raw)
    if not m:
        return {"parse_failed": True, "raw_len": len(raw)}
    d = m.groupdict()
    d["parse_failed"] = False
    return d


def main():
    files = sorted(glob.glob(f"{RAW_DIR}/*_aminer.json"))
    labels = pd.read_csv(LABELS_CSV)

    records = []
    for fp in files:
        scenario = fp.split("/")[-1].replace("_aminer.json", "")
        with open(fp, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                a = json.loads(line)
                name = (a.get("AnalysisComponent") or {}).get("AnalysisComponentName")
                if name != SIG:
                    continue
                ld = a.get("LogData") or {}
                raw = (ld.get("RawLogData") or [None])[0]
                ts = (ld.get("DetectionTimestamp") or [None])[0]
                training = a.get("AnalysisComponent", {}).get("TrainingMode")
                records.append(dict(scenario=scenario, raw=raw, epoch=float(ts) if ts else np.nan,
                                     training_mode=training))

    print(f"=== a. Signature identification ===")
    print(f"Field: AnalysisComponent.AnalysisComponentName == {SIG!r}")
    print(f"Total alert count: {len(records):,}")

    df = pd.DataFrame(records)

    # ---- label via labels.csv time-window, same discipline as elsewhere --
    df["label"] = 0
    for scenario, wins in labels.groupby("scenario"):
        mask = df["scenario"] == scenario
        if not mask.any():
            continue
        sub = df.loc[mask, ["epoch"]].copy().reset_index()
        sub = sub.sort_values("epoch")
        w = wins.sort_values("start")[["start", "end"]].reset_index(drop=True)
        merged = pd.merge_asof(sub, w.rename(columns={"start": "epoch"}), on="epoch", direction="backward")
        is_attack = (merged["epoch"] <= merged["end"]) & merged["end"].notna()
        idx = merged.loc[is_attack.values, "index"].values
        df.loc[idx, "label"] = 1

    n_attack = int((df["label"] == 1).sum())
    n_benign = int((df["label"] == 0).sum())
    ratio = n_attack / n_benign if n_benign else float("inf")
    print(f"Attack count: {n_attack:,}  Benign count: {n_benign:,}  "
          f"Ratio: {ratio:.2f}:1")

    print(f"\n=== b. Benign denominator ===")
    print(f"Benign n = {n_benign}. ", end="")
    if n_benign < 100:
        print("SMALL -- distributions will be reported directly, no classifier metrics fit.")
    else:
        print("Large enough for a simple separability check.")

    # ---- c. non-identity fields available ---------------------------------
    print(f"\n=== c. Non-identity fields available on these alerts ===")
    print("From LogData.RawLogData (the embedded Apache combined-log line): "
          "client IP, timestamp, HTTP method, path, protocol, status code, "
          "response size, referrer, user-agent.")
    print("From the AMiner envelope: DetectionTimestamp, TrainingMode flag, "
          "AMiner.ID (monitored host), LogResources (source log file).")
    print("NOT available: any Wazuh-style rule metadata, severity/level, "
          "MITRE tactic, or agent criticality -- none of the 26-feature "
          "Wazuh pipeline's fields exist for AMiner alerts.")

    parsed = df["raw"].apply(parse_apache_line).apply(pd.Series)
    df = pd.concat([df, parsed], axis=1)
    n_parse_failed = int(df["parse_failed"].sum())
    print(f"Apache line parse failures: {n_parse_failed} / {len(df)} "
          f"({100 * n_parse_failed / len(df):.2f}%)")

    df["status"] = pd.to_numeric(df["status"], errors="coerce")
    df["size_num"] = pd.to_numeric(df["size"], errors="coerce")
    df["ua_len"] = df["ua"].astype(str).str.len()
    df["path_len"] = df["path"].astype(str).str.len()
    df["is_root_path"] = (df["path"] == "/").astype(int)

    print(f"\n=== d. Distinguishability on non-identity features "
          f"(attack n={n_attack}, benign n={n_benign}) ===")
    for col in ["method", "status", "size_num", "ua_len", "path_len"]:
        atk = df.loc[df.label == 1, col]
        ben = df.loc[df.label == 0, col]
        if col == "method":
            print(f"\n  method -- attack top5: {Counter(atk).most_common(5)}")
            print(f"  method -- benign top5:  {Counter(ben).most_common(5)}")
        else:
            print(f"\n  {col}: attack mean={atk.mean():.2f} median={atk.median():.2f} "
                  f"| benign mean={ben.mean():.2f} median={ben.median():.2f}")

    atk_ua_n = df.loc[df.label == 1, 'ua'].nunique()
    ben_ua_n = df.loc[df.label == 0, 'ua'].nunique()
    print(f"\n  distinct UAs -- attack: {atk_ua_n}  benign: {ben_ua_n}")
    print(f"  distinct paths -- attack: {df.loc[df.label==1,'path'].nunique()}  "
          f"benign: {df.loc[df.label==0,'path'].nunique()}")

    ua_overlap = set(df.loc[df.label==1,'ua'].dropna()) & set(df.loc[df.label==0,'ua'].dropna())
    print(f"  UA strings shared between attack and benign: {len(ua_overlap)} -> {sorted(ua_overlap)[:10]}")

    # ---- e. training-phase overlap -----------------------------------------
    print(f"\n=== e. Training-phase check (first 12h of scenario) ===")
    day0_start = df.groupby("scenario")["epoch"].transform("min")
    df["in_training_phase"] = (df["epoch"] - day0_start) <= 12 * 3600
    ben_df = df[df.label == 0]
    n_ben_train = int(ben_df["in_training_phase"].sum())
    print(f"  Benign alerts in first-12h-of-scenario window: {n_ben_train} / {n_benign} "
          f"({100*n_ben_train/n_benign:.1f}%)")
    print(f"  AMiner's own TrainingMode=True flag set on: "
          f"{int(ben_df['training_mode'].sum())} / {n_benign} benign alerts")
    print(f"  (all-data) TrainingMode=True count: {int(df['training_mode'].sum())} / {len(df)}")

    print(f"\n  WITHOUT first-12h window (benign n={n_benign - n_ben_train}):")
    ben_excl = ben_df[~ben_df["in_training_phase"]]
    if len(ben_excl) > 0:
        print(f"    status: mean={ben_excl['status'].mean():.2f}  "
              f"method top3: {Counter(ben_excl['method']).most_common(3)}")
    else:
        print("    (zero benign alerts remain outside the training-phase window)")

    df.to_csv(_os.path.join(REPO_ROOT, "analysis", "xdet_aminer_dominant_sig_records.csv"), index=False)
    print(f"\nSaved newCol/xdet_aminer_dominant_sig_records.csv ({len(df)} rows)")


if __name__ == "__main__":
    main()
