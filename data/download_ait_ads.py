#!/usr/bin/env python3
"""
data/download_ait_ads.py -- check for (and optionally fetch) the AIT-ADS
raw alert data this project's analysis scripts expect at
data/ait_ads/raw/*_{wazuh,aminer}.json and data/ait_ads/labels.csv.

This script deliberately does NOT hardcode a download URL: at the time
this repository was prepared, the AIT-ADS paper's DOI
(10.1145/3675741.3675748) resolves to the paper itself, not a verified
direct file link, and no fabricated URL is worth shipping in a public
repo. See data/README.md for the citation and where to look.

Usage:
  python data/download_ait_ads.py --check          # report what's missing
  python data/download_ait_ads.py --url <URL> --extract-to data/ait_ads/downloads
                                                     # download + unzip once you have a URL
"""
import argparse
import os
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
AIT_DIR = os.path.join(HERE, "ait_ads")
RAW_DIR = os.path.join(AIT_DIR, "raw")
LABELS_CSV = os.path.join(AIT_DIR, "labels.csv")

SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]


def check():
    missing = []
    if not os.path.isfile(LABELS_CSV):
        missing.append(LABELS_CSV)
    for scn in SCENARIOS:
        for suffix in ("_wazuh.json", "_aminer.json"):
            p = os.path.join(RAW_DIR, scn + suffix)
            if not os.path.isfile(p):
                missing.append(p)

    if not missing:
        print("AIT-ADS raw data: all expected files present.")
        return True

    print(f"AIT-ADS raw data: {len(missing)} expected file(s) missing.")
    for m in missing:
        print(f"  missing: {os.path.relpath(m, HERE)}")
    print("\nSee data/README.md for the dataset citation and where to obtain it.")
    print("Analysis steps that need this data will be skipped by reproduce.sh, not failed silently.")
    return False


def download_and_extract(url: str, extract_to: str):
    os.makedirs(extract_to, exist_ok=True)
    zip_path = os.path.join(extract_to, "ait_ads.zip")
    print(f"Downloading {url} -> {zip_path} ...")
    urllib.request.urlretrieve(url, zip_path)
    print(f"Extracting to {RAW_DIR} ...")
    os.makedirs(RAW_DIR, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(RAW_DIR)
    print("Done. Re-run with --check to verify.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report which expected files are missing")
    ap.add_argument("--url", help="direct download URL for the AIT-ADS archive, once you have one (see data/README.md)")
    ap.add_argument("--extract-to", default=os.path.join(AIT_DIR, "downloads"))
    args = ap.parse_args()

    if args.url:
        download_and_extract(args.url, args.extract_to)
        sys.exit(0)

    ok = check()
    sys.exit(0 if ok else 1)
