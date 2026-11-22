#!/usr/bin/env python3
"""
data/download_ait_ads.py -- fetch and verify the AIT Alert Data Set (AIT-ADS) that this
project's AIT-ADS-dependent analysis scripts expect at

    data/ait_ads/raw/<scenario>_{wazuh,aminer}.json     (8 scenarios x 2 files)
    data/ait_ads/labels.csv

AIT-ADS: Landauer, Skopik, Wurzenberger. Zenodo, DOI 10.5281/zenodo.8263181, licence
Creative Commons Attribution 4.0 International. Cite the two papers listed in data/README.md.

Usage:
  python data/download_ait_ads.py --check            # all 17 files present with the expected size
  python data/download_ait_ads.py --check --full     # also verify every md5 (reads about 2.9 GB)
  python data/download_ait_ads.py --download         # download (about 96 MB zip), verify, extract
  python data/download_ait_ads.py --download --dest /some/dir   # use another folder than data/ait_ads

Exit status is 0 when the check passes and 1 otherwise; reproduce.sh uses this to decide which
steps to run.

Checksums. The archive and labels.csv checksums are the ones published on the Zenodo record
(ait_ads.zip md5 43db6b1f0996e0024befd617706c50e9, labels.csv md5 60ff33796c77fd2136c4d1a4bc841bd9).
The per-file sizes and md5 values of the 16 JSON files below were computed from that verified archive.
"""
import argparse
import hashlib
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DEST = os.path.join(HERE, "ait_ads")

ZENODO_RECORD = "8263181"
ZIP_URL = f"https://zenodo.org/records/{ZENODO_RECORD}/files/ait_ads.zip?download=1"
# the API "content" URL is the reliable one for the small file (the records/... form returned HTTP 5xx)
LABELS_URL = f"https://zenodo.org/api/records/{ZENODO_RECORD}/files/labels.csv/content"
ZIP_MD5, ZIP_SIZE = "43db6b1f0996e0024befd617706c50e9", 96202946

# file -> (size in bytes, md5)
RAW_FILES = {
    "fox_aminer.json": (8879125, "b0c0295a281d93ad1a8e0c92e46f14a9"),
    "fox_wazuh.json": (491410473, "7cc84c4cd8ba15af0208cea43e72c00b"),
    "harrison_aminer.json": (8693273, "01859f26be2f529dbb7444d0610018de"),
    "harrison_wazuh.json": (632912134, "28b1e9d1d25863c159864596c6015d56"),
    "russellmitchell_aminer.json": (3411024, "f11d8d4932d20e532582f2ed1890dede"),
    "russellmitchell_wazuh.json": (45282051, "871bfbdbb02d0174a3eb96b6ea7efa93"),
    "santos_aminer.json": (3634879, "26148531696447b7f2c929a9d629dc44"),
    "santos_wazuh.json": (145438925, "ea3150c6e0d3bec2aded9f76b0f0e4e9"),
    "shaw_aminer.json": (1944470, "229a36f116ccbbfa7d9598a22ad39eae"),
    "shaw_wazuh.json": (74755213, "ebd04583b3266baff0256de6696085b9"),
    "wardbeck_aminer.json": (2583498, "ab55c2a58bc4bcdd0db433d8d88181c9"),
    "wardbeck_wazuh.json": (96564119, "11f6ba7077e6e20db5f18bf96179857a"),
    "wheeler_aminer.json": (10220678, "718eafb36aa7c95d65155433e12b679f"),
    "wheeler_wazuh.json": (650679741, "049ced33b493d32c28409c9bb49cfe7b"),
    "wilson_aminer.json": (7570675, "408102e6d992ba823e98d6b07ca886e7"),
    "wilson_wazuh.json": (673722526, "15205391a147f4d726731e2b5fcb5c2c"),
}
LABELS = ("labels.csv", 3703, "60ff33796c77fd2136c4d1a4bc841bd9")


def md5_of(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def expected(dest):
    """[(path, size, md5)] for the 17 files under dest."""
    out = [(os.path.join(dest, "raw", n), s, m) for n, (s, m) in RAW_FILES.items()]
    out.append((os.path.join(dest, LABELS[0]), LABELS[1], LABELS[2]))
    return out


def check(dest, full=False):
    problems = []
    for path, size, md5 in expected(dest):
        rel = os.path.relpath(path, os.path.dirname(dest))
        if not os.path.isfile(path):
            problems.append(f"missing: {rel}")
        elif os.path.getsize(path) != size:
            problems.append(f"wrong size ({os.path.getsize(path)} bytes, expected {size}): {rel}")
        elif full and md5_of(path) != md5:
            problems.append(f"md5 mismatch: {rel}")
    if not problems:
        print("AIT-ADS raw data: all 17 expected files present"
              + (" and md5-verified." if full else " with the expected sizes (use --full for md5)."))
        return True
    print(f"AIT-ADS raw data: {len(problems)} problem(s).")
    for p in problems:
        print(f"  {p}")
    print("\nRun `python data/download_ait_ads.py --download`, or see data/README.md.")
    print("Analysis steps that need this data are skipped by reproduce.sh, not failed silently.")
    return False


def fetch(url, out_path, md5, size, tries=5):
    """Download url to out_path and verify size and md5; retry on server errors."""
    last = None
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "soc-repo-ait-ads-downloader"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(out_path, "wb") as fh:
                while True:
                    block = resp.read(1 << 20)
                    if not block:
                        break
                    fh.write(block)
            if os.path.getsize(out_path) == size and md5_of(out_path) == md5:
                return
            last = f"size/md5 mismatch for {os.path.basename(out_path)}"
        except (urllib.error.URLError, OSError) as e:
            last = str(e)
        print(f"  attempt {attempt}/{tries} failed ({last}); retrying", file=sys.stderr)
        time.sleep(3 * attempt)
    raise SystemExit(f"could not download {url}: {last}")


def download(dest):
    raw = os.path.join(dest, "raw")
    tmp = os.path.join(dest, "downloads")
    os.makedirs(raw, exist_ok=True)
    os.makedirs(tmp, exist_ok=True)
    zip_path = os.path.join(tmp, "ait_ads.zip")
    print(f"Downloading ait_ads.zip ({ZIP_SIZE / 1e6:.0f} MB) from Zenodo record {ZENODO_RECORD} ...")
    fetch(ZIP_URL, zip_path, ZIP_MD5, ZIP_SIZE)
    print("  archive md5 verified; extracting ...")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(raw)
    print("Downloading labels.csv ...")
    fetch(LABELS_URL, os.path.join(dest, LABELS[0]), LABELS[2], LABELS[1])
    print("Done.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify the 17 files (sizes; add --full for md5)")
    ap.add_argument("--full", action="store_true", help="with --check, also verify md5 of every file")
    ap.add_argument("--download", action="store_true", help="download from Zenodo, verify, extract")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="target folder (default: data/ait_ads)")
    args = ap.parse_args()

    dest = os.path.abspath(args.dest)
    if args.download:
        download(dest)
        sys.exit(0 if check(dest, full=True) else 1)
    sys.exit(0 if check(dest, full=args.full) else 1)
