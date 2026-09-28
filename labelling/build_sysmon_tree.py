"""
build_sysmon_tree.py -- PHASE 3 step 1: cache the Sysmon process tree.
======================================================================
Parsing sysmon_wincl1.evtx takes ~4-5 minutes (53,197 records), so extract the
process-creation records once and cache them. Later steps read the CSV.

EID 1  = process creation (ProcessGuid -> ParentProcessGuid) -- the tree.
EID 11 = file create      (ProcessGuid -> TargetFilename)   -- artifact tier.
EID 13 = registry set     (ProcessGuid -> TargetObject)     -- artifact tier.

Writes: newCol/sysmon_eid1.csv, newCol/sysmon_artifacts.csv
Run:    ~/soc_project/.venv/bin/python newCol/build_sysmon_tree.py
"""

import re
import csv
import time

from Evtx.Evtx import Evtx

import os as _os
HERE = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "testbed_collection")
EVTX = f"{HERE}/sysmon_wincl1.evtx"

RE_EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
RE_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>")


def main():
    t0 = time.time()
    procs, arts = [], []
    n = 0
    with Evtx(EVTX) as log:
        for rec in log.records():
            n += 1
            if n % 20000 == 0:
                print(f"  ...{n} records, {time.time()-t0:.0f}s", flush=True)
            x = rec.xml()
            m = RE_EID.search(x)
            if not m:
                continue
            eid = m.group(1)
            if eid not in ("1", "11", "13"):
                continue
            d = dict(RE_DATA.findall(x))
            if eid == "1":
                procs.append({
                    "process_guid": d.get("ProcessGuid", ""),
                    "parent_guid": d.get("ParentProcessGuid", ""),
                    "utc_time": d.get("UtcTime", ""),
                    "process_id": d.get("ProcessId", ""),
                    "image": d.get("Image", ""),
                    "command_line": (d.get("CommandLine", "") or "")[:300],
                    "parent_image": d.get("ParentImage", ""),
                    "user": d.get("User", ""),
                })
            else:
                arts.append({
                    "eid": eid,
                    "process_guid": d.get("ProcessGuid", ""),
                    "utc_time": d.get("UtcTime", ""),
                    "image": d.get("Image", ""),
                    "target": d.get("TargetFilename") or d.get("TargetObject", ""),
                })

    for path, rows in ((f"{HERE}/sysmon_eid1.csv", procs),
                       (f"{HERE}/sysmon_artifacts.csv", arts)):
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {len(rows):,} rows -> {path}")
    print(f"scanned {n:,} records in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
