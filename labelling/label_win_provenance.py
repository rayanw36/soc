"""
label_win_provenance.py -- PHASE 3 (Windows): provenance labeling WITH process tree.
====================================================================================
Unlike Linux (whose audit.log lost rounds 1-4 to rotation), the Windows Sysmon
capture is complete: ROOT_GUID anchors a 200-process descendant tree, and 187 of
the 401 alerts carry a Sysmon ProcessGuid that resolves into that tree. So this
phase produces the genuine HIGH-process labels the whole re-collection was for.

Confidence ladder (mirrors the brief):
  HIGH-process : alert's ProcessGuid is ROOT_GUID or a descendant of it.
                 -> attack. Technique attributed by which window the event falls in;
                    HIGH-process alerts outside every window are still attack
                    (process-anchored) but technique-ambiguous (session activity).
  LOW-time     : no usable ProcessGuid (or a foreign one), but the event time lands
                 in exactly one technique window. Flagged. This is where the
                 brute-force logon alerts (4624/4625 -> rules 60106/60122/60204)
                 land -- Security-log events carry no Sysmon GUID.
  benign       : clear of every technique window, inside the collection session,
                 and NOT in the ROOT tree.
  uncertain    : window overlaps, session gaps, or pre-collection export padding.

Time: `data.win.system.systemTime` is exact UTC and present on ALL 401 alerts
(ingestion lag ~43s), so -- unlike Linux -- there is no timestamp ambiguity here.

Two structural facts about this capture, surfaced not silently handled:
  * The markers stop mid-round-5 (last line: round-5 T1046 START, 23:14:09Z),
    but alerts run to 23:29Z. Rounds 5-6 are therefore largely UNMARKED; alerts
    after the last window are tiered as post-marker session, not benign.
  * Alerts begin at 21:42Z, exactly 30 min before COLLECTION START (22:12:39Z) --
    the `-30min` export padding. Pre-collection alerts are UNCERTAIN, not benign.

Writes: newCol/labeled_win.csv
Run:    ~/soc_project/.venv/bin/python newCol/label_win_provenance.py
"""

import json
import re
import collections
from datetime import datetime, timezone, timedelta

import pandas as pd

import os as _os
HERE = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "testbed_collection")
ALERTS = f"{HERE}/collection_win_alerts.json"
MARKERS = f"{HERE}/collect_markers_win.txt"
EID1 = f"{HERE}/sysmon_eid1.csv"
OUT = f"{HERE}/labeled_win.csv"

UTC = timezone.utc
ROOT_GUID = "{b7327453-ca05-6a4e-c903-000000002100}"
BASELINE_SECS = 90
RE_MARKER = re.compile(r">>> (\S+Z) (\w+) \| (.*)")


def load_tree():
    """Return the set of ProcessGuids that are ROOT_GUID or descend from it."""
    e = pd.read_csv(EID1, dtype=str).fillna("")
    kids = collections.defaultdict(list)
    for pg, par in zip(e.process_guid, e.parent_guid):
        kids[par].append(pg)
    desc = {ROOT_GUID}
    st = [ROOT_GUID]
    while st:
        for k in kids.get(st.pop(), []):
            if k not in desc:
                desc.add(k)
                st.append(k)
    return desc


def load_markers():
    tech, base, pending = [], [], {}
    col_s = col_e = None
    round_no = 0
    for line in open(MARKERS, encoding="utf-16"):
        m = RE_MARKER.match(line.strip())
        if not m:
            continue
        t = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        kind, rest = m.group(2), m.group(3)
        if kind == "PHASE" and rest.startswith("KNOWN"):
            round_no += 1
        if kind == "EXPORT_FROM":
            col_s = t
        if kind == "START":
            pending.setdefault(rest.split()[0], []).append((t, round_no))
        elif kind == "END":
            k = rest.split()[0]
            if pending.get(k):
                s, r = pending[k].pop(0)
                if t > s:                       # skip 0-second START==END markers
                    tech.append((s, t, k, r))
        elif kind == "BASELINE":
            base.append((t, t + timedelta(seconds=BASELINE_SECS), round_no))
        col_e = t
    tech.sort()
    base.sort()
    # collection start marker is EXPORT_FROM (-30min padding); the true activity
    # window begins at COLLECTION START. Use the first technique START as t0.
    activity_start = min(s for s, *_ in tech)
    return activity_start, col_e, tech, base


def event_time(alert):
    st = alert["data"]["win"]["system"]["systemTime"]     # exact UTC, all alerts
    return datetime.fromisoformat(st.replace("Z", "+00:00")).astimezone(UTC)


def main():
    tree = load_tree()
    act_s, col_e, tech_wins, base_wins = load_markers()
    print("=" * 84)
    print("PHASE 3 -- Windows provenance labeling (Sysmon process tree)")
    print("=" * 84)
    print(f"ROOT tree size       : {len(tree)} processes")
    print(f"marked activity span : {act_s:%H:%M:%S}Z -> {col_e:%H:%M:%S}Z "
          f"(markers stop mid-round-5)")
    print(f"technique windows    : {len(tech_wins)}   baseline windows: {len(base_wins)}")

    alerts = [json.loads(l) for l in open(ALERTS)]
    last_win_end = max(e for _, e, _, _ in tech_wins)

    rows = []
    for a in alerts:
        t = event_time(a)
        ed = a.get("data", {}).get("win", {}).get("eventdata", {})
        guid = ed.get("processGuid")
        in_tree = bool(guid) and guid in tree

        hits = [(s, e, k, r) for s, e, k, r in tech_wins if s <= t <= e]
        bhit = [(s, e, r) for s, e, r in base_wins if s <= t < e]
        one = hits[0] if len(hits) == 1 else None

        label = technique = conf = None
        rnd = one[3] if one else (bhit[0][2] if bhit else None)

        if in_tree:
            # process-anchored: definitely attack activity
            label = "attack"
            if one:
                technique, conf = one[2], "HIGH-process"
            elif len(hits) > 1:
                technique, conf = "MULTI", "HIGH-process-overlap"
            else:
                technique, conf = "", "HIGH-process-session"
        elif one:
            label, technique, conf = "attack", one[2], "LOW-time"
        elif len(hits) > 1:
            label, technique, conf = "uncertain", "MULTI", "UNCERTAIN-overlap"
        elif t < act_s:
            label, technique, conf = "uncertain", "", "UNCERTAIN-pre-collection"
        elif t > last_win_end:
            label, technique, conf = "uncertain", "", "UNCERTAIN-post-marker"
        elif bhit:
            label, technique, conf = "benign", "", "BENIGN-baseline"
        else:
            label, technique, conf = "uncertain", "", "UNCERTAIN-session-gap"

        rows.append({
            "timestamp": a["timestamp"],
            "event_time_utc": t.isoformat(),
            "rule_id": a["rule"]["id"],
            "rule_level": a["rule"]["level"],
            "rule_description": a["rule"]["description"],
            "event_id": a["data"]["win"]["system"].get("eventID"),
            "process_guid": guid,
            "in_root_tree": in_tree,
            "image": ed.get("image"),
            "parent_image": ed.get("parentImage"),
            "command_line": (ed.get("commandLine") or "")[:200],
            "target_user": ed.get("targetUserName") or ed.get("targetUser"),
            "mitre_ids": ",".join(a["rule"].get("mitre", {}).get("id", []) or []),
            "round": rnd,
            "label": label,
            "technique": technique,
            "label_confidence": conf,
        })

    df = pd.DataFrame(rows)
    df.to_csv(OUT, index=False)
    print(f"\nalerts labeled: {len(df):,}   -> {OUT}")

    print("\n--- label x confidence tier ---")
    for (lab, conf), n in df.groupby(["label", "label_confidence"]).size().items():
        print(f"  {lab:<10} {conf:<26} {n:>5}")

    atk = df[df.label == "attack"]
    ben = df[df.label == "benign"]
    unc = df[df.label == "uncertain"]
    n_high = int(atk.label_confidence.str.startswith("HIGH").sum())
    n_low = int((atk.label_confidence == "LOW-time").sum())
    residual = (n_low + len(unc)) / len(atk) if len(atk) else float("nan")

    print("\n--- headline numbers ---")
    print(f"  attack-labeled    : {len(atk):>5}")
    print(f"  benign-labeled    : {len(ben):>5}")
    print(f"  uncertain-labeled : {len(unc):>5}")
    print(f"  HIGH-process      : {n_high:>5}   ({n_high/len(atk)*100:.1f}% of attack) "
          f"<- genuine provenance anchor")
    print(f"  LOW-time          : {n_low:>5}   ({n_low/len(atk)*100:.1f}% of attack)")
    print(f"  residual = (LOW + UNCERTAIN) / attack = "
          f"({n_low} + {len(unc)}) / {len(atk)} = {residual*100:.1f}%")
    print(f"  (Contrast Linux: 0% HIGH. Here {n_high/len(atk)*100:.0f}% of attack alerts "
          f"are process-tree anchored.)")

    print("\n--- attack alerts per technique (tier split) ---")
    for k in sorted(set(atk.technique)):
        s = atk[atk.technique == k]
        hi = int(s.label_confidence.str.startswith("HIGH").sum())
        lo = len(s) - hi
        rules = ", ".join(f"{r}x{c}" for r, c in collections.Counter(s.rule_id).most_common(4))
        print(f"  {k or '(session)':<14} n={len(s):<4} HIGH={hi:<4} LOW={lo:<4} rules: {rules}")

    print("\n--- benign class ---")
    if len(ben):
        for r, n in collections.Counter(ben.rule_id).most_common(10):
            d = ben[ben.rule_id == r].rule_description.iloc[0][:44]
            print(f"  rule {r:<7} {n:>4}  {d}")
    else:
        print("  (empty)")

    print("\n--- uncertain breakdown ---")
    for c, n in unc.label_confidence.value_counts().items():
        print(f"  {c:<28} {n:>5}")
    return df


if __name__ == "__main__":
    main()
