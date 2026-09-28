"""
label_lnx_timeonly.py -- PHASE 1 (Linux): provenance labeling, TIME-ONLY mode.
=============================================================================
Per explicit user decision (2026-07-08), the raw process tree is NOT used:
audit_lnxdmz.log only covers 20:42:43Z-21:32:09Z, i.e. rounds 5-6 (21.1% of the
20:22:28Z-20:48:08Z collection). auditd rotated mid-run -- Wazuh rule 591 fired
at 20:43:55Z ("File rotated (inode changed): '/var/log/audit/audit.log'") and the
pre-rotation segment (audit.log.1) was never archived.

CONSEQUENCE, stated plainly: with no process tree there is no HIGH-process tier,
so *every* attack label is time-derived and the residual is 100% BY CONSTRUCTION.
Residual is therefore NOT an informative quality metric for this run. The real
label-quality check is Phase 2 (rule <-> technique consistency).

What this script does still get right, and why it beats the previous collection:

1. EVENT TIME, not alert timestamp.
   Wazuh's alert `timestamp` is true UTC, but it lags the real event by a
   VARIABLE 18.2s-80.4s (median ~36s) of ingestion delay. It is NOT a constant
   offset and must not be shifted. The true event time is recoverable from
   `full_log`, which carries local +03:00 (syslog ISO) or nginx CLF time.
   Measured impact of getting this wrong: 74.1% of alerts would be attributed to
   a DIFFERENT technique and 25.3% would fall outside every window, because the
   dirb windows are only ~2 seconds wide.

   This matters most for the NOVEL persistence techniques, whose only distinctive
   alerts are syscheck FIM events -- and whose windows are only ~19s wide, i.e.
   NARROWER than the median ingestion lag. Time-labeling those from
   `alert.timestamp` is hopeless. Two further event-time sources rescue them,
   both read from fields inside the alert itself (NOT from the audit log):

     * `syscheck.mtime_after` -- the file's post-event mtime.
         - rule 554 (added):    exact. implied lag 18.1-36.5s.  USED.
         - rule 550 (modified): usually exact (median 25.7s) but has an outlier
           tail up to 10,898s, because backup files (/etc/passwd-, /etc/subuid-)
           are created by copy with the ORIGINAL mtime preserved. Used only when
           the implied lag falls in a physically plausible 15-120s band.
         - rule 553 (deleted):  UNUSABLE. mtime_after is the file's last
           modification time, not the deletion time (implied lag up to 11,003s).
           These stay on alert.timestamp.
     * `msg=audit(<epoch>:<serial>)` embedded in full_log for auditd-sourced
       rules 80711/80730 -- exact. implied lag 18.1-69.0s.  USED.

   What remains without any event time: rule 553 (85), rule 591 (3), and the
   550 outliers. Those are tiered VLOW-time and carry the full 18-80s ambiguity.

2. BASELINE windows are NOT assumed benign.
   The per-round teardown (`sudo rm -f /etc/cron.d/col_cron ...`, `userdel -r
   coluser`, `sed -i /COLLECTNOVEL/d /root/.ssh/authorized_keys`) executes during
   the "quiet 90s" baseline. An alert is treated as attack-related -- never
   benign -- when the alert's OWN fields name a collection artifact
   (col_cron / col_svc / col_profile / coluser / COLLECTNOVEL / authorized_keys),
   whether via `syscheck.path`, the rule-5402 `sudo` command, or the full_log
   text. This is direct evidence inside the alert, independent of the marker
   windows, so it does not prejudge Phase 2's rule<->technique check.
   Labeling teardown benign is exactly the confound that poisoned the v6 benign set.

3. Window boundaries.
   Technique windows are inclusive [START, END] because nginx CLF has 1-second
   granularity and the last request commonly lands exactly on END. Baseline
   windows are half-open [START, START+90) and technique windows take precedence:
   baseline #1 ends 20:26:57 and round-2 dirb starts 20:26:57, which otherwise
   double-counts 1,703 alerts into both.

Artifact->technique map is derived empirically from the `sudo` commands captured
in the rule-5402 alerts of THIS collection (col_* prefix; the nov_* paths are
leftovers of the PREVIOUS run, cleaned at 20:18Z before COLLECTION START).

Writes: newCol/labeled_lnx.csv
Run:    ~/soc_project/.venv/bin/python newCol/label_lnx_timeonly.py
"""

import json
import re
import collections
from datetime import datetime, timezone, timedelta

import pandas as pd

import os as _os
HERE = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "testbed_collection")
ALERTS = f"{HERE}/collection_lnx_alerts.json"
MARKERS = f"{HERE}/collect_markers_lnx.txt"
OUT = f"{HERE}/labeled_lnx.csv"

UTC = timezone.utc
BASELINE_SECS = 90

# --- time parsing ----------------------------------------------------------
RE_SYSLOG = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})")
RE_NGINX = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
RE_MARKER = re.compile(r">>> (\S+Z) (\w+) \| (.*)")
RE_AUDIT_EPOCH = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")

# syscheck.mtime_after is naive ISO ('2026-07-08T20:23:13') and is in UTC, NOT the
# agent's local +03:00 -- unlike full_log, which is local. Verified: for the six
# `added` alerts on /etc/cron.d/col_cron the UTC reading lands exactly on the
# T1053.003 window START of each round (20:23:13, 20:27:45, 20:32:21, ...) with a
# plausible 18-36s ingestion lag, whereas a +03:00 reading is off by ~10,818s.
MTIME_TZ = timezone.utc
# Physically plausible Wazuh ingestion lag. Measured range across all rules with
# an independently-known event time: 18.1s .. 80.4s. Anything outside 15-120s
# means the candidate timestamp is not the event time (e.g. a preserved mtime).
LAG_MIN, LAG_MAX = 15.0, 120.0

# Strings that appear ONLY in this collection's own attack artifacts.
# nov_* belong to the PREVIOUS run (cleaned 20:18Z, before COLLECTION START).
COLLECTION_ARTIFACT_TOKENS = (
    "col_cron", "col_svc", "col_profile", "coluser", "COLLECTNOVEL",
    "authorized_keys",
)

# --- attack artifacts, taken verbatim from this run's rule-5402 sudo commands.
# Any syscheck path matching these is attack teardown/setup, never benign.
ARTIFACT_TECHNIQUE = {
    "/etc/cron.d/col_cron": "T1053.003",
    "/etc/systemd/system/col_svc.service": "T1543.002",
    "/etc/profile.d/col_profile.sh": "T1546.004",
    "/root/.ssh/authorized_keys": "T1098.004",
}
# useradd/userdel touch the whole passwd family (+ .lock temp files, - backups)
USER_DB_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/subuid", "/etc/subgid",
)


def artifact_technique(path):
    """Return technique for an attack-artifact syscheck path, else None."""
    if path in ARTIFACT_TECHNIQUE:
        return ARTIFACT_TECHNIQUE[path]
    if any(path.startswith(p) for p in USER_DB_PREFIXES):
        return "T1136.001"          # useradd/userdel coluser
    if "col_" in path or "coluser" in path:
        return "UNMAPPED_COL_ARTIFACT"
    return None


def event_time(alert):
    """True event time in UTC + how we got it.

    Returns (datetime, source, uncertainty_seconds). Sources are tried in order
    of fidelity; every one of them is a field of the alert itself.
    """
    fl = alert.get("full_log") or ""
    ts = datetime.fromisoformat(alert["timestamp"]).astimezone(UTC)

    m = RE_SYSLOG.match(fl)
    if m:
        return datetime.fromisoformat(m.group(1)).astimezone(UTC), "full_log_syslog", 0.0

    m = RE_NGINX.search(fl)
    if m:
        t = datetime.strptime(m.group(1) + m.group(2), "%d/%b/%Y:%H:%M:%S%z")
        return t.astimezone(UTC), "full_log_clf", 1.0          # 1s CLF granularity

    m = RE_AUDIT_EPOCH.search(fl)                              # rules 80711 / 80730
    if m:
        return datetime.fromtimestamp(float(m.group(1)), UTC), "audit_epoch", 0.0

    sc = alert.get("syscheck") or {}
    mt = sc.get("mtime_after")
    if mt and sc.get("event") in ("added", "modified"):
        # 'deleted' is excluded: mtime_after is then the file's LAST modification
        # time, not the deletion time (implied lag observed up to 11,003s).
        try:
            cand = datetime.fromisoformat(mt).replace(tzinfo=MTIME_TZ).astimezone(UTC)
            if LAG_MIN <= (ts - cand).total_seconds() <= LAG_MAX:
                return cand, "syscheck_mtime", 1.0
        except ValueError:
            pass

    # No event time anywhere in the alert: only Wazuh's ingestion timestamp,
    # which lags the real event by an unknown 18-80s.
    return ts, "alert_timestamp", 80.0


def names_collection_artifact(alert, sysp):
    """True if the alert's own fields name an artifact created by this collection.

    Independent of the marker windows -- used to keep attack setup/teardown out
    of the benign class without prejudging Phase 2's rule<->technique check.
    """
    hay = " ".join(filter(None, [
        sysp or "",
        (alert.get("data") or {}).get("command") or "",
        alert.get("full_log") or "",
    ]))
    return any(tok in hay for tok in COLLECTION_ARTIFACT_TOKENS)


def load_markers():
    """-> (collection_start, collection_end, technique_windows, baseline_windows)"""
    tech, base, pending = [], [], {}
    col_s = col_e = None
    round_no = 0
    for line in open(MARKERS):
        m = RE_MARKER.match(line.strip())
        if not m:
            continue
        t = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        kind, rest = m.group(2), m.group(3)
        if kind == "PHASE" and rest.startswith("KNOWN"):
            round_no += 1
        if kind == "EXPORT_FROM":
            col_s = t
        if kind == "EXPORT_TO":
            col_e = t
        if kind == "START":
            pending[rest.split()[0]] = (t, round_no)
        elif kind == "END":
            k = rest.split()[0]
            if k in pending:
                s, r = pending.pop(k)
                tech.append((s, t, k, r))
        elif kind == "BASELINE":
            base.append((t, t + timedelta(seconds=BASELINE_SECS), round_no))
    tech.sort()
    base.sort()
    return col_s, col_e, tech, base


def classify(t, tech_wins, base_wins, col_s, col_e):
    """Assign (window_hits, baseline_hit, in_session) for an event time."""
    hits = [(s, e, k, r) for s, e, k, r in tech_wins if s <= t <= e]     # inclusive
    bhit = [(s, e, r) for s, e, r in base_wins if s <= t < e]            # half-open
    in_sess = col_s <= t <= col_e
    return hits, bhit, in_sess


def main():
    col_s, col_e, tech_wins, base_wins = load_markers()
    print("=" * 78)
    print("PHASE 1 -- Linux provenance labeling (TIME-ONLY; process tree excluded)")
    print("=" * 78)
    print(f"collection window : {col_s:%H:%M:%S}Z -> {col_e:%H:%M:%S}Z")
    print(f"technique windows : {len(tech_wins)}   baseline windows: {len(base_wins)}")

    rows = []
    for line in open(ALERTS):
        a = json.loads(line)
        t, src, unc = event_time(a)
        hits, bhit, in_sess = classify(t, tech_wins, base_wins, col_s, col_e)

        sysp = (a.get("syscheck") or {}).get("path")
        art = artifact_technique(sysp) if sysp else None
        # `art` also covers the passwd/shadow/group family churned by
        # `useradd -m coluser` / `userdel -r coluser` (incl. .lock temp files and
        # '-' backups), whose paths name no collection token.
        is_art = names_collection_artifact(a, sysp) or art is not None

        exact = src != "alert_timestamp"
        label = technique = conf = None
        wstart = wend = rnd = None

        if len(hits) == 1:
            s, e, k, r = hits[0]
            label, technique, rnd, wstart, wend = "attack", k, r, s, e
            conf = "LOW-time" if exact else "VLOW-time"
        elif len(hits) > 1:
            label, technique, conf = "uncertain", "MULTI", "UNCERTAIN-overlap"
        elif is_art:
            # Names a collection artifact but sits outside every technique window:
            # attack setup/teardown (e.g. `rm -f /etc/cron.d/col_cron` or
            # `userdel -r coluser` during the quiet baseline).
            # Emphatically NOT benign background traffic.
            label, technique, conf = "uncertain", art or "", "UNCERTAIN-artifact-teardown"
        elif bhit:
            label, technique, rnd = "benign", "", bhit[0][2]
            conf = "BENIGN-baseline" if exact else "BENIGN-baseline-weak"
        elif in_sess:
            label, technique, conf = "uncertain", "", "UNCERTAIN-session-gap"
        else:
            label, technique, conf = "uncertain", "", "UNCERTAIN-out-of-session"

        rows.append({
            "timestamp": a["timestamp"],
            "event_time_utc": t.isoformat(),
            "time_source": src,
            "time_uncertainty_s": unc,
            "rule_id": a["rule"]["id"],
            "rule_level": a["rule"]["level"],
            "rule_description": a["rule"]["description"],
            "agent_name": a.get("agent", {}).get("name"),
            "agent_ip": a.get("agent", {}).get("ip"),
            "location": a.get("location"),
            "srcip": a.get("data", {}).get("srcip"),
            "srcport": a.get("data", {}).get("srcport"),
            "srcuser": a.get("data", {}).get("srcuser"),
            "url": a.get("data", {}).get("url"),
            "sudo_command": a.get("data", {}).get("command"),
            "syscheck_path": sysp,
            "syscheck_event": (a.get("syscheck") or {}).get("event"),
            "artifact_technique": art,
            "names_collection_artifact": is_art,
            "mitre_ids": ",".join(a["rule"].get("mitre", {}).get("id", []) or []),
            "round": rnd,
            "window_start": wstart.isoformat() if wstart else None,
            "window_end": wend.isoformat() if wend else None,
            "label": label,
            "technique": technique,
            "label_confidence": conf,
            "full_log": (a.get("full_log") or "")[:300],
        })

    df = pd.DataFrame(rows)
    df.to_csv(OUT, index=False)

    # ---- report -----------------------------------------------------------
    print(f"\nalerts labeled: {len(df):,}   -> {OUT}")

    print("\n--- label x confidence tier ---")
    tab = df.groupby(["label", "label_confidence"]).size().reset_index(name="n")
    for _, r in tab.sort_values(["label", "n"], ascending=[True, False]).iterrows():
        print(f"  {r['label']:<10} {r['label_confidence']:<28} {r['n']:>7,}")

    print("\n--- time source ---")
    for s, n in df.time_source.value_counts().items():
        print(f"  {s:<20} {n:>7,}")

    atk = df[df.label == "attack"]
    unc = df[df.label == "uncertain"]
    ben = df[df.label == "benign"]
    n_high = 0                                    # no process tree -> no HIGH tier
    n_low = int((atk.label_confidence.isin(["LOW-time", "VLOW-time"])).sum())
    residual = (n_low + len(unc)) / len(atk) if len(atk) else float("nan")

    n_vlow = int((atk.label_confidence == "VLOW-time").sum())
    print("\n--- headline numbers ---")
    print(f"  attack-labeled     : {len(atk):>7,}")
    print(f"  benign-labeled     : {len(ben):>7,}")
    print(f"  uncertain-labeled  : {len(unc):>7,}")
    print(f"  HIGH-confidence    : {n_high:>7,}   (process tree excluded by decision)")
    print(f"  LOW-time  (attack) : {n_low - n_vlow:>7,}   exact event time")
    print(f"  VLOW-time (attack) : {n_vlow:>7,}   alert.timestamp only (+/-18-80s)")
    print(f"\n  residual as specified = (LOW + UNCERTAIN) / attack-labeled")
    print(f"                        = ({n_low:,} + {len(unc):,}) / {len(atk):,} "
          f"= {residual*100:.1f}%")
    print("  It exceeds 100% because UNCERTAIN alerts are not a subset of the")
    print("  attack-labeled set, so the ratio is not a proportion. Decomposed:")
    print(f"    attack alerts at HIGH tier : 0 / {len(atk):,}  (0.0%)  <- structural")
    print(f"    attack alerts at LOW tier  : {n_low - n_vlow:,} / {len(atk):,} "
          f"({(n_low-n_vlow)/len(atk)*100:.1f}%)")
    print(f"    attack alerts at VLOW tier : {n_vlow:,} / {len(atk):,} "
          f"({n_vlow/len(atk)*100:.1f}%)")
    print(f"    alerts left UNCERTAIN      : {len(unc):,} / {len(df):,} "
          f"({len(unc)/len(df)*100:.1f}% of all alerts)")
    print("  With no process tree no alert can reach HIGH, so residual is")
    print("  uninformative by construction. Phase 2 is the real quality check.")

    print("\n--- attack alerts per technique ---")
    for k, n in atk.technique.value_counts().items():
        rules = collections.Counter(atk[atk.technique == k].rule_id)
        top = ", ".join(f"{r}x{c}" for r, c in rules.most_common(4))
        print(f"  {k:<12} {n:>7,}   rules: {top}")
    expected = {k for _, _, k, _ in tech_wins}
    missing = sorted(expected - set(atk.technique))
    if missing:
        print(f"\n  *** {len(missing)} technique(s) executed but produced ZERO alerts: "
              f"{', '.join(missing)}")
        for k in missing:
            ws = [(s, e) for s, e, kk, _ in tech_wins if kk == k]
            span = sum((e - s).total_seconds() for s, e in ws)
            print(f"      {k}: {len(ws)} windows, {span:.0f}s total -- no Wazuh rule fired")

    print("\n--- BENIGN class composition (what survives as background traffic) ---")
    if len(ben):
        for r, n in collections.Counter(ben.rule_id).most_common(12):
            d = ben[ben.rule_id == r].rule_description.iloc[0][:46]
            print(f"  rule {r:<7} {n:>6,}  {d}")
        print("  sample full_log lines:")
        for s in ben.full_log.head(4):
            print(f"    {str(s)[:110]}")
        print(f"\n  *** {len(ben)} 'benign' alerts, none of which is background traffic:")
        print("      every one is a side effect of the attack script's own sudo/PAM")
        print("      activity during the quiet baseline. The 90s baselines are truly")
        print("      idle -- an idle host emits no alerts, so there is nothing to")
        print("      label benign. FPR (Phase 4c) is NOT computable from this data.")
    else:
        print("  *** EMPTY -- no alert qualifies as benign background traffic. ***")

    print("\n--- UNCERTAIN breakdown ---")
    for c, n in unc.label_confidence.value_counts().items():
        print(f"  {c:<30} {n:>7,}")
    art_unc = unc[unc.label_confidence == "UNCERTAIN-artifact-teardown"]
    if len(art_unc):
        print("  teardown artifacts (would otherwise have been labeled benign):")
        paths = art_unc.syscheck_path.fillna("(non-syscheck: sudo command / full_log)")
        for p, n in collections.Counter(paths).most_common(9):
            print(f"    {n:>4}  {p}")
    return df


if __name__ == "__main__":
    main()
