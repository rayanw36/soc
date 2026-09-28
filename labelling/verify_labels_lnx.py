"""
verify_labels_lnx.py -- PHASE 2 (Linux): verify the Phase-1 labels before trusting them.
=======================================================================================
Phase 1 assigned a technique to each alert PURELY from the marker windows (time).
This script tests those assignments against evidence that does not come from the
windows at all, so the check is not circular:

  * RULE SEMANTICS. Each Wazuh rule has a known meaning. 31101 is a web 400; 5710 is
    an sshd invalid-user; 5901/5902 are group/user creation. If a 31101 is labeled
    "cron persistence", the labeling is wrong -- no timezone or marker reading can
    make a web 404 into a cron write.

  * ARTIFACT PATH (the strong one). Every syscheck alert carries `syscheck.path`,
    which names the technique outright: /etc/cron.d/col_cron IS T1053.003,
    /etc/systemd/system/col_svc.service IS T1543.002, and so on. That gives a
    per-alert ground-truth technique, independent of time, for all 344 FIM alerts.
    Time-assigned technique vs path-derived technique is a genuine confusion matrix.

Rules split into two classes, because most rules are NOT discriminative:

  DISCRIMINATIVE -- fire for exactly one technique, so a mismatch is a real error.
  INCIDENTAL     -- side effects of the harness itself. 5402/5501/5502 are the
                    sudo+PAM triple emitted by EVERY technique that calls sudo;
                    80711/1010 are process-exit/segfault noise. These carry no
                    technique information and are excluded from the error count
                    (counting them as errors would be as wrong as counting them
                    as detections).

If mismatches share a consistent time offset, that is a marker/timezone
misalignment and is reported as such -- never silently corrected.

Reads:  newCol/labeled_lnx.csv
Writes: newCol/phase2_technique_rule_table.csv, newCol/phase2_contradictions.csv
Run:    ~/soc_project/.venv/bin/python newCol/verify_labels_lnx.py
"""

import collections
from datetime import datetime, timedelta

import pandas as pd

import os as _os
HERE = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "testbed_collection")
LABELED = f"{HERE}/labeled_lnx.csv"

# --- rule semantics --------------------------------------------------------
# Which technique each discriminative rule is EXPECTED to belong to.
# A rule may legitimately map to several (554 "file added" fires for cron,
# systemd, profile.d and the passwd .lock temp files).
EXPECTED = {
    "31101": {"T1595.003"},          # web 400
    "31151": {"T1595.003"},          # multiple web 400s from same src
    "31104": {"T1595.003"},          # common web attack
    "31516": {"T1595.003"},          # suspicious URL
    "5710":  {"T1110.001"},          # sshd invalid user
    "5712":  {"T1110.001"},          # sshd brute force aggregate
    "5901":  {"T1136.001"},          # new group
    "5902":  {"T1136.001"},          # new user
    "5903":  {"T1136.001"},          # group/user deleted (userdel teardown)
    "554":   {"T1053.003", "T1543.002", "T1546.004", "T1136.001"},
    "550":   {"T1098.004", "T1136.001"},
    "553":   {"T1053.003", "T1543.002", "T1546.004", "T1136.001"},
}
# Fire for every sudo-using technique; carry no technique signal.
INCIDENTAL = {"5402", "5501", "5502", "80711", "1010", "591", "80730"}

# Rules ABSENT from ait_ads_seen_all.txt (the 31 training rule IDs).
NOVEL_RULES = {"554", "550", "553", "5901", "5902", "5903", "5712", "5710",
               "80711", "1010", "591"}


def main():
    df = pd.read_csv(LABELED, dtype={"rule_id": str})
    atk = df[df.label == "attack"].copy()

    print("=" * 84)
    print("PHASE 2 -- label verification (evidence independent of the marker windows)")
    print("=" * 84)
    print(f"attack-labeled alerts under test: {len(atk):,}\n")

    # ---------------------------------------------------------------- 2.1
    print("-" * 84)
    print("2.1  TECHNIQUE x RULE crosstab  (rows = time-assigned technique)")
    print("-" * 84)
    ct = pd.crosstab(atk.technique, atk.rule_id)
    ct = ct[sorted(ct.columns, key=int)]
    ct.to_csv(f"{HERE}/phase2_technique_rule_table.csv")
    print(ct.to_string())
    print("\n  discriminative rules:", ", ".join(sorted(EXPECTED, key=int)))
    print("  incidental rules    :", ", ".join(sorted(INCIDENTAL, key=int)),
          "  (sudo+PAM triple / process noise -- no technique signal)")

    # ---------------------------------------------------------------- 2.2
    print("\n" + "-" * 84)
    print("2.2  GROUND-TRUTH SPOT CHECKS (from your smoke tests)")
    print("-" * 84)
    checks = [
        ("31101 lands in dirb (T1595.003) windows", "31101", "T1595.003"),
        ("31151 lands in dirb (T1595.003) windows", "31151", "T1595.003"),
        ("5710  lands in ssh-brute (T1110.001) windows", "5710", "T1110.001"),
        ("5712  lands in ssh-brute (T1110.001) windows", "5712", "T1110.001"),
        ("5901  lands in create-user (T1136.001) windows", "5901", "T1136.001"),
        ("5902  lands in create-user (T1136.001) windows", "5902", "T1136.001"),
    ]
    for desc, rid, want in checks:
        sub = atk[atk.rule_id == rid]
        if not len(sub):
            print(f"  [ n/a ] {desc:<48} 0 attack-labeled alerts")
            continue
        hit = int((sub.technique == want).sum())
        pct = hit / len(sub) * 100
        print(f"  [{'PASS' if hit == len(sub) else 'FAIL':^6}] {desc:<48} "
              f"{hit}/{len(sub)} ({pct:.1f}%)")

    # 554/550 need the path to say which technique is correct -> handled in 2.3

    # ---------------------------------------------------------------- 2.3
    print("\n" + "-" * 84)
    print("2.3  ARTIFACT-PATH CONFUSION  (syscheck alerts; path = independent truth)")
    print("-" * 84)
    fim = atk[atk.artifact_technique.notna() &
              (atk.artifact_technique != "UNMAPPED_COL_ARTIFACT")].copy()
    print(f"  syscheck attack alerts with a path-derived technique: {len(fim)}")
    if len(fim):
        cm = pd.crosstab(fim.artifact_technique, fim.technique,
                         rownames=["TRUE (from syscheck.path)"],
                         colnames=["ASSIGNED (from time window)"])
        print()
        print(cm.to_string())
        agree = int((fim.artifact_technique == fim.technique).sum())
        print(f"\n  agreement: {agree}/{len(fim)} = {agree/len(fim)*100:.1f}%")
        print(f"  MISLABELED by time: {len(fim)-agree} "
              f"({(len(fim)-agree)/len(fim)*100:.1f}%)")

    # ---------------------------------------------------------------- 2.4
    print("\n" + "-" * 84)
    print("2.4  CONTRADICTIONS  (rule ID vs assigned technique)")
    print("-" * 84)
    bad = []
    for _, r in atk.iterrows():
        rid, tech = r.rule_id, r.technique
        if rid in INCIDENTAL:
            continue
        exp = EXPECTED.get(rid)
        if exp is None:
            continue
        # For syscheck rules the path pins the exact technique; use it when present.
        truth = r.artifact_technique if isinstance(r.artifact_technique, str) and \
            r.artifact_technique in exp else None
        wrong = (tech != truth) if truth else (tech not in exp)
        if wrong:
            bad.append({
                "event_time_utc": r.event_time_utc, "rule_id": rid,
                "rule_description": r.rule_description,
                "assigned_technique": tech,
                "true_technique": truth or "/".join(sorted(exp)),
                "syscheck_path": r.syscheck_path, "time_source": r.time_source,
                "label_confidence": r.label_confidence,
            })
    bad = pd.DataFrame(bad)
    disc = atk[~atk.rule_id.isin(INCIDENTAL) & atk.rule_id.isin(EXPECTED)]
    print(f"  discriminative attack alerts : {len(disc):,}")
    print(f"  contradictions               : {len(bad):,} "
          f"({len(bad)/max(len(disc),1)*100:.2f}%)")
    if len(bad):
        bad.to_csv(f"{HERE}/phase2_contradictions.csv", index=False)
        print(f"  -> {HERE}/phase2_contradictions.csv\n")
        print("  by rule -> assigned technique:")
        for (rid, tech, truth), n in collections.Counter(
                zip(bad.rule_id, bad.assigned_technique, bad.true_technique)).most_common(20):
            print(f"    {n:>4}x  rule {rid:<5} assigned {tech:<12} but path/semantics say {truth}")

    # ---------------------------------------------------------------- 2.5
    print("\n" + "-" * 84)
    print("2.5  IS IT A CONSTANT OFFSET? (marker/timezone misalignment test)")
    print("-" * 84)
    if len(bad):
        # For each mislabeled syscheck alert, how far is its event time from the
        # nearest window of its TRUE technique?
        offs = []
        for _, r in bad.iterrows():
            if not isinstance(r.syscheck_path, str):
                continue
            t = datetime.fromisoformat(r.event_time_utc)
            tw = atk[atk.technique == r.true_technique]
            if not len(tw):
                continue
            best = None
            for _, w in tw.drop_duplicates("window_start").iterrows():
                s = datetime.fromisoformat(w.window_start)
                e = datetime.fromisoformat(w.window_end)
                d = 0.0 if s <= t <= e else (
                    (t - e).total_seconds() if t > e else (t - s).total_seconds())
                if best is None or abs(d) < abs(best):
                    best = d
            if best is not None:
                offs.append(best)
        if offs:
            offs_sorted = sorted(offs)
            med = offs_sorted[len(offs_sorted) // 2]
            spread = offs_sorted[-1] - offs_sorted[0]
            print(f"  offset of mislabeled FIM alerts from their TRUE technique window:")
            print(f"    n={len(offs)}  min={offs_sorted[0]:+.1f}s  median={med:+.1f}s  "
                  f"max={offs_sorted[-1]:+.1f}s  spread={spread:.1f}s")
            if spread <= 5.0:
                print(f"  => CONSTANT offset ({med:+.1f}s). This is a marker/timezone")
                print("     misalignment. NOT corrected here -- reporting only.")
            else:
                print(f"  => NOT a constant offset (spread {spread:.0f}s). This is the")
                print("     variable 18-80s Wazuh ingestion lag on alerts that carry no")
                print("     event time, not a timezone bug. A constant shift would be wrong.")
        else:
            print("  no measurable offsets")
    else:
        print("  no contradictions to test")

    # ---------------------------------------------------------------- 2.6
    print("\n" + "-" * 84)
    print("2.6  NOVEL-RULE CHECK vs ait_ads_seen_all.txt")
    print("-" * 84)
    print("  rules present tonight that are ABSENT from the 31 training rule IDs:")
    for rid, n in collections.Counter(df.rule_id).most_common():
        if rid in NOVEL_RULES:
            d = df[df.rule_id == rid].rule_description.iloc[0][:44]
            print(f"    {rid:<7} n={n:<6} {d}")
    print("\n  NOTE: 5710 is ABSENT from ait_ads_seen_all.txt, yet the task brief calls it")
    print("        a KNOWN rule and defines the Phase-4 KNOWN set as 31101/31151/5710.")
    print("        Unresolved -- flagged, not silently decided.")


if __name__ == "__main__":
    main()
