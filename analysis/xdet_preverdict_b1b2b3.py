#!/usr/bin/env python3
"""
XDET pre-verdict checks B1-B3.

B1: per-signature majority-label distribution and attack:benign ratio,
    Suricata (86601) population -- is the 2.8% lookup recall "no shortcut
    exists" or "the shortcut points at benign"?
B2: does the 86601 (Wazuh-ingested) Suricata population match the
    dataset's own documented complete Suricata signature set (Table 1,
    landauer_introducing_2024), or is it a filtered subset?
B3: for all three detectors, the FULL distribution of per-signature
    attack:benign ratios (not just the binary exclusive/mixed split from
    Task 3) -- how much volume sits above 10:1, 100:1, 1000:1 without
    being strictly exclusive.
"""
import json
import sys
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
from collections import Counter

import numpy as np

sys.path.insert(0, REPO_ROOT)

WAZUH_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_wazuh_recovered_split.npz")
AMINER_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_aminer_split.npz")

# Table 1 of landauer_introducing_2024 -- the 29 documented Suricata alert
# description texts, transcribed directly from the fetched PDF (Sect. 3.1.2,
# Table 1, Suricata rows only). Used for B2 -- comparing our reconstructed
# 86601 population's signature set against the dataset authors' own
# published complete list, since no standalone raw Suricata file exists in
# our holdings to compare against instead (see Task 0 / B2 write-up).
PAPER_SURICATA_SIGNATURES = {
    "ET INFO Suspicious Domain (*.ga) in TLS SNI",
    "ET DNS DNS Lookup for localhost.DOMAIN.TLD",
    "SURICATA DNS Unsolicited response",
    "ET DNS Query for .cc TLD",
    "ET DNS Query for .su TLD (Soviet Union) Often Malware Related",
    "ET DNS Query for .to TLD",
    "ET DNS Query to a *.pw domain - Likely Hostile",
    "ET INFO DNS Query for Suspicious .ga Domain",
    "ET INFO Observed DNS Query to .biz TLD",
    "ET INFO Observed DNS Query to .cloud TLD",
    "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection",
    "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
    "ET HUNTING Possible COVID-19 Domain in SSL Certificate M2",
    "ET HUNTING Suspicious Domain Request for Possible COVID-19 Domain M1",
    "ET HUNTING Suspicious TLS SNI Request for Possible COVID-19 Domain M1",
    "ET SCAN Possible Nmap User-Agent Observed",
    "SURICATA HTTP gzip decompression failed",
    "SURICATA HTTP unable to match response to request",
    "SURICATA HTTP invalid response chunk len",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)",
    "SURICATA SMTP invalid reply",
    "SURICATA SMTP no server welcome message",
    "SURICATA TLS certificate invalid der",
    "ET INFO TLS Handshake Failure",
    "SURICATA TLS invalid handshake message",
    "SURICATA TLS invalid record/traffic",
    "SURICATA TLS invalid SSLv2 header",
    "SURICATA TLS invalid record type",
}


def per_signature_table(sig, y):
    sig = np.asarray(sig, dtype=object)
    y = np.asarray(y)
    rows = []
    for s in sorted(set(sig.tolist()), key=lambda x: str(x)):
        mask = sig == s
        n_attack = int(y[mask].sum())
        n_benign = int((y[mask] == 0).sum())
        total = n_attack + n_benign
        ratio = (n_attack / n_benign) if n_benign > 0 else float("inf")
        majority = "attack" if n_attack >= n_benign else "benign"
        rows.append(dict(signature=str(s), n_attack=n_attack, n_benign=n_benign,
                          total=total, attack_benign_ratio=ratio, majority=majority))
    return rows


def b1_report(rows, detector_name):
    print(f"\n{'='*70}\nB1 -- {detector_name}: per-signature majority-label distribution\n{'='*70}")
    n_maj_attack = sum(1 for r in rows if r["majority"] == "attack")
    n_maj_benign = sum(1 for r in rows if r["majority"] == "benign")
    vol_maj_attack = sum(r["total"] for r in rows if r["majority"] == "attack")
    vol_maj_benign = sum(r["total"] for r in rows if r["majority"] == "benign")
    total = sum(r["total"] for r in rows)
    print(f"  signatures: majority-attack={n_maj_attack}  majority-benign={n_maj_benign}")
    print(f"  volume: majority-attack={vol_maj_attack:,} ({100*vol_maj_attack/total:.2f}%)  "
          f"majority-benign={vol_maj_benign:,} ({100*vol_maj_benign/total:.2f}%)")
    print(f"\n  per-signature attack:benign ratio, sorted descending:")
    for r in sorted(rows, key=lambda r: -r["attack_benign_ratio"]):
        ratio_str = "inf" if r["attack_benign_ratio"] == float("inf") else f"{r['attack_benign_ratio']:.4f}"
        print(f"    {r['signature']:75s} atk={r['n_attack']:>7,} ben={r['n_benign']:>7,} "
              f"ratio={ratio_str:>8} majority={r['majority']}")
    return dict(n_majority_attack=n_maj_attack, n_majority_benign=n_maj_benign,
                vol_majority_attack=vol_maj_attack, vol_majority_benign=vol_maj_benign,
                total=total, rows=rows)


def b3_bands(rows, detector_name):
    print(f"\n{'='*70}\nB3 -- {detector_name}: per-signature attack:benign ratio bands\n{'='*70}")
    total = sum(r["total"] for r in rows)
    bands = [(">=1000:1", 1000), (">=100:1", 100), (">=10:1", 10), (">=2:1", 2)]
    out = {}
    for label, thresh in bands:
        sigs = [r for r in rows if r["attack_benign_ratio"] >= thresh]
        vol = sum(r["total"] for r in sigs)
        print(f"  {label:10s}: {len(sigs):3d} signatures, {vol:>10,} alerts ({100*vol/total:.2f}%)")
        out[label] = dict(n_signatures=len(sigs), volume=vol, volume_pct=100 * vol / total)
    # also: strictly exclusive (benign=0) for reference against Task 3
    excl = [r for r in rows if r["n_benign"] == 0]
    vol_excl = sum(r["total"] for r in excl)
    print(f"  {'exclusive':10s}: {len(excl):3d} signatures, {vol_excl:>10,} alerts "
          f"({100*vol_excl/total:.2f}%)  [for reference against Task 3's exclusivity count]")
    out["strictly_exclusive"] = dict(n_signatures=len(excl), volume=vol_excl,
                                      volume_pct=100 * vol_excl / total)
    return out


def main():
    out = {}

    wz = np.load(WAZUH_NPZ, allow_pickle=True)
    rid_all, rdesc_all, y_all = wz["rid_all"], wz["rdesc_all"], wz["y_all"]
    native_mask = rid_all != 86601
    suricata_mask = rid_all == 86601

    am = np.load(AMINER_NPZ, allow_pickle=True)

    # ---- B1: Suricata majority-label distribution ------------------------
    suri_rows = per_signature_table(rdesc_all[suricata_mask], y_all[suricata_mask])
    out["b1_suricata"] = b1_report(suri_rows, "Suricata (86601)")

    # ---- B2: signature-set completeness check -----------------------------
    print(f"\n{'='*70}\nB2 -- 86601 population vs. dataset authors' documented Suricata "
          f"signature set (landauer_introducing_2024 Table 1)\n{'='*70}")
    our_sigs = set(r["signature"].replace("Suricata: Alert - ", "") for r in suri_rows)
    print(f"  Our reconstructed 86601 population: {len(our_sigs)} distinct signatures")
    print(f"  Paper's documented Suricata signature list: {len(PAPER_SURICATA_SIGNATURES)} signatures")
    missing_from_ours = PAPER_SURICATA_SIGNATURES - our_sigs
    extra_in_ours = our_sigs - PAPER_SURICATA_SIGNATURES
    print(f"  Paper signatures MISSING from our 86601 population: {len(missing_from_ours)} {sorted(missing_from_ours)}")
    print(f"  Signatures in our population NOT in the paper's list: {len(extra_in_ours)} {sorted(extra_in_ours)}")
    our_total_volume = sum(r["total"] for r in suri_rows)
    print(f"  Our total 86601 volume: {our_total_volume:,}  "
          f"Paper's published total Suricata alert count: 306,635  "
          f"match={our_total_volume == 306635}")
    print("  NOTE: no standalone raw Suricata file exists in our holdings to compare against "
          "instead (confirmed in Task 0 -- no *_suricata.json anywhere in data/ait_ads/); "
          "per the paper itself (Sect 3.1.2), Wazuh-mediated ingestion was the ONLY Suricata "
          "collection mechanism used to build this dataset, so there is no unfiltered channel "
          "to compare against even in principle. The comparison against the paper's own "
          "published Table 1 is the strongest available check.")
    out["b2"] = dict(
        our_n_signatures=len(our_sigs), paper_n_signatures=len(PAPER_SURICATA_SIGNATURES),
        missing_from_ours=sorted(missing_from_ours), extra_in_ours=sorted(extra_in_ours),
        our_total_volume=our_total_volume, paper_total_volume=306635,
        volume_match=(our_total_volume == 306635),
    )

    # ---- B3: ratio-band distribution, all three detectors ------------------
    native_rows = per_signature_table(rid_all[native_mask], y_all[native_mask])
    out["b3_wazuh_native"] = b3_bands(native_rows, "Wazuh-native")
    out["b3_suricata"] = b3_bands(suri_rows, "Suricata (86601)")
    aminer_rows = per_signature_table(am["name_all"], am["y_all"])
    out["b3_aminer"] = b3_bands(aminer_rows, "AMiner")

    # also dump full per-signature tables for wazuh-native and aminer for
    # the report (rule 31101 specifically)
    r31101 = [r for r in native_rows if r["signature"] == "31101"]
    if r31101:
        print(f"\nRule 31101 (Wazuh) detail: {r31101[0]}")
        out["rule_31101_detail"] = r31101[0]

    def jsonable(o):
        if isinstance(o, dict):
            return {str(k): jsonable(v) for k, v in o.items()}
        if isinstance(o, list):
            return [jsonable(v) for v in o]
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, float) and o == float("inf"):
            return "inf"
        return o

    out_path = _os.path.join(REPO_ROOT, "analysis", "xdet_b1b2b3_results.json")
    with open(out_path, "w") as f:
        json.dump(jsonable(out), f, indent=2)
    print(f"\nSaved {out_path}")


if __name__ == "__main__":
    main()
