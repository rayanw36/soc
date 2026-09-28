#!/usr/bin/env python3
"""Classify a Wazuh rule ID against the AIT-ADS training data.

Usage:
    python3 check_rule.py <rule_id> [<rule_id> ...]

Prints for each ID whether it is:
  in-attack  - fired during a labeled attack window (results_v2/ait_ads_rule_breakdown.csv)
  in-all     - seen somewhere in the raw training data (attack or benign) but not in an attack window
  novel      - not seen anywhere in the AIT-ADS training data
"""
import sys
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ALL_PATH = os.path.join(BASE, "ait_ads_seen_all.txt")
ATTACK_PATH = os.path.join(BASE, "ait_ads_seen_attack.txt")


def load_set(path):
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}


def classify(rule_id, all_ids, attack_ids):
    rule_id = str(rule_id).strip()
    if rule_id in attack_ids:
        return "in-attack"
    if rule_id in all_ids:
        return "in-all"
    return "novel"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    all_ids = load_set(ALL_PATH)
    attack_ids = load_set(ATTACK_PATH)

    for rid in sys.argv[1:]:
        print(f"{rid}: {classify(rid, all_ids, attack_ids)}")


if __name__ == "__main__":
    main()
