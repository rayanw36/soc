#!/usr/bin/env python3
"""
controls/practices/run_practices.py -- run the two binary checks that are
kept as practices rather than controls (docs/controls_spec.md, "Practices"):

  * small-n hyperparameter determinism  (formerly C4)
  * claim provenance                    (formerly C6)

They are not part of the five-control table in controls/run_all.py, but the
code is kept and still runs. Run from the repository root:

    python controls/practices/run_practices.py

As in run_all.py, an input that is cited from an existing analysis rather
than recomputed is marked [CITED: ...], and a missing input is reported as
"input not found" rather than reconstructed.
"""
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import claim_provenance as ClaimProv
import small_n_determinism as SmallN

ANALYSIS = os.path.join(REPO_ROOT, "analysis")

# verdicts the paper reports for these two checks (docs/controls_spec.md)
EXPECTED = {
    ("small-n hyperparameter determinism", "Testbed"): "fail",
    ("small-n hyperparameter determinism", "AIT-ADS"): "pass",
    ("claim provenance", "Testbed (historical claim set)"): "fail",
    ("claim provenance", "Testbed (current claim set)"): "n/a",
}


def small_n_ait_ads():
    path = os.path.join(ANALYSIS, "rev_task3_multiseed_results.json")
    if not os.path.isfile(path):
        return None, "analysis/rev_task3_multiseed_results.json -- INPUT NOT FOUND"
    with open(path) as f:
        d = json.load(f)
    # "full" variant F1 across 10 seeds; qualitative verdict = "rule-identity shortcut
    # gap survives" iff model F1 stays within 0.01 of lookup F1 at every seed
    f1s = [r["f1"] for r in d["raw_runs"]["random_full"]]
    lookup_f1 = d["lookup_random"]["f1"]
    verdicts = {f"seed_{i}": ("gap survives" if abs(f1 - lookup_f1) < 0.01 else "gap closes")
                for i, f1 in enumerate(f1s)}
    r = SmallN.run_from_precomputed(verdicts, dict(zip(verdicts, f1s)))
    return r, "analysis/rev_task3_multiseed_results.json (10-seed multiseed run, random_full variant vs. lookup)"


def small_n_testbed():
    # The falsifying result is the rule-31101 window study (n = 7 entity
    # windows). It is cited from the existing analysis, not re-fit here.
    return None, ("docs/history/ew_phase3_31101_case_study.md, docs/history/ew_results_report.md -- "
                  "verdict cited from existing analysis, not re-fit here")


def provenance_historical():
    return (ClaimProv.run(os.path.join(REPO_ROOT, "docs", "claims_historical.csv"), REPO_ROOT),
            "docs/claims_historical.csv")


def provenance_current():
    return (ClaimProv.run(os.path.join(REPO_ROOT, "docs", "claims.csv"), REPO_ROOT),
            "docs/claims.csv")


def main():
    items = [
        ("small-n hyperparameter determinism", "Testbed", small_n_testbed),
        ("small-n hyperparameter determinism", "AIT-ADS", small_n_ait_ads),
        ("claim provenance", "Testbed (historical claim set)", provenance_historical),
        ("claim provenance", "Testbed (current claim set)", provenance_current),
    ]
    print(f"{'Practice':<38} {'Claim set / corpus':<32} {'Verdict':<12} {'Matches paper?'}")
    print("-" * 100)
    detail, mismatches = [], 0
    for name, corpus, fn in items:
        result, source = fn()
        if result is None:
            verdict = "cited" if "cited" in source else "input not found"
            match = "[CITED] not compared" if verdict == "cited" else "input not found"
            reason = source
        else:
            verdict = result.verdict.lower()
            expected = EXPECTED.get((name, corpus), "?")
            match = "not compared" if expected == "n/a" else ("MATCH" if verdict == expected else "MISMATCH")
            mismatches += match == "MISMATCH"
            reason = result.reason
        print(f"{name:<38} {corpus:<32} {verdict:<12} {match}")
        detail.append((name, corpus, source, reason))
    print("\n--- detail ---")
    for name, corpus, source, reason in detail:
        print(f"\n{name} / {corpus}\n  source: {source}\n  reason: {reason}")
    print("\n" + ("No mismatches among the verdicts this run could compute."
                  if not mismatches else f"{mismatches} MISMATCH(ES) against the paper."))


if __name__ == "__main__":
    main()
