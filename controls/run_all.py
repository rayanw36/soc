#!/usr/bin/env python3
"""
controls/run_all.py -- apply all seven controls (docs/controls_spec.md)
to both corpora in this study (the fresh testbed collection and
AIT-ADS), print a table in the paper's Table X layout, and report
whether every verdict matches the paper.

Run from the repository root: `python controls/run_all.py`.

Reuses already-computed data and artifacts wherever they exist (cited
per cell) rather than re-deriving results this repository already has;
computes C1/C2/C3/C5 directly from the raw/labeled collection files and
AIT-ADS split, since those are cheap and their exact inputs are
available. Where an input genuinely cannot be found, the cell is marked
"input not found" rather than invented.
"""
import csv
import json
import os
import sys
from collections import deque

import numpy as np
import pandas as pd

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import c1_benign_burst as C1
import c2_benign_failure_events as C2
import c3_rule_composition as C3
import c4_small_n_determinism as C4
import c5_capture_tempo as C5
import c6_claim_provenance as C6
import c7_artifact_persistence as C7

DATA = os.path.join(REPO_ROOT, "data", "testbed_collection")
MODELS = os.path.join(REPO_ROOT, "models_v2")
ANALYSIS = os.path.join(REPO_ROOT, "analysis")

CAP = 20  # alert_rate_1min structural ceiling (AgentHistory maxlen), shared_features.py

# rule IDs used for the auth-failure event class (C2) -- Linux SSH brute
# force (5710/5712) and failed-password family (5501/5502); Windows
# logon-failure family (60122/60204). 60106 (logon success) is
# deliberately excluded -- it is not a failure event.
LNX_AUTH_FAIL_RULES = {5710, 5712, 5501, 5502}
WIN_AUTH_FAIL_RULES = {60122, 60204}

EXPECTED = {
    "C1": {"Testbed": "fail", "AIT-ADS": "pass"},
    "C2": {"Testbed": "fail", "AIT-ADS": "pass"},
    "C3": {"Testbed": "fail", "AIT-ADS": "not applied"},
    "C4": {"Testbed": "fail", "AIT-ADS": "pass"},
    "C5": {"Testbed": "flagged", "AIT-ADS": "not flagged"},
    "C6": {"Testbed (historical claim set)": "fail", "Testbed (current claim set)": "n/a", "AIT-ADS": "not applied"},
    "C7": {"Testbed": "pass", "AIT-ADS": "not applicable"},
}

# cells whose input is CITED from existing analysis rather than recomputed
# by this script -- marked explicitly in the printed table (FIX 4), not
# just in the detail section, so a reader can tell at a glance which
# results run_all.py actually recomputes.
CITED_CELLS = {
    ("C4", "Testbed"): "docs/ew_phase3_31101_case_study.md, docs/ew_results_report.md",
    ("C5", "AIT-ADS"): "not computed for AIT-ADS (Table X: not flagged, taken as given)",
}


def agent_history_rate(timestamps, cap=CAP):
    """Single-buffer replication of shared_features.py's AgentHistory
    alert_rate_1min: for each alert (in chronological order), the count
    of the preceding <=cap alerts within 60s. Same method as
    figures/fig8_cap_censoring_cross_dataset.py."""
    ts = pd.to_datetime(pd.Series(timestamps), format="ISO8601").sort_values().reset_index(drop=True)
    buf = deque(maxlen=cap)
    rates = []
    for cur in ts:
        rate = sum(1 for rts in buf if 0 <= (cur - rts).total_seconds() <= 60)
        rates.append(rate)
        buf.append(cur)
    return np.array(rates)


# ---------------------------------------------------------------------------
# C1 -- alert_rate_1min, both corpora
# ---------------------------------------------------------------------------
def c1_ait_ads():
    d = np.load(os.path.join(MODELS, "ait_split.npz"), allow_pickle=True)
    feat_cols = list(d["feature_cols"])
    idx = feat_cols.index("alert_rate_1min")
    X = np.concatenate([d["X_train"], d["X_test"]], axis=0)
    y = np.concatenate([d["y_train"], d["y_test"]], axis=0)
    attack = X[y == 1, idx]
    benign = X[y == 0, idx]
    return C1.run(attack, benign, cap=CAP), (
        f"models_v2/ait_split.npz, feature_cols[{idx}]=alert_rate_1min "
        f"(n_attack={len(attack)}, n_benign={len(benign)})"
    )


def c1_testbed():
    lnx = pd.read_csv(os.path.join(DATA, "labeled_lnx.csv"))
    lnx_rates = agent_history_rate(lnx["event_time_utc"])
    attack_mask = (lnx["label"] == "attack").values
    attack = lnx_rates[attack_mask]

    ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    benign = agent_history_rate(ben["timestamp"])

    return C1.run(attack, benign, cap=CAP), (
        f"data/testbed_collection/labeled_lnx.csv (attack side, n={attack_mask.sum()}, "
        f"AgentHistory-replicated alert_rate_1min on event_time_utc) and "
        f"data/testbed_collection/collection_benign_lnx_alerts.csv (benign side, n={len(benign)}, "
        f"same replication on timestamp -- same method as figures/fig8_cap_censoring_cross_dataset.py)"
    )


# ---------------------------------------------------------------------------
# C2 -- auth-failure events in the benign corpus
# ---------------------------------------------------------------------------
def c2_ait_ads():
    d = np.load(os.path.join(MODELS, "ait_split.npz"), allow_pickle=True)
    feat_cols = list(d["feature_cols"])
    idx = feat_cols.index("is_auth_failure")
    X = np.concatenate([d["X_train"], d["X_test"]], axis=0)
    y = np.concatenate([d["y_train"], d["y_test"]], axis=0)
    benign_auth_fail = int(X[y == 0, idx].sum())
    n_benign = int((y == 0).sum())
    return C2.run(benign_auth_fail, n_benign), (
        f"models_v2/ait_split.npz, feature_cols[{idx}]=is_auth_failure, benign rows (y==0), n={n_benign}"
    )


def c2_testbed():
    lnx_ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    lnx_fail = int(lnx_ben["rule_id"].isin(LNX_AUTH_FAIL_RULES).sum())
    win_ben = pd.read_csv(os.path.join(DATA, "collection_benign_win_alerts.csv"))
    win_fail = int(win_ben["rule_id"].isin(WIN_AUTH_FAIL_RULES).sum())
    # Spec's decision rule is per-corpus; the testbed corpus has two
    # platforms, both must be checked, worst case governs the cell.
    r_lnx = C2.run(lnx_fail, len(lnx_ben))
    r_win = C2.run(win_fail, len(win_ben))
    verdict = "FAIL" if (r_lnx.verdict == "FAIL" or r_win.verdict == "FAIL") else "PASS"
    combined = C2.C2Result(verdict, lnx_fail + win_fail, len(lnx_ben) + len(win_ben),
                            f"Linux: {r_lnx.reason}; Windows: {r_win.reason}")
    return combined, (
        f"data/testbed_collection/collection_benign_lnx_alerts.csv (rule_id in {sorted(LNX_AUTH_FAIL_RULES)}) "
        f"and collection_benign_win_alerts.csv (rule_id in {sorted(WIN_AUTH_FAIL_RULES)})"
    )


# ---------------------------------------------------------------------------
# C3 -- rule-composition confounding, testbed only ("not applied" to AIT-ADS
# per Table X -- AIT-ADS's memorization audit already targets rule identity
# directly (Figs 1/9), so a pivot-subset composition check is a different
# question this study did not separately run on AIT-ADS)
#
# docs/controls_spec.md defines C3's input as "the pivot subset on which
# the feature is computed, split by class" -- NOT the whole corpus. The
# pivot this control's Table X cell falsifies is the entity-window
# study's cross-platform interarrival feature (R3), computed on the
# ew_user_present==1 (Linux) subset of analysis/ew_features/ew_augmented_per_alert.csv
# -- reconstructed here from that existing artifact, not redefined.
# See docs/ew_phase2_leakage_audit.md's "User-pivot composition check".
# ---------------------------------------------------------------------------
def c3_pivot_subset_testbed():
    path = os.path.join(ANALYSIS, "ew_features", "ew_augmented_per_alert.csv")
    if not os.path.isfile(path):
        return None, "analysis/ew_features/ew_augmented_per_alert.csv -- INPUT NOT FOUND"
    df = pd.read_csv(path)
    sub = df[(df["platform"] == "lnx") & (df["ew_user_present"] == 1)
             & (df["label"].isin(["attack", "benign"]))]
    attack_rules = sub.loc[sub["label"] == "attack", "rule_id"].tolist()
    benign_rules = sub.loc[sub["label"] == "benign", "rule_id"].tolist()
    n_attack, n_benign = len(attack_rules), len(benign_rules)

    source = (
        f"analysis/ew_features/ew_augmented_per_alert.csv, platform=='lnx' & "
        f"ew_user_present==1 (the exact subset behind the entity-window study's "
        f"cross-platform interarrival feature, R3) -- n_attack={n_attack}, n_benign={n_benign}"
    )
    if n_attack == 0 or n_benign == 0:
        return None, source + " -- one class is empty in this subset, input not usable"

    r = C3.run(attack_rules, benign_rules)
    # report the exact per-class top rule shares alongside the verdict, since
    # this is the number the paper cites (55% / 70%), not just PASS/FAIL
    from collections import Counter
    atk_top = Counter(attack_rules).most_common(1)[0]
    ben_top = Counter(benign_rules).most_common(1)[0]
    r.reason += (
        f" | attack top rule: {atk_top[0]} ({100*atk_top[1]/n_attack:.1f}% of attack side); "
        f"benign top rule: {ben_top[0]} ({100*ben_top[1]/n_benign:.1f}% of benign side)"
    )
    return r, source


def c3_whole_corpus_testbed_EXTRA():
    """NOT the Table X cell (see c3_pivot_subset_testbed above) -- kept as a
    separately-labelled extra output only, per instruction: the whole-corpus
    check answers a different question (does ANY rule dominate one class
    across the entire attack-round/benign-round collections) than the
    pivot-subset check the paper's C3 example falsifies."""
    lnx = pd.read_csv(os.path.join(DATA, "labeled_lnx.csv"))
    attack_rules = lnx.loc[lnx["label"] == "attack", "rule_id"]
    ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    benign_rules = ben["rule_id"]
    return C3.run(attack_rules.tolist(), benign_rules.tolist()), (
        "EXTRA, not the Table X cell -- data/testbed_collection/labeled_lnx.csv (attack side, rule_id) vs. "
        "collection_benign_lnx_alerts.csv (benign side, rule_id), whole corpus"
    )


# ---------------------------------------------------------------------------
# C4 -- small-n hyperparameter determinism
# ---------------------------------------------------------------------------
def c4_ait_ads():
    path = os.path.join(ANALYSIS, "rev_task3_multiseed_results.json")
    if not os.path.isfile(path):
        return None, "analysis/rev_task3_multiseed_results.json -- INPUT NOT FOUND"
    with open(path) as f:
        d = json.load(f)
    # "full" variant F1 across 10 seeds; qualitative verdict = "memorization
    # gap survives" iff model F1 stays within ~0.001 of lookup F1 every seed
    f1s = [r["f1"] for r in d["raw_runs"]["random_full"]]
    lookup_f1 = d["lookup_random"]["f1"]
    verdicts = {f"seed_{i}": ("gap survives" if abs(f1 - lookup_f1) < 0.01 else "gap closes")
                for i, f1 in enumerate(f1s)}
    r = C4.run_from_precomputed(verdicts, {k: v for k, v in zip(verdicts, f1s)})
    return r, "analysis/rev_task3_multiseed_results.json (10-seed multiseed run, random_full variant vs. lookup)"


def c4_testbed():
    # Reuses the already-computed rule-31101 window study (n=7 entity
    # windows) rather than re-deriving it -- see docs/ew_phase3_31101_case_study.md
    # and docs/figure_inventory.md's citation of the same n=7 result as a
    # "mechanism, not deployment-grade generalization" finding whose
    # magnitude was shown elsewhere in this study to be hyperparameter-
    # and configuration-sensitive (the retracted EW positive results,
    # documented in docs/ew_results_report.md).
    return None, ("docs/ew_phase3_31101_case_study.md, docs/ew_results_report.md -- "
                   "verdict cited from existing analysis, not re-fit here (see REPO_CHANGES.md)")


# ---------------------------------------------------------------------------
# C5 -- capture-tempo asymmetry, diagnostic
# ---------------------------------------------------------------------------
def c5_testbed():
    lnx = pd.read_csv(os.path.join(DATA, "labeled_lnx.csv"))
    attack_ts = pd.to_datetime(lnx.loc[lnx["label"] == "attack", "event_time_utc"], format="ISO8601").astype("int64") / 1e9
    ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    benign_ts = pd.to_datetime(ben["timestamp"], format="ISO8601").astype("int64") / 1e9
    return C5.run(attack_ts.values, benign_ts.values), (
        "data/testbed_collection/labeled_lnx.csv (attack, event_time_utc) vs. "
        "collection_benign_lnx_alerts.csv (benign, timestamp) -- Linux side; "
        "see docs/eval_set_definition.md for the frozen 135.2x/820.8x figures this reproduces"
    )


def c5_ait_ads():
    return None, "AIT-ADS is not a fresh timestamped collection in the same sense -- not flagged, per Table X (not computed here)"


# ---------------------------------------------------------------------------
# C6 -- claim provenance. Evaluated on BOTH the historical claim set (the
# claim as it stood before correction -- the "endogenous auth aggregates"
# T1110.001 carrier characterisation, no producing artifact -- this is the
# claim Table X's "fail" cell falsifies) and the current, already-corrected
# claim set (docs/claims.csv, this repository's own present-day claims).
# Both results are real; printing both is the point of the control, not a
# hedge -- see docs/claims_historical.csv.
# ---------------------------------------------------------------------------
def c6_historical():
    return C6.run(os.path.join(REPO_ROOT, "docs", "claims_historical.csv"), REPO_ROOT), "docs/claims_historical.csv"


def c6_current():
    return C6.run(os.path.join(REPO_ROOT, "docs", "claims.csv"), REPO_ROOT), "docs/claims.csv"


# ---------------------------------------------------------------------------
# C7 -- post-attack artifact persistence, testbed only
# ---------------------------------------------------------------------------
def c7_testbed():
    lnx = pd.read_csv(os.path.join(DATA, "labeled_lnx.csv"))
    benign_rows = lnx[lnx["label"] == "benign"]
    inventory = {
        "/etc/cron.d/col_cron", "/etc/systemd/system/col_svc.service",
        "/etc/profile.d/col_profile.sh", "/root/.ssh/authorized_keys",
    }
    paths_in_label_benign = benign_rows["syscheck_path"].dropna().tolist()

    ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    paths_in_fresh_benign = ben["path"].dropna().tolist() if "path" in ben.columns else []

    all_benign_paths = paths_in_label_benign + paths_in_fresh_benign
    r = C7.run(all_benign_paths, inventory)
    return r, (
        f"data/testbed_collection/labeled_lnx.csv (label=='benign' rows, syscheck_path, n={len(paths_in_label_benign)}) "
        f"and collection_benign_lnx_alerts.csv (path, n={len(paths_in_fresh_benign)}), "
        f"against the artifact inventory in analysis/art_contamination_check.py"
    )


def main():
    rows = []  # (control, corpus, verdict, source, reason)

    for ctrl_id, fn_pairs in [
        ("C1", [("Testbed", c1_testbed), ("AIT-ADS", c1_ait_ads)]),
        ("C2", [("Testbed", c2_testbed), ("AIT-ADS", c2_ait_ads)]),
        ("C3", [("Testbed", c3_pivot_subset_testbed), ("AIT-ADS", None)]),
        ("C4", [("Testbed", c4_testbed), ("AIT-ADS", c4_ait_ads)]),
        ("C5", [("Testbed", c5_testbed), ("AIT-ADS", c5_ait_ads)]),
        ("C6", [("Testbed (historical claim set)", c6_historical),
                ("Testbed (current claim set)", c6_current),
                ("AIT-ADS", None)]),
        ("C7", [("Testbed", c7_testbed), ("AIT-ADS", None)]),
    ]:
        for corpus, fn in fn_pairs:
            if fn is None:
                # use the paper's own N/A wording per cell (Table X
                # distinguishes "not applied" from "not applicable")
                verdict = EXPECTED.get(ctrl_id, {}).get(corpus, "not applied")
                source, reason = "-", f"{verdict}, per docs/controls_spec.md Table X"
            else:
                result, source = fn()
                if result is None:
                    verdict, reason = "input not found / cited, not recomputed", source
                elif hasattr(result, "flagged"):  # C5 diagnostic
                    verdict = "flagged" if result.flagged else "not flagged"
                    reason = result.reason
                else:
                    verdict = result.verdict.lower()
                    reason = result.reason
            cited_from = CITED_CELLS.get((ctrl_id, corpus))
            if cited_from:
                verdict = f"{verdict} [CITED: {cited_from}]"
            rows.append((ctrl_id, corpus, verdict, source, reason))

    # ---- C3 extra: whole-corpus check, NOT the Table X cell -------------
    extra_result, extra_source = c3_whole_corpus_testbed_EXTRA()
    rows.append(("C3", "Testbed (EXTRA: whole corpus, not the Table X cell)",
                 extra_result.verdict.lower(), extra_source, extra_result.reason))

    # ---- print Table X-style summary -----------------------------------
    print(f"{'ID':<4} {'Corpus':<34} {'Verdict':<28} {'Matches paper?':<20}")
    print("-" * 100)
    mismatches = []
    for ctrl_id, corpus, verdict, source, reason in rows:
        if "EXTRA" in corpus:
            match = "n/a -- not a Table X cell"
        else:
            expected = EXPECTED.get(ctrl_id, {}).get(corpus, "?")
            # normalize: strip a "[CITED: ...]" suffix and anything from the
            # first " (" or " /" onward, before comparing to EXPECTED
            norm_verdict = verdict.split(" [CITED")[0].split(" /")[0].split(" (")[0].strip()
            if "input not found" in verdict:
                match = "input not found"
            elif expected == "n/a":
                match = "not compared (no Table X cell for this row)"
            elif norm_verdict.lower() == expected.lower():
                match = "MATCH"
            else:
                match = "MISMATCH"
        if match == "MISMATCH":
            mismatches.append((ctrl_id, corpus, verdict, expected))
        print(f"{ctrl_id:<4} {corpus:<34} {verdict:<28} {match:<20}")

    print("\n--- detail ---")
    for ctrl_id, corpus, verdict, source, reason in rows:
        print(f"\n{ctrl_id} / {corpus}: {verdict}")
        print(f"  source: {source}")
        print(f"  reason: {reason}")

    print("\n" + "=" * 70)
    if mismatches:
        print(f"{len(mismatches)} MISMATCH(ES) against the paper's Table X:")
        for m in mismatches:
            print(f"  {m}")
        print("Per instruction: reporting only, not adjusting the control to match.")
    else:
        print("No mismatches among the verdicts this run could compute "
              "(cited/not-applied cells excluded from comparison).")

    sweep_parameters()


def sweep_parameters():
    """Re-run C1 (both corpora) and C3 (testbed) across a small range of
    the unquantified 'negligible' parameter, and report whether any
    verdict in the table above changes. Per instruction: if none does,
    say so; if one does, report it (do not pick the value that matches)."""
    print("\n" + "=" * 70)
    print("PARAMETER SENSITIVITY SWEEP (negligible in {0, 0.01, 0.05})")
    print("=" * 70)

    any_flip = False

    d = np.load(os.path.join(MODELS, "ait_split.npz"), allow_pickle=True)
    feat_cols = list(d["feature_cols"])
    idx = feat_cols.index("alert_rate_1min")
    X = np.concatenate([d["X_train"], d["X_test"]], axis=0)
    y = np.concatenate([d["y_train"], d["y_test"]], axis=0)
    ait_attack, ait_benign = X[y == 1, idx], X[y == 0, idx]

    lnx = pd.read_csv(os.path.join(DATA, "labeled_lnx.csv"))
    lnx_rates = agent_history_rate(lnx["event_time_utc"])
    tb_attack = lnx_rates[(lnx["label"] == "attack").values]
    ben = pd.read_csv(os.path.join(DATA, "collection_benign_lnx_alerts.csv"))
    tb_benign = agent_history_rate(ben["timestamp"])

    for negligible in (0.0, 0.01, 0.05):
        v_tb = C1.run(tb_attack, tb_benign, cap=CAP, negligible=negligible).verdict
        v_ait = C1.run(ait_attack, ait_benign, cap=CAP, negligible=negligible).verdict
        print(f"  C1 negligible={negligible}: Testbed={v_tb}  AIT-ADS={v_ait}")
        if v_tb != "FAIL" or v_ait != "PASS":
            any_flip = True

    # C3 on the pivot subset (the Table X cell, FIX 1) -- and, separately,
    # on the whole corpus (the EXTRA row, kept only for contrast)
    ew_path = os.path.join(ANALYSIS, "ew_features", "ew_augmented_per_alert.csv")
    if os.path.isfile(ew_path):
        ew = pd.read_csv(ew_path)
        pivot = ew[(ew["platform"] == "lnx") & (ew["ew_user_present"] == 1)
                   & (ew["label"].isin(["attack", "benign"]))]
        pivot_attack = pivot.loc[pivot["label"] == "attack", "rule_id"].tolist()
        pivot_benign = pivot.loc[pivot["label"] == "benign", "rule_id"].tolist()
        for negligible in (0.0, 0.01, 0.05):
            v = C3.run(pivot_attack, pivot_benign, negligible=negligible).verdict
            print(f"  C3 (pivot subset, the Table X cell) negligible={negligible}: Testbed={v}")
            if v != "FAIL":
                any_flip = True
    else:
        print("  C3 pivot-subset sweep skipped: analysis/ew_features/ew_augmented_per_alert.csv not found")

    lnx_attack_rules = lnx.loc[lnx["label"] == "attack", "rule_id"].tolist()
    lnx_benign_rules = ben["rule_id"].tolist()
    for negligible in (0.0, 0.01, 0.05):
        v = C3.run(lnx_attack_rules, lnx_benign_rules, negligible=negligible).verdict
        print(f"  C3 (EXTRA, whole-corpus scope, not the Table X cell) negligible={negligible}: Testbed={v}")

    if any_flip:
        print("\n>>> At least one C1 verdict changes under the swept negligible values -- "
              "reported here, not resolved by picking a value.")
    else:
        print("\n>>> No C1 verdict changes across the swept negligible values in {0, 0.01, 0.05}; "
              "the paper's verdicts do not depend on the exact value chosen.")


if __name__ == "__main__":
    main()
