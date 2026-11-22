#!/usr/bin/env bash
# reproduce.sh -- run this repository's pipeline end to end, from the
# repository root: `bash reproduce.sh` (or `bash reproduce.sh --quick`).
#
# Only two steps need the AIT-ADS raw download (data/ait_ads/raw/): recovering the
# train/test split and building the AMiner split. They are skipped, not failed, if
# that data is not present -- `python data/download_ait_ads.py --check` reports what
# is missing and `--download` fetches it. Every other step uses data already
# committed in this repository (data/testbed_collection/, models_v2/,
# analysis/*.json,*.npz, results/rule_memorization_audit/), including the audit,
# temporal-split, multiseed and cross-detector steps, which read the committed
# models_v2/ait_split.npz and analysis/xdet_*.npz.
#
# --quick skips the ten-seed REV-C multiseed run (about 6 minutes of the total).
set -uo pipefail

# Some scripts write non-ASCII characters (arrows, dashes) to text files; make Python use
# UTF-8 for files on every platform (Windows defaults to cp1252).
export PYTHONUTF8=1
export MPLBACKEND="${MPLBACKEND:-Agg}"

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    *) echo "usage: bash reproduce.sh [--quick]"; exit 2 ;;
  esac
done

PY="${PYTHON:-python3}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
SKIP=0
declare -a FAILED_STEPS

run_step() {
  local desc="$1"; shift
  echo ""
  echo "=== $desc ==="
  if "$@" ; then
    echo "--- OK: $desc"
    PASS=$((PASS+1))
  else
    echo "--- FAILED: $desc"
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$desc")
  fi
}

skip_step() {
  local desc="$1"; local reason="$2"
  echo ""
  echo "=== $desc ==="
  echo "--- SKIPPED: $reason"
  SKIP=$((SKIP+1))
}

echo "############################################################"
echo "0. Data availability check"
echo "############################################################"
"$PY" data/download_ait_ads.py --check
AIT_ADS_PRESENT=$?

echo ""
echo "############################################################"
echo "1. Labelling (uses data/testbed_collection/, already committed)"
echo "############################################################"
run_step "Linux labelling (time-window, corrected event time)" "$PY" labelling/label_lnx_timeonly.py
run_step "Linux label verification (syscheck.path cross-check)" "$PY" labelling/verify_labels_lnx.py
if [ -f "data/testbed_collection/sysmon_wincl1.evtx" ]; then
  run_step "Windows Sysmon process-tree build" "$PY" labelling/build_sysmon_tree.py
else
  skip_step "Windows Sysmon process-tree build" \
    "data/testbed_collection/sysmon_wincl1.evtx not present (excluded, 59MB -- see data/README.md; the already-parsed sysmon_eid1.csv/sysmon_artifacts.csv it produces are committed, so label_win_provenance.py below still works)"
fi
run_step "Windows provenance labelling" "$PY" labelling/label_win_provenance.py

echo ""
echo "############################################################"
echo "2. Analysis on the AIT-ADS benchmark"
echo "############################################################"
if [ "$AIT_ADS_PRESENT" -eq 0 ]; then
  run_step "recover exact Wazuh train/test split (needs data/ait_ads/raw/)" "$PY" analysis/xdet_recover_wazuh_split.py
  run_step "build AMiner split (needs data/ait_ads/raw/)" "$PY" analysis/xdet_build_aminer.py
else
  skip_step "recover exact Wazuh train/test split" "data/ait_ads/raw/ not present (run: python data/download_ait_ads.py --download); the committed analysis/xdet_wazuh_recovered_split.npz is used instead"
  skip_step "build AMiner split" "data/ait_ads/raw/ not present; the committed analysis/xdet_aminer_split.npz is used instead"
fi
# The remaining steps read only the committed models_v2/ait_split.npz and analysis/xdet_*.npz.
run_step "XDET Task 1 (cross-detector lookup tables)" "$PY" analysis/xdet_task1_lookup.py
run_step "REV-C temporal split" "$PY" analysis/rev_task1_temporal_split.py
if [ "$QUICK" -eq 1 ]; then
  skip_step "REV-C multiseed (ten seeds, about 6 minutes)" "--quick given; the committed analysis/rev_task3_multiseed_results.json is used"
else
  run_step "REV-C multiseed (ten seeds, about 6 minutes)" "$PY" analysis/rev_task3_multiseed.py
fi
run_step "rule-memorization audit exp1 (feature classification)" "$PY" results/rule_memorization_audit/exp1_feature_classification.py
run_step "rule-memorization audit exp2 (feature importance)" "$PY" results/rule_memorization_audit/exp2_feature_importance.py
run_step "rule-memorization audit exp3 (lookup table)" "$PY" results/rule_memorization_audit/exp3_lookup_table.py
run_step "rule-memorization audit exp4 (ablation)" "$PY" results/rule_memorization_audit/exp4_ablation.py
run_step "rule 31101 episode-level recall/FPR (committed data only)" \
  "$PY" analysis/rule31101_episodes.py
run_step "rule 31101 field inventory and collision check" \
  "$PY" analysis/rule31101_fields.py
run_step "tier-study test set provenance (3,464 attack / 42 benign) and Wilson intervals" \
  "$PY" analysis/tier_study_subset.py
run_step "OC-SVM training data and overlap with the evaluation sets" \
  "$PY" analysis/ocsvm_training_split.py
run_step "Windows alerts per agent and Sysmon source" \
  "$PY" analysis/windows_agents_sysmon.py
run_step "rule 553 technique behind the 20 novel-attack alerts" \
  "$PY" analysis/rule553_technique.py
run_step "non-attack alerts in the attack rounds (Linux 312, Windows 65)" \
  "$PY" analysis/nonattack_alerts_attack_rounds.py

echo ""
echo "############################################################"
echo "3. Figures (all read already-committed data; no AIT-ADS download needed)"
echo "############################################################"
for f in figures/fig1_lookup_vs_model.py figures/fig2_feature_composition.py \
         figures/fig3a_ablation_separability.py figures/fig3b_31101_tier_study.py \
         figures/fig4_31101_score_overlap.py figures/fig5_tempo_asymmetry.py \
         figures/fig6_benign_composition.py figures/fig7_threshold_sweep_v5defer.py \
         figures/fig8_cap_censoring_cross_dataset.py figures/fig9_cross_detector_lookup.py; do
  run_step "$(basename "$f")" "$PY" "$f"
done

echo ""
echo "############################################################"
echo "4. Controls (Table X) and practices"
echo "############################################################"
run_step "five controls vs. both corpora" "$PY" controls/run_all.py
run_step "practices (small-n determinism, claim provenance)" "$PY" controls/practices/run_practices.py

echo ""
echo "############################################################"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped"
echo "############################################################"
if [ "$FAIL" -gt 0 ]; then
  echo "Failed steps:"
  for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
fi
exit 0
