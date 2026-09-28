#!/usr/bin/env bash
# reproduce.sh -- run this repository's pipeline end to end, from the
# repository root: `bash reproduce.sh`.
#
# Steps that need the full AIT-ADS raw download (data/ait_ads/raw/) are
# skipped, not failed, if that data is not present -- data/download_ait_ads.py
# --check reports what's missing. Every other step uses data already
# committed in this repository (data/testbed_collection/, models_v2/,
# analysis/*.json,*.npz, results/rule_memorization_audit/).
set -uo pipefail

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
echo "2. AIT-ADS-dependent analysis (needs data/ait_ads/raw/)"
echo "############################################################"
if [ "$AIT_ADS_PRESENT" -eq 0 ]; then
  run_step "recover exact Wazuh train/test split" "$PY" analysis/xdet_recover_wazuh_split.py
  run_step "build AMiner split" "$PY" analysis/xdet_build_aminer.py
  run_step "XDET Task 1 (cross-detector lookup tables)" "$PY" analysis/xdet_task1_lookup.py
  run_step "REV-C temporal split" "$PY" analysis/rev_task1_temporal_split.py
  run_step "REV-C multiseed" "$PY" analysis/rev_task3_multiseed.py
  run_step "rule-memorization audit exp1" "$PY" results/rule_memorization_audit/exp1_feature_classification.py
  run_step "rule-memorization audit exp3 (lookup table)" "$PY" results/rule_memorization_audit/exp3_lookup_table.py
  run_step "rule-memorization audit exp4 (ablation)" "$PY" results/rule_memorization_audit/exp4_ablation.py
else
  skip_step "recover exact Wazuh train/test split" "data/ait_ads/raw/ not present"
  skip_step "build AMiner split" "data/ait_ads/raw/ not present"
  skip_step "XDET Task 1 (cross-detector lookup tables)" "data/ait_ads/raw/ not present"
  skip_step "REV-C temporal split" "data/ait_ads/raw/ not present"
  skip_step "REV-C multiseed" "data/ait_ads/raw/ not present"
  skip_step "rule-memorization audit exp1/exp3/exp4" "data/ait_ads/raw/ not present (exp2 uses only the committed models_v2/ait_split.npz + xgb_model.pkl, see below)"
  echo "NOTE: this repository already ships the committed OUTPUTS of these steps"
  echo "(analysis/xdet_*.npz, analysis/xdet_*.json, results/rule_memorization_audit/exp*.csv)"
  echo "so figures/ and controls/ below still run correctly without re-deriving them."
fi
run_step "rule-memorization audit exp2 (feature importance, only needs models_v2/)" \
  "$PY" results/rule_memorization_audit/exp2_feature_importance.py

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
echo "4. Controls (Table X)"
echo "############################################################"
run_step "seven controls vs. both corpora" "$PY" controls/run_all.py

echo ""
echo "############################################################"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped"
echo "############################################################"
if [ "$FAIL" -gt 0 ]; then
  echo "Failed steps:"
  for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
fi
exit 0
