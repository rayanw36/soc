# Rule-Identity Memorization in SIEM Alert Triage

Artifact repository for *"Rule-Identity Memorization in SIEM Alert Triage:
Why Benchmark Performance Does Not Transfer, and Seven Controls That
Detect It"* (Mohammad Arwani, Rayen Chikhaoui, Abdulaziz Barnawi, Farid
Binbeshr, Muhammad Imam).

**The finding, in one paragraph:** a two-layer SOC alert-triage pipeline
(cost-sensitive XGBoost for known attacks, One-Class SVM for novel ones)
reports near-benchmark performance on AIT-ADS, but a trivial
majority-label-per-signature lookup table — no training, no features
beyond "which rule fired" — matches it to within 0.0003 F1. The same
lookup-table-vs-model comparison, run across all three of AIT-ADS's
detectors (Wazuh, Suricata, AMiner) and against a trivial always-predict-
attack baseline rather than recall alone, shows the effect is real but
detector-specific, concentrated in a small number of high-purity rules
(chiefly rule 31101), and does not hold at all for Suricata. Applying the
same scrutiny to this project's own fresh testbed collection surfaces a
parallel problem — several apparently strong results turn out to be
artifacts of collection tempo, rule composition, or small-n
hyperparameter sensitivity rather than genuine detection. The paper's
contribution is not just the specific findings but **seven reusable
controls** (`controls/`) that catch this class of problem, applied here
to both corpora and reported honestly including where a control's
verdict on one corpus doesn't match its verdict on the other for reasons
this repository documents rather than hides.

## Install and reproduce

```bash
pip install -r requirements.txt
bash reproduce.sh
```

`reproduce.sh` runs labelling, analysis, all nine figures, and all seven
controls, from the repository root, and prints a pass/fail/skip summary.
Steps needing the full AIT-ADS raw download are **skipped, not failed**,
if that data isn't present — see the next section. Every other step
(labelling, all nine figures, all seven controls) runs against data
already committed in this repository and does not need any download.

Verified end-to-end on Python 3.11 with the versions pinned in
`requirements.txt`: **15 steps pass, 0 fail, 7 skip** (6 AIT-ADS-dependent
steps + the raw-Sysmon-`.evtx`-dependent step, both explained below).

## Getting the AIT-ADS data

Not included in this repository (see `data/README.md` for why, and the
full citation). To run the AIT-ADS-dependent steps:

1. Cite/obtain the dataset per `data/README.md` (Landauer, Skopik,
   Wurzenberger, CSET '24, DOI 10.1145/3675741.3675748).
2. Place it at `data/ait_ads/raw/<scenario>_{wazuh,aminer}.json` and
   `data/ait_ads/labels.csv` (8 scenarios: fox, harrison, russellmitchell,
   santos, shaw, wardbeck, wheeler, wilson).
3. `python data/download_ait_ads.py --check` confirms the layout.
4. Re-run `bash reproduce.sh` — the previously-skipped steps now run.

You do **not** need this to reproduce any of the nine figures or the
controls table — this repository ships the already-computed intermediate
artifacts (`models_v2/ait_split.npz`, `analysis/xdet_*.{npz,json}`,
`results/rule_memorization_audit/exp*.csv`) those steps read from.

## Figure and table map

| figure/result | script | reads |
|---|---|---|
| Fig 1 — lookup table vs. model F1 | `figures/fig1_lookup_vs_model.py` | `results/rule_memorization_audit/exp3_lookup_results.csv`, `exp4_ablation_main.csv` |
| Fig 2 — feature-gain composition | `figures/fig2_feature_composition.py` | `results/rule_memorization_audit/exp2_importance_gain.csv` |
| Fig 3a — rule-identity ablation | `figures/fig3a_ablation_separability.py` | `results/rule_memorization_audit/exp4_ablation_main.csv`, `exp1_feature_classification.csv` |
| Fig 3b — rule-31101 raw-HTTP tier study | `figures/fig3b_31101_tier_study.py` | `analysis/fr_31101_features.csv` |
| Fig 4 — rule-31101 OC-SVM score overlap | `figures/fig4_31101_score_overlap.py` | `analysis/ew_phase3_31101_per_alert_combined.csv`, `models_v2/thresholds_production_v3.json` |
| Fig 5 — capture-tempo asymmetry | `figures/fig5_tempo_asymmetry.py` | `analysis/ew_features/ew_augmented_per_alert.csv` |
| Fig 6 — benign-corpus rule composition | `figures/fig6_benign_composition.py` | `analysis/ew_features/ew_augmented_per_alert.csv` |
| Fig 7 — deployed threshold sweep | `figures/fig7_threshold_sweep_v5defer.py` | `analysis/threshold_sweep.csv`, `models_v2/thresholds_production_v3.json` |
| Fig 8 — cross-dataset cap censoring | `figures/fig8_cap_censoring_cross_dataset.py` | `models_v2/ait_split.npz`, `data/testbed_collection/collection_benign_lnx_alerts.csv` |
| Fig 9 — cross-detector lookup vs. model vs. trivial baseline | `figures/fig9_cross_detector_lookup.py` | `analysis/fig9m_task1_results.json`, `analysis/fig9m_task2_aminer_model_results.json`, `analysis/xdet_task1_results.json` |
| Table X — seven controls, both corpora | `controls/run_all.py` | see `docs/controls_spec.md` and the per-control source citations it prints |
| Claims map | `docs/claims.csv` | every row cites its own producing file |

Every figure script prints its exact source path(s) before writing
output, and writes both a `.pdf` and a `.png` to `figures/out/`.

**Which control cells `run_all.py` actually recomputes vs. cites.** Most
cells in Table X are computed directly from committed data by
`controls/run_all.py` itself. Two are not — the script prints
`[CITED: <source>]` on these, and they are excluded from its
paper-verdict comparison rather than silently marked "match":

| cell | why cited, not recomputed | source |
|---|---|---|
| C4, Testbed | the falsifying result is the rule-31101 window study (n=7); re-fitting it was out of scope for this script | `docs/ew_phase3_31101_case_study.md`, `docs/ew_results_report.md` |
| C5, AIT-ADS | AIT-ADS is not a fresh timestamped collection in the same sense the testbed corpus is; Table X marks it "not flagged" and that is taken as given | (not computed) |

`run_all.py` also prints one extra row beyond Table X's seven-by-two
grid: a whole-corpus version of C3, labelled `EXTRA, not the Table X
cell`, kept only to show the contrast with the pivot-subset result that
*is* the Table X cell (see `docs/controls_spec.md`'s C3 entry and
`REPO_CHANGES.md` for why the distinction matters).

## Running the seven controls on a new corpus

`controls/` is designed to be reused outside this repository. Each
control (`c1_benign_burst.py` … `c7_artifact_persistence.py`) is a small,
dependency-light module exposing a `run(...)` function that takes plain
arrays/lists you provide — none of them know about this project's file
layout. Minimal example, checking a rate-shaped feature for the
capture-tempo/censored-cap failure mode C1 exists to catch:

```python
import sys
sys.path.insert(0, "controls")
import c1_benign_burst as C1

# your_feature: e.g. alerts-per-minute for each class, from YOUR corpus
attack_rates = [...]   # feature values for attack-labelled rows
benign_rates = [...]   # feature values for benign-labelled rows

result = C1.run(attack_rates, benign_rates, cap=20)  # cap=None if the
                                                       # feature has no
                                                       # structural ceiling
print(result.verdict, result.reason)
```

`docs/controls_spec.md` has the full specification (all seven controls,
their inputs/statistics/decision rules, and the paper's own falsification
examples) and the parameters (`negligible`, `high`, `far_from_one`) the
paper deliberately leaves uncalibrated — `controls/run_all.py`'s
parameter sweep shows this repository's own verdicts don't depend on the
exact values chosen.

## Repository layout

```
controls/     the seven controls (c1..c7), importable + run_all.py
analysis/     cross-detector audit, purity, multiseed, temporal split,
              Wilson intervals, entity-window study, v8 recalibration
labelling/    Linux time-window / Windows process-tree labelling
figures/      one script per figure, output to figures/out/
data/         data sources README, AIT-ADS download helper, and this
              project's own testbed collection (testbed_collection/)
docs/         frozen definitions, full audit reports, claims.csv,
              controls_spec.md; docs/notes/ has internal working notes
results/      results/rule_memorization_audit/ -- the core Fig 1-3
              evidence (exp1-4)
results_v2/, models_v2/  deployed models, thresholds, and the v8 Windows
              recalibration study
```

Root-level `.py` files (`phase1_xgboost.py`, `combined_decision_v3.py`,
`combined_decision_v6.py`, `shared_features.py`, `shared_constants*.py`,
`normalize_schema.py`, `anomaly_model_comparison.py`,
`finalize_ocsvm_threshold.py`, `retrain_ocsvm_v6.py`,
`task3_xplatform_benign.py`, `check_rule.py`) are the deployed pipeline
and shared feature-extraction code every analysis/labelling/figures
script imports from — left at the root rather than moved, since that is
where they were already correctly placed and where the (unmodified)
import statements throughout this repository expect them.

## Known limitations

- **Linux testbed labels are time-window, on a corrected event time —
  not process-tree anchored, unlike Windows.** Audit-log rotation lost
  ~79% of the Linux collection window, so no process tree could be built
  for it; every Linux attack label comes from matching a
  forensically-recovered event time (not Wazuh's raw, variably-lagged
  ingestion timestamp) against a labelled technique window. Windows
  labels are 55.7% genuinely process-tree-anchored (Sysmon `ProcessGuid`
  resolved against the attack process's ancestry) and 44.3% the same
  time-window fallback. See `labelling/label_lnx_timeonly.py`'s own
  docstring and `docs/eval_set_definition.md`.
- **The fresh benign corpora are small** (Linux n=267, Windows n=201,
  single collection sessions) — every FPR/benign-side number in this
  study should be read as an estimate with that sample size, not a
  production rate. `docs/f1_final_summary.md` and
  `results_v2/windows_recalibration_v8.md` state this explicitly wherever
  a number depends on it.
- **Capture-tempo asymmetry between the testbed's attack and benign
  rounds** (Control C5: ~135x mean-rate, ~227-820x depending on exact
  measurement, on Linux; ~1.5x on Windows) means every rate-/
  volume-shaped feature on this corpus is suspect until it separately
  passes Control C1 — several results in this study's own history did
  not, and are documented as retracted, not silently dropped
  (`docs/ew_results_report.md`).
- **AIT-ADS's train/test split is stratified-random, not temporal.**
  Re-run under a genuine chronological split, the model-vs-lookup-table
  memorization gap survives (0.9909 vs. 0.9907, `docs/notes/rev_task1_split.md`)
  but this should still be read as the honest caveat it is for any
  number computed on the random split.
- **All seven controls' `run_all.py` verdicts now match the paper's Table X**
  (see `REPO_CHANGES.md` for the fix history — C3 initially ran on the
  wrong population, the whole corpus rather than the entity-window
  study's user-scoped pivot subset the paper's example actually uses; C6
  initially conflated the current, already-corrected claim set with the
  historical one the paper's cited failure describes). Both are worth
  reading in `REPO_CHANGES.md` even though they're resolved — they show
  what "the fix belongs in the code, not the paper" looks like when it's
  actually true.

## Citation

```bibtex
@software{arwani_soc_memorization,
  title  = {Rule-Identity Memorization in SIEM Alert Triage: Why Benchmark Performance Does Not Transfer, and Seven Controls That Detect It},
  author = {Arwani, Mohammad and Chikhaoui, Rayen and Barnawi, Abdulaziz and Binbeshr, Farid and Imam, Muhammad},
  year   = {2026},
  url    = {https://github.com/rayanw36/soc}
}
```

See `CITATION.cff` for the citation-file-format version (venue/year are
placeholders pending publication).

## License

MIT (code only — see `LICENSE`). The AIT-ADS dataset is not included and
carries its own terms (`data/README.md`).
