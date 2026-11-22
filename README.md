# Rule-Identity Shortcuts and Benign-Corpus Confounds in SIEM Alert-Triage Evaluation

Artifact repository for the paper *Rule-Identity Shortcuts and Benign-Corpus Confounds in SIEM Alert-Triage
Evaluation* by Rayen Chikhaoui, Mohammad Arwani, Abdulaziz Barnawi, Farid Binbeshr and Muhammad Imam (King Fahd
University of Petroleum and Minerals, KFUPM). Status: submitted to *Computers & Security*; no DOI yet.

## Summary

A two-layer Wazuh alert-triage pipeline (a cost-sensitive XGBoost classifier for known attacks and a one-class SVM
for novel ones) scores F1 0.9945 on the public AIT-ADS benchmark. A majority-label-per-rule-identifier lookup table,
with no training and no features beyond "which rule fired", scores 0.9942, and the gap stays at 0.0002 under a
chronological split. Repeated across the benchmark's three detectors (Wazuh, Suricata, AMiner) against a trivial
always-attack baseline, the effect is real but detector-specific: strong for Wazuh, weak for AMiner, absent for
Suricata. Applying the same scrutiny to the authors' own Linux and Windows testbed collections shows that several
apparently strong results are artifacts of capture tempo (the Linux attack rounds were captured at about 135 times
the benign mean alert rate), of benign-corpus composition (78.3% of the Linux benign alerts are one rule) or of small
samples. For rule 31101, the most frequent rule, the fields an alert carries separate attack from benign only
through fields an attacker controls. The paper's reusable contribution is five evaluation controls, C1-C5
(`controls/`), applied here to both corpora.

## How to cite

The paper is submitted and has no DOI yet; the DOI of the paper and of the archived release of this repository will
be added on publication. Until then:

```bibtex
@unpublished{chikhaoui_rule_identity_shortcuts,
  title  = {Rule-Identity Shortcuts and Benign-Corpus Confounds in {SIEM} Alert-Triage Evaluation},
  author = {Chikhaoui, Rayen and Arwani, Mohammad and Barnawi, Abdulaziz and Binbeshr, Farid and Imam, Muhammad},
  note   = {Submitted to Computers \& Security. DOI added on publication},
  year   = {2026}
}
```

`CITATION.cff` has the same information for GitHub's "Cite this repository". If you use AIT-ADS, cite its authors
as well (see `data/README.md`).

## Repository layout

```
controls/      the five controls (c1..c5) as importable modules, run_all.py (Table X), and
               practices/ (small-n determinism, claim provenance: kept as practices, not controls)
analysis/      analysis scripts and their outputs (cross-detector audit, temporal split, multiseed,
               entity-window study, rule 31101 analyses, Windows recalibration); analysis/README.md
               says which scripts run, and with what
labelling/     Linux time-window labelling and Windows process-tree labelling of the testbed alerts
figures/       one script per figure; output goes to figures/out/ (PDF and PNG)
data/          data/README.md, the AIT-ADS downloader, and the testbed collection (testbed_collection/)
docs/          controls_spec.md, eval_set_definition.md, rev_model_config.md, rev_multiseed.md, claims.csv;
               docs/history/ holds the frozen working reports behind the paper (read its README first)
results/       rule_memorization_audit/  the experiments behind Figs 1-3 (the directory keeps its original
                                         name; "rule-identity shortcut" is the paper's term for what it measures)
               report files written by the analysis scripts (rule 31101, tier study, OC-SVM split, ...)
results_v2/    benign baseline, Windows recalibration study, rule breakdown
models_v2/     the deployed models, scalers, thresholds and the AIT-ADS split
lnx_dmz_ai_detections.json   alerts from the same Linux host, 2025-12-02 to 2026-05-25 (OC-SVM training source)
*.py (root)    the original training and decision pipeline and shared feature code that the scripts import
reproduce.sh   runs everything end to end
```

Root-level pipeline scripts: `phase1_xgboost.py` (L1 training), `combined_decision_v3.py`, `_v5.py`, `_v6.py` (the
deployed decision logic), `shared_features.py`, `shared_constants*.py`, `build_clean_benign_baseline.py` (builds the
OC-SVM's training baseline from `lnx_dmz_ai_detections.json`), `finalize_ocsvm_threshold.py`,
`build_expanded_benign_baseline_v6.py` and `retrain_ocsvm_v6.py` (a v6 path that is not the deployed L2),
`anomaly_model_comparison.py`, `normalize_schema.py`, `task3_xplatform_benign.py`, `check_rule.py`. They stay at the
root because the scripts import them from there. `analysis/README.md` lists which of them can be rerun from this
repository.

## Requirements and setup

Python 3.11. Tested on Windows 11 with Python 3.11.9 in a fresh virtual environment.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` pins every package. `matplotlib` is pinned to 3.10.7 because that is the version the committed
figures were made with: with 3.11 every regenerated figure differs from the committed one. On Windows, set
`PYTHONUTF8=1` when you run a script directly (`reproduce.sh` sets it for you).

## Getting AIT-ADS

The AIT Alert Data Set is not included; it is public and licensed CC BY 4.0
([doi:10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181)).

```bash
python data/download_ait_ads.py --download    # about 96 MB download, md5-verified, 2.9 GB unpacked
python data/download_ait_ads.py --check --full
```

`data/README.md` has the required citations, what this repository ships that was derived from AIT-ADS, and the
licences.

## Reproduce everything

```bash
bash reproduce.sh            # about 8-9 minutes; the ten-seed multiseed step is about 6 of them
bash reproduce.sh --quick    # skips the multiseed step
```

It runs the labelling, the analysis steps, all figures, the five controls and the two practices from the repository
root, and prints a pass/fail/skip summary. Measured in a fresh environment (Windows 11, Python 3.11.9):

- without AIT-ADS: 29 passed, 0 failed, 3 skipped, in 495 s
- with AIT-ADS downloaded: 31 passed, 0 failed, 1 skipped, in 548 s

The skipped steps are the Windows Sysmon process-tree build (it needs `sysmon_wincl1.evtx`, a 59 MB file that is not
distributed; the parsed `sysmon_eid1.csv` it produces is committed) and, without the data, the two steps that
recover the AIT-ADS train/test split and build the AMiner split. The committed `.npz` files those steps produce are
used instead, and when the data is present they are regenerated with identical arrays. The audit, temporal-split,
multiseed and cross-detector steps use only the committed `models_v2/ait_split.npz` and `analysis/xdet_*.npz`.

To run only the controls (the paper's Table X, ten cells) and the practices:

```bash
python controls/run_all.py
python controls/practices/run_practices.py
```

## Using the controls on another corpus

`controls/` can be reused outside this repository. Each control is a small module with a `run(...)` function that
takes plain arrays or lists; none of them depends on this project's file layout. For example, checking a rate-shaped
feature for the censored-cap failure mode that C1 catches:

```python
import sys
sys.path.insert(0, "controls")
import c1_benign_burst as C1

attack_rates = [...]   # feature values for attack-labelled rows of your corpus
benign_rates = [...]   # feature values for benign-labelled rows
result = C1.run(attack_rates, benign_rates, cap=20)   # cap=None if the feature has no structural ceiling
print(result.verdict, result.reason)
```

`docs/controls_spec.md` specifies the five controls and the two practices, with inputs, statistics, decision rules and
the parameters (`negligible`, `high`, `far_from_one`) that the paper leaves uncalibrated;
`controls/run_all.py` sweeps them and shows that this repository's verdicts do not depend on the values chosen.

## Paper figures and tables

Figures are written to `figures/out/<name>.pdf` and `.png`. "Reads" lists the committed input.

| paper item | script | reads or writes |
|---|---|---|
| Fig. 1, lookup table vs. model | `figures/fig1_lookup_vs_model.py` | `results/rule_memorization_audit/exp3_lookup_results.csv`, `exp4_ablation_main.csv` |
| Fig. 2, feature gain composition | `figures/fig2_feature_composition.py` | `results/rule_memorization_audit/exp2_importance_gain.csv`, `exp1_feature_classification.csv` |
| Fig. 3a, ablation (two panels: `fig3a_ablation`, `fig3a_thresholds`) | `figures/fig3a_ablation_separability.py` | `exp4_ablation_main.csv`, `models_v2/ait_split.npz` |
| Fig. 3b, rule 31101 raw-HTTP tier study | `figures/fig3b_31101_tier_study.py` | `analysis/fr_31101_features.csv` (from `analysis/fr_31101_feature_recovery.py`); test-set provenance in `results/tier_study_subset.md` |
| Fig. 4, OC-SVM score overlap | `figures/fig4_31101_score_overlap.py` | `analysis/ew_phase3_31101_per_alert_combined.csv` |
| Fig. 5, capture-tempo asymmetry | `figures/fig5_tempo_asymmetry.py` | `analysis/ew_features/ew_augmented_per_alert.csv` |
| Fig. 6, benign-corpus composition (`fig6_benign_composition_h`) | `figures/fig6_benign_composition.py` | `analysis/ew_features/ew_augmented_per_alert.csv` |
| Fig. 7, threshold sweeps | `figures/fig7_threshold_sweep_v5defer.py` | `analysis/threshold_sweep.csv` |
| Fig. 8, cap censoring on two datasets | `figures/fig8_cap_censoring_cross_dataset.py` | `models_v2/ait_split.npz`, `data/testbed_collection/collection_benign_lnx_alerts.csv` |
| Fig. 9 and Table (cross-detector), lookup vs. model vs. trivial | `figures/fig9_cross_detector_lookup.py`; numbers from `analysis/xdet_task1_lookup.py` and `analysis/fig9m_task2_aminer_model.py` | `analysis/xdet_task1_results.json`, `analysis/fig9m_task*_results.json` |
| Table, five controls on both corpora | `controls/run_all.py` | prints the table; specification in `docs/controls_spec.md` |
| Table, rule 31101 fields | `analysis/rule31101_fields.py` | `results/rule31101_fields.md` |
| Table, rule 31101 episodes | `analysis/rule31101_episodes.py` | `results/rule31101_episodes.md`, `.csv` |
| Table, dataset characterisation and top-ten rules | `analysis/rev_task2_dataset_chars.py` | `analysis/rev_dataset_characterisation.csv` |
| Table, train/test split sizes, temporal split, multiseed | `analysis/rev_task1_temporal_split.py`, `analysis/rev_task3_multiseed.py` | `analysis/rev_task1_temporal_results.json`, `analysis/rev_task3_multiseed_results.json` |
| Tables, XGBoost and OC-SVM configuration | none (read from the artifacts) | `docs/rev_model_config.md`; OC-SVM training and held-out sets in `results/ocsvm_training_split.md` |
| Tables, carrier type and per-rule counts | computed interactively; committed result | `docs/eval_set_definition.md`, `analysis/a10_recall_fpr_per_rule_table.csv`, `analysis/ew_carrier_tempo_table.csv` |
| Other reports | `analysis/windows_agents_sysmon.py`, `analysis/rule553_technique.py`, `analysis/nonattack_alerts_attack_rounds.py` | `results/` |
| Literature tables, testbed topology and software versions, technique context table | not produced by code | none |
| Every number quoted in the paper | claims map | `docs/claims.csv` (each row names the file that produced it; checked by `controls/practices/claim_provenance.py`) |

Two committed inputs have no generating script in this repository: `analysis/threshold_sweep.csv` (Fig. 7) and
`analysis/ew_features/ew_augmented_per_alert.csv` (Figs 5 and 6, built by an entity-window extractor that is not
included).

## Known limitations

- **One testbed.** One Linux host and one Windows host, a single attack session and a separate single benign session
  per platform, collected with Atomic Red Team and `dirb` on one lab network. All numbers are for that setup. The
  deployed one-class SVM was trained on an earlier benign history of the same Linux host; none of its training,
  held-out or threshold-selection alerts is among the evaluation alerts (`results/ocsvm_training_split.md`), but the
  host and lab are the same.
- **The benign traffic is tool-generated.** The Linux benign collection is `curl` polling three fixed endpoints plus
  daemon activity (for example the printing service rewriting a lease file); the rule 31101 attack and benign
  populations are both tool-generated. It contains no high-rate burst and no authentication failures. The benign
  corpora are small (267 Linux, 201 Windows alerts), so every false-positive rate is an estimate with that sample
  size, and several rule families have no benign alerts at all.
- **Linux labels are time-window labels, not process-tree anchored.** Audit-log rotation lost about 79% of the Linux
  collection window, so every Linux attack label comes from matching a corrected event time (recovered from the log
  line, not Wazuh's lagged ingestion timestamp) against a labelled technique window. On Windows, 55.7% of the attack
  labels are anchored in the Sysmon process tree and the rest use the same time-window fallback.
- **Capture-tempo asymmetry.** The Linux attack rounds were captured at a much higher alert rate than the benign
  round: 135.2x in mean rate over all attack-round alerts, 227.5x over the attack-labelled alerts, and a peak ratio
  of 684.0x (Windows: about 1.5x). Every rate-shaped feature on this corpus is therefore suspect until it passes
  Control C1.
- **Per-alert statistics assume independent alerts.** The rule 31101 recall (465/20,665) and FPR (10/209), and the
  tests on them, count each alert as a separate trial; `results/rule31101_episodes.md` regroups them into episodes,
  where the difference is not significant.
- **AIT-ADS split.** The benchmark split is stratified-random. Under a chronological split the lookup-vs-model gap
  persists (0.9907 vs. 0.9909).
- **The shipped XGBoost model is the deployed one.** Retraining with `phase1_xgboost.py` (AIT-ADS raw data needed)
  reproduces the split and the threshold but gives a model whose probabilities differ from the shipped one by up to
  about 0.05; the audit-time retrains used for the ablations are separate models.
- **Not every script runs from this repository.** `analysis/README.md` lists, for each script, whether it runs, needs
  the AIT-ADS data, or needs files that are not distributed. Older reports in `docs/history/` mention an earlier
  working directory, `newCol/`.

## Licence

- Code and documentation: MIT (`LICENSE`).
- Data produced by the authors (testbed collection, result tables): CC BY 4.0 (`LICENSE-DATA`).
- Files derived from AIT-ADS: CC BY 4.0, with attribution to Landauer, Skopik and Wurzenberger and citation of both
  papers listed in `data/README.md`. The raw AIT-ADS files are not redistributed here.
