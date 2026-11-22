# Analysis scripts: what runs, with what

Run every script from the repository root (`python analysis/<script>.py`) in the environment of
`requirements.txt`, with `PYTHONUTF8=1` on Windows. Statuses below were checked by running each script in a
clean copy of the repository with Python 3.11.9 and the pinned requirements. "Committed data" means the
files in this repository only.

Scripts that were written in an earlier working directory used a folder called `newCol/`. They now read the raw
collection files from `data/testbed_collection/` and read and write derived files in `analysis/` (the variables
`DATA` and `HERE` at the top of each script). Old docstrings and reports in `docs/history/` still mention `newCol/`.
Where the committed outputs and a regenerated output differ, the difference is stated in the table; otherwise
a rerun reproduces the committed file (CSV differences in the last digit of a float are formatting only).

## Run by `reproduce.sh`

| script | needs | output |
|---|---|---|
| `xdet_recover_wazuh_split.py`, `xdet_build_aminer.py` | AIT-ADS raw data (`python data/download_ait_ads.py --download`) | `xdet_wazuh_recovered_split.npz`, `xdet_aminer_split.npz` (arrays identical to the committed ones) |
| `xdet_task1_lookup.py` | committed data | `xdet_task1_results.json` (cross-detector table) |
| `rev_task1_temporal_split.py`, `rev_task3_multiseed.py` | committed data | `rev_task1_temporal_results.json`, `rev_task3_multiseed_results.json` (about 6 minutes for the multiseed run) |
| `rule31101_episodes.py`, `rule31101_fields.py`, `tier_study_subset.py`, `ocsvm_training_split.py`, `windows_agents_sysmon.py`, `rule553_technique.py`, `nonattack_alerts_attack_rounds.py` | committed data | one report each in `results/` |

## Run from committed data (not part of `reproduce.sh`)

`a9_acctmgmt_carrier_swap`, `art_contamination_check`, `eval_phase4` (also writes `docs/history/eval_summary.md`),
`ew_phase2_leakage_audit`, `ew_phase3_31101_case_study`, `ew_phase4_deferral_study`, `f1_phaseA_diag_l2`,
`f1_phaseA_lnx`, `f1_phaseA_v5defer`, `f1_phaseB_normalized_crossplatform`, `f1_phaseB_win`,
`fr_31101_feature_recovery` (the raw-HTTP tier study; writes `fr_31101_features.csv`), `v5_temporal_task0`,
`v5_temporal_task1`, `v5_temporal_task2`, `v8_fim_task1`, `v8_fim_task2` (run after `v8_fim_task1`),
`v8_fim_task3`, `v8_task2_eval`, `v8_task3_lnx_regression`, `v9_pretask_t1136`, `fig9m_task1_baselines`,
`lbl_signature_exclusivity`, `purity_task1`, `rev_task2_dataset_chars`, `v8_write_outputs`,
`xdet_preverdict_b1b2b3`, `xdet_task2_task3`.

## Need the AIT-ADS raw data

`fig9c1_task1_check`, `fig9m_task2_aminer_model`, `uadiv_check`, `xdet_aminer_signature_check` (also writes the
git-ignored `xdet_aminer_dominant_sig_records.csv`; see `data/README.md`).

## Cannot be rerun from this repository

| script | why |
|---|---|
| `v8_task1_train.py`, `v8_task4_l1_routing.py` | read an older Wazuh alert pool (`testAlerts/Alerts/ossec-alerts-23.json` and `-24.json`) that is not distributed; their committed outputs (`v8_task1_*.csv`, `v8_task4_l1_routing.csv`) are what the reports cite |

`v8_common.py` is a helper imported by the `v8_*` scripts, not a script to run.

## Root-level pipeline scripts

| script | status |
|---|---|
| `phase1_xgboost.py` | needs the AIT-ADS raw data (about 90 s). Reproduces `models_v2/ait_split.npz` (arrays identical) and `theta_xgb` (0.07537688442211056), but the retrained `xgb_model.pkl` is not byte-identical: its probabilities differ from the shipped model by up to 0.046 on the test split. Use the shipped model for the results in the paper. |
| `build_clean_benign_baseline.py` | runs from committed data (`lnx_dmz_ai_detections.json`); reproduces `results_v2/benign_baseline_clean.csv` exactly and also writes `benign_baseline_diff.csv` and a manifest. This is the OC-SVM's training baseline (see `results/ocsvm_training_split.md`). |
| `finalize_ocsvm_threshold.py` | runs from committed data; re-verifies the locked L2 threshold |
| `combined_decision_v3.py`, `combined_decision_v5.py`, `combined_decision_v6.py` | libraries for the deployed decision logic (v6 imports v5, v5 imports v3); `combined_decision_v3.py` also has a self-test |
| `shared_features.py`, `shared_constants.py`, `shared_constants_v2.py`, `check_rule.py` | libraries / a small utility |
| `build_expanded_benign_baseline_v6.py`, `retrain_ocsvm_v6.py` | the v6 retraining path (not the deployed L2); need `results_v2/additional_benign_31151_5710.csv` and the v6 manifest, which are not distributed. The resulting `models_v2/ocsvm_nu05_v6.pkl` is shipped. |
| `anomaly_model_comparison.py`, `anomaly_diagnostic_verdict.py` | the original OC-SVM comparison; need `torch` and files that are not distributed (`results_v2/anomaly_model_per_technique.csv`, the MemAE model). Their committed output `results_v2/anomaly_model_comparison.csv` is read by `finalize_ocsvm_threshold.py`. |
| `normalize_schema.py`, `task3_xplatform_benign.py` | need the older Wazuh alert pool (`testAlerts/`), not distributed |

## `labelling/`

`label_lnx_timeonly.py`, `label_win_provenance.py` and `verify_labels_lnx.py` run from committed data
(`reproduce.sh`). `build_sysmon_tree.py` needs `data/testbed_collection/sysmon_wincl1.evtx`, which is not
distributed.
