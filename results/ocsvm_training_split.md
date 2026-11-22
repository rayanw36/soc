**No overlap for the deployed OC-SVM: every overlap count below is 0 (matched by alert id and by (timestamp, rule id, full_log)). Separate finding, section 6: a different, non-deployed Windows candidate (`ocsvm_xplatform_v8`, C3) was fitted on the 267 benign alerts and then scored on them.**

# OC-SVM training data and evaluation overlap

Produced by `analysis/ocsvm_training_split.py`. Read-only on every committed file.

## 0. Which model, which script, which data

- **Deployed L2:** `models_v2/ocsvm_nu05.pkl`, `OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)`; `theta_ocsvm = -0.3349956708403319` (`models_v2/thresholds_production_v3.json`).
- **Fit by:** `anomaly_model_comparison.py` (lines 55-57 and 87: fit on `train_benign_raw`). It trains nu in {0.05, 0.10, 0.15}; the threshold and the choice nu=0.05 were then fixed by `finalize_ocsvm_threshold.py` from `results_v2/anomaly_model_comparison.csv`.
- **Training data:** 80% of `results_v2/benign_baseline_clean.csv`, split by `np.random.RandomState(SEED=42).permutation(n)`, first `int(0.20 n)` rows held out. That CSV holds the 26 feature columns only, no id or timestamp. It is written by `build_clean_benign_baseline.py`, which is in the original working folder but not in this repository; its logic is reproduced in this script.
- **Source alerts:** `lnx_dmz_ai_detections.json` (the lnx-dmz DQN-watcher log; the alert is in `original_alert`), every record, all dates, labelled with the corrected 14-window list `ATTACK_WINDOWS_LNX_V2`. Benign = label 0, minus Wazuh rules 5401/5402/5403 (sudo), 5503 (PAM failure) and 52002 (AppArmor), minus anything within 60 s of a window edge.

Reconstruction checks (all pass; the script asserts the first two):

1. The rebuilt baseline has 4,257 rows and its 26 features equal `benign_baseline_clean.csv` row for row (from 9,151 label-0 alerts, 4,894 removed).
2. The 43 novel alerts below are exactly `load_lnx_detections` rows with phase NOVEL and label 1.
3. Refitting `OneClassSVM(nu=0.05, gamma='scale')` in memory on the rebuilt 3,406 training rows gives the same support vectors as the deployed pickle: **identical** (176 vs 176 support vectors; max |decision-function difference| on the held-out rows below 1e-9). So the rows listed in section 1 are the rows the deployed model was fitted on.

## 1. Training data

| | value |
|---|---|
| benign alerts trained on | **3,406** (of 4,257 cleaned; 851 held out) |
| host (agent) | `lnx-dmz-VirtualBox` (3,406) |
| agent IP | `192.168.30.31` (3,404), `None` (2) (`None` = the alert has no agent ip field) |
| first / last alert timestamp (Wazuh) | 2025-12-02T18:45:03.425112+00:00 / 2026-05-25T14:30:52.494506+00:00 |
| **first / last corrected event time** | **2025-12-02 18:40:28 UTC / 2026-05-25 14:30:51 UTC** |
| event-time source | full_log_clf: 2,896, full_log_syslog: 361, alert_timestamp: 149 |
| calendar days with training alerts (event time) | 9 days, 2025-12-02 to 2026-05-25 |
| top rules | 31101: 2,718, 31151: 178, 5501: 117, 5710: 109, 5502: 104, 2901: 45, 2902: 42, 2904: 38 |

Corrected event time is `labelling/label_lnx_timeonly.event_time` (the log line's own time where it has one, else the syscheck mtime or audit epoch, else the Wazuh timestamp). The span covers every training alert, so it includes the whole history in the file, not only the 2026-05-25 experiment day. The 267 evaluation alerts span 2026-07-12 11:11:56 UTC to 2026-07-12 12:19:51 UTC (event time).

## 2. Overlap with the 267 Linux benign evaluation alerts

The 267 are the alerts of `data/testbed_collection/collection_benign_lnx_alerts.json` (the `lnx_benign` population of every FPR in the paper; 209 of them are rule 31101). Both sides carry a Wazuh alert `id`, so the match is done on `id` and, separately, on the triple (timestamp, rule id, full_log). A looser (rule id, full_log) match without the timestamp is shown only to say whether any identical log line exists in both.

| training-side set | matched by alert id | matched by (timestamp, rule id, full_log) | looser: (rule id, full_log) only |
|---|---:|---:|---:|
| training rows (n=3406) | 0 | 0 | 11 |
| held-out benign (n=851) | 0 | 0 | 2 |
| whole cleaned baseline (n=4257) | 0 | 0 | 13 |

**Overlap count between the 3,406 training alerts and the 267: 0 by id, 0 by (timestamp, rule id, full_log).**

The looser column is non-zero: identical log text occurs in both sets at different times (these are repeating system events, not the same alert).

## 3. The held-out benign alerts used in the nu grid search

`anomaly_model_comparison.py` scores nu in {0.05, 0.10, 0.15} on the held-out 20% of the cleaned baseline plus the 43 novel attack alerts, and picks each model's threshold there. The held-out set is **851** alerts (`int(0.20 x 4,257)`), host `lnx-dmz-VirtualBox`, corrected event time 2025-12-03 07:19:51 UTC to 2026-05-25 18:49:05 UTC. Its overlap with the 267: **0 by id, 0 by (timestamp, rule id, full_log)** (table above). It is also disjoint from the training rows by construction (it is the complement in the same permutation).

## 4. The 43 novel-attack alerts and the 306 of Table XIII

- **43 alerts** (threshold selection): `load_lnx_detections` rows with phase NOVEL and label 1 in `lnx_dmz_ai_detections.json`, between 2026-05-25T13:32:39Z and 2026-05-25T18:22:46Z. Host `lnx-dmz-VirtualBox`; corrected event time 2026-05-25 14:18:41 UTC to 2026-05-25 18:10:05 UTC; rules 5402: 9, 5501: 8, 5502: 8, 5503: 6, 5401: 6, 52002: 4, 2832: 1, 11: 1; techniques T1003.008: 3, T1053.003: 1, T1548.001: 10, T1548.003: 29.
- **306 alerts** (Table XIII, `docs/eval_set_definition.md` cross-tab): the attack-labelled alerts of `data/testbed_collection/labeled_lnx.csv` whose rule is in {5710, 5712, 550, 553, 554, 5901, 5902, 5903} (`analysis/f1_phaseA_lnx.py`: 113 + 96 + 59 + 20 + 6 + 6 + 6), collected 2026-07-08.

| comparison | matched by alert id | matched by (timestamp, rule id, full_log) | looser: (rule id, full_log) only |
|---|---:|---:|---:|
| 43 novel vs the 306 | 0 | 0 | 0 |
| 43 novel vs all 23,081 alerts of the attack-round collection | 0 | 0 | 0 |
| 43 novel vs the 267 benign | 0 | 0 | 0 |

**Overlap count between the 43 novel alerts and the 306: 0 by id, 0 by (timestamp, rule id, full_log).**

What the two sets contain, by technique (the 306 use the `technique` column of `labeled_lnx.csv`; the 43 use the window technique of `ATTACK_WINDOWS_LNX_V2`):

| technique | in the 43 (threshold selection) | in the 306 (Table XIII) |
|---|---:|---:|
| T1003.008 | 3 | 0 |
| T1053.003 | 1 | 6 |
| T1098.004 | 0 | 6 |
| T1110.001 | 0 | 119 |
| T1136.001 | 0 | 163 |
| T1543.002 | 0 | 6 |
| T1546.004 | 0 | 6 |
| T1548.001 | 10 | 0 |
| T1548.003 | 29 | 0 |

Techniques present in both: T1053.003. The 43 are mostly sudo, PAM and AppArmor events; the 306 are mostly FIM and authentication-failure alerts. Different alerts, collected on different days with the same agent.

## 5. Reading this

- The deployed OC-SVM is fitted on the lnx-dmz history in `lnx_dmz_ai_detections.json` (2025-12-02 to 2026-05-25), not on the July 2026 collections. None of its training rows, none of its 851 held-out rows and none of the 43 threshold-selection alerts is among the 267 benign or the 306 novel-technique alerts, by id or by (timestamp, rule id, full_log).
- Same host (`lnx-dmz-VirtualBox`) on both sides. Training/tuning and evaluation are separate alerts, not separate environments, so this shows no alert-level leakage, not that the evaluation is out-of-environment.
- The text-only matches in section 2 (11 training, 2 held-out) are all rule 503 ("Agent started") lines, which repeat each time the agent restarts, on different dates; they are not the same alerts.

## 6. A different model that was fitted on the 267 (not the deployed L2)

The deployed L2 above never saw the July collections. A separate Windows-recalibration candidate did see the 267:

- `models_v2/ocsvm_xplatform_v8.pkl` ("C3", `analysis/v8_task1_train.py`) is an OC-SVM fitted on the fresh Linux benign collection (the same 267 alerts of `collection_benign_lnx_alerts.json`) plus 5,000 Windows old-pool rows (`results_v2/windows_recalibration_v8.md`, "What was trained on what").
- `analysis/v8_task3_lnx_regression.py` then scores C3 on those same 267 as its Linux-regression benign set; `analysis/v8_task3_same_space.csv` records FP=14, TN=253, FPR=5.2% for C3 (14/267). That FPR is measured on C3's own training alerts.
- `results_v2/windows_recalibration_v8.md` says of this set "used for *training* C3, not re-evaluated on itself elsewhere". The script and the CSV show it is re-evaluated on itself in the Linux regression guard, so that sentence does not match the code.
- Scope: C3 is a Windows-routing candidate that the same document does not select (it routes Windows to C2, `ocsvm_xplatform_v7.pkl`, which was not fitted on the 267). It is not the deployed L2, and the deployed L2's FPRs (10/209 on rule 31101, the 267-alert FPRs) are not affected. Any paper statement quoting C3's Linux FPR should say it is in-sample.

