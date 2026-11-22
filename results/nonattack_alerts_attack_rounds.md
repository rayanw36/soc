# The non-attack alerts in the attack rounds (Linux 312, Windows 65)

Produced by `analysis/nonattack_alerts_attack_rounds.py` from `data/testbed_collection/labeled_lnx.csv` and `labeled_win.csv`, the collection markers (parsed with the labellers' own `load_markers`), and `analysis/ew_features/ew_augmented_per_alert.csv`. Read-only.

**Short answer.** None of the 377 alerts (312 + 65) was used to train a model, to select a threshold, or in any FPR. 293 + 62 are labelled `uncertain` and dropped from every metric. The 19 + 3 labelled `benign` are not the benign class of any FPR (that is the separate benign-only collections, n=267 and n=201); they appear only as extra members of the benign class in the entity-window leakage audit and the C3 control, and in a path check (C5) that finds no path in them. All 377 also sit in the per-agent alert history that feeds the 26 features of their neighbours, and all of them are inside the row counts of the Fig. 5 tempo-asymmetry rates. Details below.

## Linux: 23,081 alerts, 22,769 attack, 312 not attack

Marked windows (from the collection markers): 48 technique windows, 5 baseline windows; first technique window starts 2026-07-08 20:22:28Z, last ends 20:47:59Z. Non-attack alerts span 2026-07-08 20:17:59Z to 21:00:59Z (event time).

How each was labelled (`label_confidence` is the labeller's own tier):

| label | tier (`label_confidence`) | alerts | what it means | top rules (id: alerts) | where it falls | median / max seconds to the nearest technique window |
|---|---|---:|---|---|---|---|
| uncertain | `UNCERTAIN-out-of-session` | 43 | outside the collection session | 5502 PAM: Login session closed.: 11; 5501 PAM: Login session opened.: 9; 550 Integrity checksum changed.: 6; 5402 Successful sudo to ROOT execu...: 5 | after the last technique window: 24; before the first technique window: 19 | 268 / 781 |
| uncertain | `UNCERTAIN-artifact-teardown` | 184 | alert's own fields name a collection artifact (e.g. `col_cron`, passwd-family files) but it is outside every technique window: attack setup or teardown, deliberately not called benign | 550 Integrity checksum changed.: 75; 553 File deleted.: 60; 5402 Successful sudo to ROOT execu...: 22; 554 File added to the system.: 21 | between windows (not in a baseline window): 96; inside a 90 s baseline window: 38; before the first technique window: 28; after the last technique window: 22 | 8 / 269 |
| uncertain | `UNCERTAIN-session-gap` | 66 | inside the collection session, outside every technique and baseline window | 80711 Auditd: Process ended abnorma...: 25; 5501 PAM: Login session opened.: 20; 5502 PAM: Login session closed.: 15; 5402 Successful sudo to ROOT execu...: 5 | between windows (not in a baseline window): 57; after the last technique window: 9 | 8 / 9 |
| benign | `BENIGN-baseline` | 18 | inside a 90 s quiet-baseline window, no collection artifact named, exact event time | 5502 PAM: Login session closed.: 8; 5501 PAM: Login session opened.: 4; 80711 Auditd: Process ended abnorma...: 3; 1010 Process segfaulted.: 2 | inside a 90 s baseline window: 18 | 9 / 12 |
| benign | `BENIGN-baseline-weak` | 1 | as BENIGN-baseline but only the Wazuh timestamp is available (18-80 s lag unresolved) | 591 Log file rotated.: 1 | inside a 90 s baseline window: 1 | 27 / 27 |

Whole group, by rule: 550: 81, 553: 65, 5502: 34, 5402: 33, 5501: 33, 80711: 28, 554: 23, 5903: 7, 591: 3, 1010: 2, 80730: 2, 5710: 1.

## Windows: 401 alerts, 336 attack, 65 not attack

Marked windows (from the collection markers): 21 technique windows, 4 baseline windows; first technique window starts 2026-07-08 22:12:40Z, last ends 23:12:23Z. Non-attack alerts span 2026-07-08 21:41:21Z to 23:26:47Z (event time).

How each was labelled (`label_confidence` is the labeller's own tier):

| label | tier (`label_confidence`) | alerts | what it means | top rules (id: alerts) | where it falls | median / max seconds to the nearest technique window |
|---|---|---:|---|---|---|---|
| uncertain | `UNCERTAIN-pre-collection` | 36 | before the first window: export padding (the export starts 30 min early) | 60106 Windows logon success.: 19; 61104 Service startup type was chan...: 5; 60642 Software protection service s...: 4; 60122 Logon failure - Unknown user ...: 2 | before the first technique window: 36 | 1077 / 1878 |
| uncertain | `UNCERTAIN-session-gap` | 10 | inside the collection session, outside every technique and baseline window | 60106 Windows logon success.: 3; 63104 A Windows log file was cleared: 3; 60642 Software protection service s...: 1; 61104 Service startup type was chan...: 1 | between windows (not in a baseline window): 10 | 3 / 9 |
| benign | `BENIGN-baseline` | 3 | inside a 90 s quiet-baseline window, no collection artifact named, exact event time | 60106 Windows logon success.: 3 | inside a 90 s baseline window: 3 | 50 / 50 |
| uncertain | `UNCERTAIN-post-marker` | 16 | after the last marked window (the markers stop mid-round 5; alerts continue) | 60106 Windows logon success.: 12; 60642 Software protection service s...: 2; 63104 A Windows log file was cleared: 1; 92052 Windows command prompt starte...: 1 | after the last technique window: 14; inside a 90 s baseline window: 2 | 590 / 864 |

Whole group, by rule: 60106: 37, 60642: 7, 61104: 6, 63104: 4, 92052: 3, 60122: 2, 92058: 2, 61102: 1, 61109: 1, 91816: 1, 92213: 1.

## Were they used anywhere?

Checked by reading every script that reads `labeled_lnx.csv`, `labeled_win.csv`, `ew_augmented_per_alert.csv` or fits a model on testbed data (grep of the repository), not by assuming.

| use | Linux (312: 293 uncertain + 19 benign) | Windows (65: 62 uncertain + 3 benign) |
|---|---|---|
| training of a deployed model (L1 `xgb_model.pkl`, L2 `ocsvm_nu05.pkl`) | no: both were fitted in June 2026, before the 2026-07-08 collection (L2 on `lnx_dmz_ai_detections.json`, see `results/ocsvm_training_split.md`) | no: same |
| training of any diagnostic model on testbed data | no. `fr_31101_feature_recovery.py`, `ew_phase3_31101_case_study.py` fit on rule 31101 only, and none of the 312 is rule 31101; `ew_phase4_deferral_study.py` fits on attack-labelled and fresh-benign rows only; `v8_task1_train.py` (Windows candidates) uses the old pool and the fresh benign collections | no: same scripts |
| threshold selection | no: thresholds were locked 2026-06-19 (`thresholds_production_v3.json`); Windows candidates calibrate on an old-pool holdout (`v8_task1_train.py`) | no |
| any FPR | no. Every FPR denominator is the benign-only collection (Linux n=267, Windows n=201). `eval_phase4.py` counts the 'benign'-labelled rows and reports FPR as not computable from them | no: same |
| attack-side recall | no: attack side is `label == 'attack'` in every script found | no |
| control C1 (cap censoring) | context only: the AgentHistory-replicated `alert_rate_1min` is computed over all rows, then masked to attack | not run |
| control C2, C4 | no: attack side only (`label == 'attack'`) | not run |
| control C3 (rule-share, pivot subset) | **yes, benign class**: the filter is `label in (attack, benign)` with no source filter. Benign members of the pivot subset: 32 from the benign collection and 5 from the attack round (rule 5501: 4, rule 5402: 1). The 293 uncertain are excluded. Dropping those 5 leaves the C3 verdict unchanged: negligible=0.0: FAIL with them, FAIL without; negligible=0.01: FAIL with them, FAIL without; negligible=0.05: FAIL with them, FAIL without | not run |
| control C5 (artifact persistence) | `label == 'benign'` rows of `labeled_lnx.csv` are read; 0 of the 19 carry a `syscheck_path`, so they contribute no path to the check | not run |
| `ew_phase2_leakage_audit.py` (entity-window MI) | **yes, benign class**: benign-labelled attack-round rows are kept, uncertain dropped (`n_uncertain_dropped`). Benign class = 19 + 267 = 286 Linux; 293 dropped | **yes**: benign class = 3 + 201 = 204; 62 dropped |
| 26 features of the attack rows (`AgentHistory`) | **yes, as context**: every alert of the session, whatever its label, is added to the per-agent history in event-time order, so the 312 shape `alert_rate_1min`, `rule_diversity_10min` etc. of nearby attack rows | same, over all 401 |
| Fig. 5 tempo asymmetry (`fig5_tempo_asymmetry.py`) | **yes**: the attack rate is all rows of source `lnx_attack` (n=23,081), no label filter. With attack-labelled rows only (n=22,769) the ratio is 227.5x instead of 135.2x | **yes**: all 401 rows; attack-labelled only (336) gives 1.7x instead of 1.5x |

## Reading this

- The 19 + 3 `benign` rows are not background traffic: `eval_phase4.py` already describes the Linux ones as attack-script side effects, and the Windows ones are three 'Windows logon success' events inside a baseline window. They should not be described as benign evaluation data. The benign class of every FPR is the separate collection.
- The two places that do treat them as benign members, the leakage audit's benign class and control C3's pivot subset, are descriptive (mutual information, rule-share) rather than FPR or recall claims. Whether to drop them there is a choice for the authors; this report only shows where they enter.
- Fig. 5's 135.2x / 1.5x use all rows of the attack-round files, including the 312 and 65. The two ratios in the table above show how far restricting to attack-labelled rows would move them.
- Control C4 restricts to attack-labelled rows, so it does not reproduce the frozen figures. Run live from `controls/run_all.py`, Linux C4 reports a mean-rate ratio of 227.5x and a peak-rate ratio of 684.0x, not 135.2x / 820.8x, although the source string it prints says it reproduces those. Recomputed three ways (Linux, mean-rate ratio / peak-rate ratio):

| attack population | benign time field | mean-rate ratio | peak-rate ratio |
|---|---|---:|---:|
| all attack-round rows, corrected `ts` | benign corrected `ts` (Fig. 5 basis) | 135.2x | 684.0x |
| attack-labelled rows only | benign corrected `ts` | 227.5x | 684.0x |
| attack-labelled rows only | benign raw `timestamp` (C4 as implemented) | 227.5x | 684.0x |

The mean-rate ratio depends on which alerts count as the attack population (the non-attack alerts lie before and after the labelled attack alerts and lengthen the span): all rows give the frozen 135.2x, attack-labelled rows give 227.5x. The peak-rate ratio is 684.0x in every variant, so none of them reproduces the frozen 820.8x; the cause of that difference is not determined here. The asymmetry is far above 1 under every variant. The scripts were not edited; which population the paper should quote is for the authors to decide.
