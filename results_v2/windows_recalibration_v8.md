# Windows recalibration (v8) — summary

## What was trained on what

| model | training data | n | session |
|---|---|--:|---|
| C1 `ocsvm_win_native_v8.pkl` (new) | Windows-only, old testAlerts pool, full train partition | 7,928 | 2025-11-23/24 (cross-session, flagged) |
| C2 `ocsvm_xplatform_v7.pkl` (existing, unretrained) | Linux old pool (5,000 cap) + Windows old pool (5,000 cap) | 10,000 | both cross-session |
| C3 `ocsvm_xplatform_v8.pkl` (new) | **Linux fresh/matched (267, 2026-07-12)** + Windows old pool (5,000 cap) | 5,267 | mixed: Linux fresh, Windows cross-session |
| REF `ocsvm_normalized.pkl` (unchanged) | Linux-only, AIT-ADS (via `v6_to_normalized`) | — | historical AIT-ADS |

All three candidates were calibrated on the **same** Windows calibration holdout (n=3,398, carved from the old testAlerts pool by the identical 70/30 seed=42 split `task3_xplatform_benign.py` used — repurposed as calibration, never touched by training) and evaluated on the **fresh, matched, held-out** Windows benign (n=201, WIN-CL1, 2026-07-12) — completely disjoint from training and calibration.

## Headline comparison (Task 2)

| row | recall T1110.001 | recall T1136.001 | FPR | F1 | saturated? |
|---|---|---|--:|--:|---|
| Table 7.5 baseline, un-normalized 26-feat | 160/160 | 8/8 | 75.1% | 0.6899 | **YES** |
| Table 7.5 baseline, normalized 22-feat | 160/160 | 8/8 | 100.0% | 0.6257 | **YES** |
| C1 Windows-native | 121/160 | 8/8 | 16.4% | 0.7818 | no |
| **C2 `xplatform_v7`** | 124/160 | 8/8 | 14.9% | **0.8000** | no |
| C3 `xplatform_v8` | 122/160 | 8/8 | 14.9% | 0.7927 | no |

Attack set: `label=='attack' & in_root_tree==True`, technique ∈ {T1110.001, T1136.001} (n=168). This replaces the earlier unrecoverable "241/8" figure — that predicate could not be found anywhere in the codebase after an exhaustive search; `in_root_tree==True` (process-tree-confirmed provenance) is the closest well-defined match (T1136.001=8 matched exactly), confirmed with you before use. Both Table 7.5 rows were **re-scored** under this same predicate so every row in this table shares an identical attack set — only the benign-side FPR methodology (model/threshold/benign set) is unchanged from the original baselines.

Both baselines' 100% recall is a saturation artifact, not detection — they flag 75–100% of benign traffic too. All three v8 candidates are genuinely non-degenerate (15–16% FPR) with real partial credit on T1110.001 and full recall on T1136.001.

## Linux regression guard (Task 3) — the real cost

**Important, verified finding:** REF (`ocsvm_normalized.pkl`) is *also* saturated on the fresh Linux benign (100% FPR at its own threshold) — not just on Windows. Every rule in the fresh Linux benign collection scores at the same ~160.87 ceiling, regardless of rule type. This means REF is not a valid "floor" for the same-space regression comparison — its 100% recall there is equally meaningless.

The real comparison is against the **frozen, currently-deployed v5-defer production pipeline** (26-feat, cross-pipeline reference): 84.3% novel recall @ 10.86% FPR, F1=0.8702.

| candidate | Windows F1 | Linux novel recall (vs. frozen v5 prod) | Linux FPR (vs. frozen v5 prod) |
|---|--:|--:|--:|
| C1 | 0.7818 | 84.3% → 47.7% (**−36.6pp**) | 10.86% → 5.6% |
| C2 | 0.8000 | 84.3% → 43.8% (**−40.5pp**) | 10.86% → 1.5% |
| C3 | 0.7927 | 84.3% → 47.7% (**−36.6pp**) | 10.86% → 5.2% |

Every candidate fixes Windows saturation convincingly but costs 37–41 points of real Linux novel-attack recall relative to the currently deployed pipeline. None of the 22-feature candidates is a like-for-like replacement for Linux production.

## L1 routing (Task 4)

L1 (`xgb_normalized.pkl`), recalibrated on the Windows calibration holdout to a sane FPR operating point (θ=0.99286, 10.1% FPR on calibration), is **fully inert** on the fresh evaluation data — 0% recall, 0% FPR, fires on nothing. Combining it into the path changes nothing for any candidate (identical recall/FPR/F1 with or without L1). **Recommendation: bypass L1 entirely for Windows, L2-only.**

## Recommendation (not a unilateral decision)

**Platform-routed architecture**, not a single unified model:
- **Linux:** keep the 26-feat v5-defer production pipeline unchanged — still the best Linux performer by a wide margin (84.3% novel recall @ 10.86% FPR vs. ~44–48%/1.5–5.6% for any 22-feat candidate).
- **Windows:** route to **C2 (`ocsvm_xplatform_v7.pkl`, unretrained, existing artifact)**, L2-only, at its calibrated threshold (θ=−0.23722). It's marginally the best of the three candidates (F1=0.8000) and requires no new model file. C3 (F1=0.7927) is a close second if a Linux-fresh-benign-informed retrain is preferred for other reasons; C1 (F1=0.7818) is Windows-only and slightly behind both.
- Bypass L1 for Windows traffic (Task 4).

This replaces the degenerate, saturated Windows number with a real one, at the honestly-stated cost of not being a unified cross-platform model — Linux and Windows need different pipelines.

## Caveats — read before citing any number here

- **Small n throughout.** Windows FPR evaluation rests on 201 fresh benign alerts; Linux fresh benign is 267. Both are single-session collections. Report every FPR here as an estimate with its sample size, not a definitive production rate.
- **Session provenance of every benign set used:**
  - Windows calibration (n=3,398) and C1/C2's Windows training data: 2025-11-23/24 — 8 months before the attack collection (2026-07-08). Cross-session, used only for training/calibration (never for the reported FPR), per Guard 1.
  - Windows FPR evaluation (n=201) and Linux regression evaluation (n=267): 2026-07-12 — 4 days after the attack collection (2026-07-08), same testbed/agent, single dedicated session, not interleaved with attacks. The best available "matched" data; not literally same-session.
  - C3's Linux training component (n=267): the same fresh/matched set as the Linux regression evaluation above — used for *training* C3, not re-evaluated on itself elsewhere.
  - REF and the frozen v5-production reference: trained on AIT-ADS / older pools entirely, predating the guarded-pipeline convention.
- **Calibration/evaluation separation:** every model here was calibrated on the 3,398-row Windows holdout and evaluated on the disjoint, never-touched 201-row fresh set. No threshold was tuned on the same data its FPR is reported on.
- **REF's saturation is not Windows-specific.** It saturates on fresh Linux benign too — treat its "reference" role in same-space comparisons as informative but not a trustworthy floor.
- **The un-normalized (26-feat) vs. normalized (22-feat) Table 7.5 baselines and the v8 candidates are genuinely different feature spaces** — the Linux regression guard's outcome-level bar (frozen v5 production) is explicitly a cross-pipeline reference, not an apples-to-apples same-space number.
- **The "241/8" provenance figure could not be recovered** from any file in this repository; `in_root_tree==True` was adopted as the best-available, confirmed predicate (160/8), not verified against an external source.

## Files

- `models_v2/ocsvm_win_native_v8.pkl` (C1, new)
- `models_v2/ocsvm_xplatform_v8.pkl` (C3, new)
- `models_v2/thresholds_v8.json`
- `results_v2/windows_recalibration_v8.csv`
- `results_v2/windows_recalibration_v8.md` (this file)
- Scripts: `newCol/v8_common.py`, `v8_task1_train.py`, `v8_task2_eval.py`, `v8_task3_lnx_regression.py`, `v8_task4_l1_routing.py`, `v8_write_outputs.py`
