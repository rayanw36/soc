# Figure inventory (PRE-MS)

Inventory only — no new figures created in this pass. Method: every
`.png`/`.pdf`/`.svg` under the project root was enumerated; each was traced
to its producing script/notebook via `grep -rn savefig` and direct reading
of that script's docstring/title text (not guessed from filename alone,
except where explicitly flagged below as filename-only). Status
(current/superseded/retracted/abandoned-architecture) is assigned from
what the producing code says it computes and which dataset/config it
uses, cross-checked against what this project's later work
(`models_v2/`, `newCol/`) has since established. Grouped by era/directory
because figures within one producing script share one status and
reasoning — repeating the same paragraph 39 times would bury the signal.

**Format note that applies to every figure below, not repeated per row:**
all are raster PNG (`matplotlib`, `dpi` 100–300, resolutions 683×547 up to
3900×1650 — see per-group tables). None are vector format (SVG/PDF).
Resolution is generally adequate for a manuscript at normal print size;
vector regeneration would be preferable for anything going to a journal
that requires it, but that is a format preference, not a defect.

---

## Group 1 — Current (`newCol/`): this manuscript's actual evidence

| file | producing script | shows | supports | status |
|---|---|---|---|---|
| `newCol/ew_fig_31101_before_after.png` (2200×1000) | `newCol/ew_fig_31101_before_after.py`, also reproducible via `newCol/ew_phase3_figure.ipynb` | left panel: per-alert OC-SVM score overlap for rule 31101 (the undecidability proof); right panel: the same alerts aggregated to entity-windows (Phase 3 case study) | the 2.25% recall / 4.78–4.8% benign-FPR per-alert-undecidability finding, and the EW mechanism demonstration (n=7 windows) | **current, but must carry two caveats already on record and not yet folded into the figure's own caption**: (1) Phase 3d — this demonstrates mechanism only, not deployment-grade generalization (3 attack-side windows, one attacker, one host); (2) Phase 3e (added this session) — both sides of the left panel are tool-generated HTTP traffic (`dirb` vs `curl`), not attack-vs-organic. If this figure is reused in the manuscript, the caption must state both, not just cite the figure as the undecidability proof standalone. |
| `newCol/fnr_tp_threshold_v5defer.png` (3900×1650, byte-identical to `plots_v2/fnr_tp_threshold_v5defer.png`) | `newCol/fnr_tp_threshold_v5defer.py` | Panel A: L1 threshold sweep, known attacks (31101/31151) vs fresh benign — flat by construction (defer suppresses L1 for these rules); Panel B: L2 threshold sweep, novel attacks vs fresh benign — genuine FN/FP tradeoff | the deployed v5+defer production config (`theta_xgb=0.07538`, `theta_ocsvm=-0.33500`, `models_v2/rule_confound_fixes_v5.json`) — the same config used throughout ART-C, A7–A10, and the FIX 1–4 corrections | **current** — this is the canonical production config used everywhere else in this phase of the study. Publication-quality as-is; no known caveat outstanding against it. |

---

## Group 2 — `plots_v2/`: pre-confound-fix "deployed v6" era (superseded)

**Common defect, stated once:** every confusion-matrix/threshold figure in
this group evaluates against the **original held-out benign set (851
alerts)**, not the fresh 267-alert Linux benign collection this later
phase's entire FPR analysis (A7–A10, ART-C, FIX 1–4) is built on, and
predates the v5-L2-revert decision (`f1_phaseA_v5defer.py` found v6
bought no FPR improvement while collapsing 31151/5710 recall — see that
script's own docstring). They report the R3/R4 "deployed v6" headline
numbers (R3 recall 74.4%, R4 combined FPR 7.1%) as clean figures, without
any of the rule-composition, memorization, or carrier-classification
caveats this project later established. **None of these present the
F1=0.8702 or v8 F1=0.80 numbers specifically — checked directly, neither
literal figure exists anywhere in this repository as a plotted number —
but they are superseded for the same underlying reason: a different,
earlier evaluation config than everything reported from A7 onward.**

| files | producing script(s) | shows |
|---|---|---|
| `confusion_matrices_combined_v6.png` (2100×1050), `confusion_matrix_known_attacks_v6.png` / `confusion_matrix_novel_attacks_v6.png` (975×900 each), `combined_cm.png` (1800×540) | `plot_confusion_matrices_v6.py` | "presentation-ready" confusion matrices, deployed v6 thresholds, both phases — script's own docstring states Task 2's 4.2% FPR is L2-in-isolation, explicitly distinct from combined R4=7.1% |
| `confusion_matrices_combined_bestf1_v6.png`, `confusion_matrix_known_attacks_bestf1_v6.png` / `confusion_matrix_novel_attacks_bestf1_v6.png` | `plot_confusion_matrices_bestf1_v6.py` | same, but at best-F1 threshold instead of deployed — a teaching figure showing L1 threshold tuning alone cannot fix FPR (92%→80% at best, F1 0.919→0.927) |
| `fnr_combined_meeting_v6.png` (2600×975), `fnr_l1_known_attacks.png`, `fnr_l2_novel_attacks.png` (1300×780 each) | `plot_fnr_l1_known_attacks.py`, `plot_fnr_l2_novel_attacks.py`, `plot_fnr_combined_for_meeting.py` | FN/TP vs. threshold, same v6/851-benign config |
| `threshold_cost_curve.png`, `threshold_comparison_all.png`, `threshold_comparison_phase1_vs_phase2.png`, `threshold_fn_tp_phase2_novel.png` | `phase1_xgboost.py`, `phase5_final_report.py`, `phase2_novel_threshold_plot.py` | threshold-sweep/cost-curve exploration, same era |
| `cross_platform_confusion.png` (1381×593) | `phase3_normalized_v7.py` | Windows/Linux normalized cross-platform confusion — predates the later `f1_phaseB_normalized_crossplatform.py`/v8 work entirely |
| `xgb_cm_lnx_dmz.png`, `xgb_cm_ait_ads.png`, `xgb_vs_dqn.png`, `threshold_cost_curve.png`, `shap_feature_importance.png`, `training_curves.png`, `roc_curves_ait_ads.png`, `roc_curves_real.png`, `pr_curves_real.png`, `confusion_matrices_ait_ads.png`, `rule_overlap_matrix.png` | `phase1_xgboost.py` / `phase1_novelty_v7.py` | Phase-1-era XGBoost-only training curves, SHAP importance, ROC/PR curves, AIT-ADS confusion matrix, rule-overlap heatmap |
| `domain_distribution_gap.png`, `domain_shift_comparison.png`, `coral_comparison.png`, `transfer_comparison.png` | `phase4_transfer.py` | CORAL domain-transfer experiment (AIT-ADS → lnx-dmz) |
| `requirements_radar.png` (960×960) | `phase5_final_report.py` | project-requirements-satisfaction radar chart — not a model-performance figure at all; likely still usable as-is in a methodology/scope section, not a results section |

**Verdict for the whole group: superseded.** Not individually retracted
(none states F1=0.8702 or v8=0.80), but every one evaluates a
pre-confound-fix config against a benign set this project no longer uses
as its FPR baseline. **Must not be presented as the current production
system's performance without relabeling** — if reused at all, only as
explicitly-dated intermediate/development-history figures.

## Group 2b — `plots_v2/`: abandoned alternative architectures (not superseded results, never-adopted paths)

| files | producing script | shows |
|---|---|---|
| `memae_training_curve.png`, `memae_recon_errors.png`, `memae_threshold_calibration.png`, `memae_v2_reconstruction_errors_clean_baseline.png` | `phase2_memae.py`, `phase2_memae_v2.py` | a Memory-Augmented Autoencoder (MemAE) anomaly detector — an alternative to the OC-SVM L2 that is not part of the current production pipeline (`models_v2/ocsvm_nu05.pkl` is what's deployed) |
| `rl_training_curves.png`, `rl_threshold_evolution.png` | `phase3_rl_feedback.py` | a reinforcement-learning threshold-adaptation agent — also not part of the current production pipeline |
| `anomaly_model_comparison_per_technique.png`, `anomaly_model_score_distributions_all.png`, `anomaly_model_aggregate_recall.png` | `anomaly_model_comparison.py` | head-to-head comparison across anomaly-model candidates (presumably including OC-SVM, MemAE, and others) |

**Verdict: not "superseded" in the sense of a corrected number — these
document architectures that were evaluated and not adopted.** Potentially
legitimate for a manuscript "alternatives considered" subsection, but
must not be captioned as describing the deployed system, and their
underlying numbers were never carried forward into any later phase of
this study (not referenced anywhere in `newCol/`).

---

## Group 3 — `plots/`, `EvalSteps/plots/`, `EvalSteps/evaluating/`: earliest evaluation era (superseded, pre-dates fresh collection entirely)

Traced to `EvalSteps/step1_linux_eval_v2.ipynb`, `EvalSteps/step2_windows_eval.py`,
`EvalSteps/step3_guide_eval.py`, `src/gen_notebooks.py`, `src/create_nb.py`,
`EvalSteps/evaluating/thr.py`. These evaluate against **AIT-ADS test-split
data and an earlier "real data" extraction** — one cell in
`step1_linux_eval_v2.ipynb` literally compares "AIT-ADS test split
(F1=0.9897)" against "Previous real data (F1=0.0123)," confirming this
predates the Wazuh live-collection work this entire later phase of the
project is built on.

| files | notebook/script | shows |
|---|---|---|
| `EvalSteps/plots/step1_*.png` (5 files: confusion_matrices, key_finding, per_technique_cm, roc_curves, score_distributions) | `EvalSteps/step1_linux_eval_v2.ipynb` | AIT-ADS vs. novel-attack vs. combined phase comparison, per-technique confusion matrices, F1/AUC bar chart across 5 dataset variants |
| `EvalSteps/plots/step2_*.png` (5 files), `plots/step2_*` overlap by name only (different directory, same producing family) | `EvalSteps/step2_windows_eval.py`, `src/gen_notebooks.py` | Windows-model training loss, confusion matrix, cross-model/phase comparison |
| `EvalSteps/plots/step3_*.png` (6 files) | `EvalSteps/step3_guide_eval.py`, `src/gen_notebooks.py` | guide-model training loss/confusion matrix, all-models comparison, 3-way comparison, phase breakdown, ROC curves |
| `EvalSteps/evaluating/threshold_*.png` (9 files: fn_tp / metrics / tradeoff × {ait-ads, all, novel}) | `EvalSteps/evaluating/thr.py` | threshold sweeps, same AIT-ADS-era data, three data-slice variants each |
| `plots/training_curves.png`, `roc_curves_ait_ads.png`, `confusion_matrices_ait_ads.png`, `roc_curves_real.png`, `domain_shift_comparison.png`, `pr_curves_real.png` | `src/create_nb.py` | earliest-era training/ROC/PR/confusion/domain-shift figures — root-level `plots/` predates even `plots_v2/`'s v6 naming |

**Verdict: superseded**, by construction — different data era entirely
(AIT-ADS-only, pre-Wazuh-collection), several full pipeline generations
before the current production config. Useful only as project-history
context, never as a results figure for this manuscript's actual claims.

---

## Group 4 — `img/`: provenance not fully confirmed, likely superseded duplicates

| file | producing script | notes |
|---|---|---|
| `img/cm.png` (683×547) | **not definitively traced** — no exact-path `savefig("img/cm.png", ...)` call found anywhere in the repo; only substring false-matches on other scripts' filenames | filename-only inference: a generic confusion-matrix export |
| `img/confusion_matrix_fixed.png` (720×480) | `src/soc_dqn_fixed_extracted.py` saves to bare `confusion_matrix_fixed.png` (repo root, not `img/`) — likely a manually relocated copy, not reproduced by re-running that script as committed | DQN-model confusion matrix — abandoned-architecture category (Group 2b's reasoning applies), not the deployed pipeline |
| `img/confusion_matrix_real.png` (750×600) | `src/eval_real_data_extracted.py` saves to bare `confusion_matrix_real.png` — same relocation note | earlier "real data" evaluation, same era as Group 3 |
| `img/confusion_matrix_real_comparison.png` (1650×600) | `src/eval_real_data_extracted.py` | same |

**Verdict: superseded**, same reasoning as Groups 2/3, plus an
unresolved provenance gap (exact producing invocation not confirmed for
`cm.png`; the other three are inferred from a bare-filename match, not a
path match, so treat the mapping as probable, not certain).

---

## Group 5 — Non-figure PDFs (out of scope for this inventory's "reuse" question, listed for completeness)

`Sources/*.pdf` (10 files), `Progress1/*.pdf` (2 files),
`SOC Alert Fatigue Mitigation using Wazuh and AI_ A Literature Review.pdf`
(root, duplicate of the one in `Progress1/`), `VersionPinning/Lab_Configuration_Report_Detailed.pdf`,
`VersionPinning/Screenshot 2025-10-06 112010.png` — literature-review
sources, prior progress-report submissions, and lab-infrastructure
documentation. None are result figures produced by this project's own
pipeline; not evaluated for current/superseded status since that question
does not apply to them.

---

## Figures that MUST NOT be reused as-is (flagged explicitly, per the prompt's instruction)

**No figure in this repository was found to plot the literal F1=0.8702 or
v8 F1=0.80 headline numbers** — checked directly (`grep` for both values
across every plotting script; neither appears). Those two retracted
numbers exist only as text/table claims in `newCol/*.md` and
`newCol/f1_final_summary.md`/`f1_final.csv`, not as a rendered figure, so
the specific reuse risk the prompt anticipated does not materialize for
any existing image. The real reuse risk is broader than those two named
numbers:

- **Every figure in Group 2 and Group 3** (≈55 files) presents a
  pre-confound-fix, pre-fresh-collection evaluation as if it were current.
  None carries any caption noting the benign-collection gaps, the
  rule-composition confounds, or the defer-mechanism justification this
  later phase established. If any of these ship in the manuscript without
  an explicit "intermediate/development-history" label and a
  cross-reference to the current numbers, a reader will reasonably take
  R3=74.4%/R4=7.1% (or the AIT-ADS-era F1s) as this project's reported
  result, which they are not.
- **`newCol/ew_fig_31101_before_after.png`** (Group 1) is current and
  correct, but its existing caption (in `newCol/ew_phase3_31101_case_study.py`/`.md`)
  predates this session's two caveats (3d generalization limits, 3e
  tool-generated-traffic). It must not be captioned as a clean
  attack-vs-benign undecidability demonstration without both.

**CHECKPOINT: `newCol/figure_inventory.md`. STOP.**
