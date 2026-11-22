# Working reports behind the paper (frozen)

The files in this folder are the working reports written while the study was being done, kept as an audit trail
for the numbers in the paper. They are **frozen**: terminology, file paths and control numbering predate the final
paper, and they are not edited. **The paper and the top-level documents (`README.md`, `docs/controls_spec.md`,
`docs/eval_set_definition.md`, `docs/rev_model_config.md`, `docs/rev_multiseed.md`, `docs/claims.csv`) are
authoritative.**

Reading notes:

- **Paths.** Reports refer to an earlier working directory, `newCol/`. In this repository the raw collections are in
  `data/testbed_collection/` and the derived files are in `analysis/`. Reports also refer to each other by bare file
  name; all of them are in this folder (or in `notes/`).
- **Working notes not distributed.** Some reports and script docstrings cite caption drafts, figure follow-up lists
  and number-fix notes (`captions.md`, `fig_corrections.md`, `fig_followups.md`, `pre_ms_number_fixes.md`). Those
  were working material for the manuscript and are not part of this repository.
- **Control numbering.** Earlier drafts used seven controls. The paper uses five, C1-C5. Old to new:

  | in these reports | now |
  |---|---|
  | C1 benign burst | C1 |
  | C2 benign failure events | C2 |
  | C3 rule composition | C3 |
  | C4 small-n hyperparameter determinism | a practice (`controls/practices/small_n_determinism.py`), not a control |
  | C5 capture tempo | **C4** |
  | C6 claim provenance | a practice (`controls/practices/claim_provenance.py`), not a control |
  | C7 post-attack artifact persistence | **C5** |

  For example, `fr_31101_report.md` says "control 4" for small-n determinism and `ew_results_report.md` says
  "control 6" for claim provenance.
- **The word "memorization".** The reports use it for what the paper calls a rule-identity shortcut. The directory
  `results/rule_memorization_audit/` keeps its name for that reason.
- **Superseded explanations.** Several reports (`xdet_results.md`, `sources.md` and others) say the deployed XGBoost
  model could not be scored because of a serialization-version mismatch. That was wrong: it was a scaling error in
  the scoring step, and the deployed model gives F1 = 0.9945 when scored through its own scaler and imputer
  (`docs/rev_model_config.md`).
- **Tempo figures.** `135.2x` and `820.8x` in these reports are the frozen values at the time. In this repository
  the Linux mean-rate ratio is 135.2x over all attack-round rows and 227.5x over attack-labelled rows, and the peak
  ratio is 684.0x in both; 820.8x is not reproduced (see `controls/c4_capture_tempo.py`).
- **Audit-time retrain threshold.** `sources.md`, `xdet_86601_numbers.md` and `xdet_results.md` quote the F1-optimal
  threshold of the audit-time XGBoost retrain as 0.37981 (and 0.42313, 0.39006 for the ablation variants). Those values
  come from an earlier run. Rerunning `results/rule_memorization_audit/exp4_ablation.py` in the pinned environment
  gives 0.41783, 0.40135 and 0.38974; the full-model value agrees with `analysis/rev_task1_temporal_results.json`. The committed
  `exp4_ablation_*.csv` and the `theta_audit_retrain` field of `analysis/xdet_task1_results.json` were regenerated.
  F1, recall and FPR are unchanged (0.9945, 0.9891, 0.0000 for the full model); only the thresholds, and the
  per-technique recalls that depend on them, differ.
