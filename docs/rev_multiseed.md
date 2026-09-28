# REV-C Task 3 — Headline-number classification, multiseed runs, Wilson intervals

Scripts: `newCol/rev_task3_multiseed.py` (10 seeds × 4 model-fit
configurations; raw output `newCol/rev_task3_multiseed.log`, full numeric
output `newCol/rev_task3_multiseed_results.json`), Wilson intervals
computed directly from `newCol/a8_fp_rule_breakdown.csv`. No existing
artifact modified; `models_v2/*.pkl` and `thresholds_*.json` untouched.

## a. Classification of every headline number

Note on scope: as established in Task 4, the manuscript's own LaTeX/PDF
source was not found in this local checkout (`Sources/*.pdf` are
downloaded related-work papers, not our manuscript). The classification
below covers every headline number this response actually cites or that
the task brief names — i.e. the computational results that back the
manuscript's claims — rather than a page-by-page manuscript audit that
isn't possible from what's on disk here.

| category | what belongs here | seed variance? |
|---|---|---|
| **Deterministic** | counts, ratios, distributions, split sizes, the majority-label lookup table (a majority vote has no RNG), NMI, per-rule tallies, tempo/share percentages, dataset composition (93=30+29+34), rule-31101 dominance figures | none — exact, report as-is |
| **Model-fit, stochastic under seed** | XGBoost variants: `full`/`no_identity`/`behav_only` (random split), audit-time retrain (temporal split) — `XGBClassifier(random_state=...)` with `subsample=0.5` controls per-tree row sampling, so different seeds build different trees | yes — quantified below |
| **Model-fit, but *not* stochastic** | the deployed/audit One-Class SVM — `sklearn.svm.OneClassSVM` has **no `random_state` parameter at all** (verified against the sklearn 1.9.0 API in this task, not assumed); its libsvm QP solve is deterministic given fixed data and hyperparameters. Refitting it never changes the result. | none — deliberately not seeded (see Task 4b) |
| **Proportion-based, small denominator** | rule-31101 FPR (10/209), and the other per-rule benign-side FP counts in `newCol/a8_fp_rule_breakdown.csv` (550: 3/6, 553: 1/1, 554: 1/2, 5402: 10/10, 52002: 2/2, 5502: 1/11, 5501: 1/22) | not a seed question — a sampling-uncertainty question; Wilson 95% CI reported below instead |

The lookup table deserves a specific note since it is easy to
mis-classify: it is **model-fit** (fit on training data) but **not
stochastic** — `{rule_id: majority_label}` from a `Counter` has no random
component, so it belongs with the deterministic quantities for the
purpose of *seed* variance, even though it is refit per split. Its
uncertainty, if any were needed, would be a sampling question (how much
would the majority label change on a different draw of the same corpus),
not a seed question — out of scope here since we have the entire corpus,
not a sample of it.

## b. Multiseed results (10 seeds, 0–9) for every stochastic model-fit number

Same audit-time `XGB_PARAMS` and max-F1 threshold-calibration procedure
as `results/rule_memorization_audit/exp4_ablation.py` / Task 1, varying
only `random_state`.

| configuration | n seeds | F1 mean ± SD | F1 95% CI | min–max |
|---|--:|---|---|---|
| random split, `full` (26 feat) | 10 | 0.994526 ± 0.0000016 | [0.994525, 0.994527] | 0.994523–0.994528 |
| random split, `no_identity` (23 feat) | 10 | 0.994518 ± 0.0000030 | [0.994516, 0.994520] | 0.994513–0.994522 |
| random split, `behav_only` (3 feat) | 10 | 0.989462 ± 0.0 (exact) | [0.989462, 0.989462] | 0.989462–0.989462 |
| temporal split, `full` (26 feat) — **added per instruction** | 10 | 0.990898 ± 0.0000033 | [0.990896, 0.990900] | 0.990892–0.990902 |

`behav_only`'s **exact-zero** SD across all 10 seeds is a genuine
empirical result, not a display-rounding artifact — the raw per-seed
values in `rev_task3_multiseed_results.json` agree to all 15 printed
decimal digits. With only 3 continuous behavioral features and
`subsample=0.5`, different row subsamples evidently converge to
functionally identical split structure at `max_depth=5`; this is reported
as observed, not smoothed over.

**The gap, with its own interval (this is the number the reviewer would
ask about):**

| | lookup F1 (deterministic) | model F1 mean ± SD (10 seeds) | gap mean ± SD | gap 95% CI |
|---|---|---|---|---|
| random split | 0.9942476 | 0.9945258 ± 0.0000016 | 0.000278 ± 0.0000016 | [0.000275, 0.000281] |
| temporal split | 0.9907398 | 0.9908976 ± 0.0000033 | 0.000158 ± 0.0000033 | [0.000151, 0.000165] |

**Both gap intervals sit entirely below 0.0003 and nowhere near zero
crossing in the direction that would matter (i.e. the gap does not
plausibly reverse sign or grow to a size that would undercut the
memorization claim).** If anything, the temporal-split gap's interval is
*below* the random-split gap's interval — consistent with, not
contradicting, Task 1's "gap survives" verdict. A 0.0002 gap on a single
seed was a legitimate thing to double-check; it turns out to be a stable
0.00016–0.00028 band across 10 independent refits, not a coincidence of
one draw.

## c. Wilson 95% intervals for small-denominator proportions

From `newCol/a8_fp_rule_breakdown.csv` (per-rule false-positive counts on
the fresh 267-alert live benign collection; 31101 is 78.3% of that
collection by itself, hence its much larger denominator and much tighter
interval than the others):

| rule | x/n | point FPR | Wilson 95% CI | width |
|---|---|--:|---|--:|
| 31101 | 10/209 | 4.8% | [2.6%, 8.6%] | 6.0pp |
| 5402 | 10/10 | 100.0% | [72.2%, 100.0%] | 27.8pp |
| 550 | 3/6 | 50.0% | [18.8%, 81.2%] | 62.5pp |
| 52002 | 2/2 | 100.0% | [34.2%, 100.0%] | 65.8pp |
| 553 | 1/1 | 100.0% | [20.7%, 100.0%] | 79.3pp |
| 5502 | 1/11 | 9.1% | [1.6%, 37.7%] | 36.1pp |
| 5501 | 1/22 | 4.5% | [0.8%, 21.8%] | 21.0pp |
| 554 | 1/2 | 50.0% | [9.5%, 90.5%] | 81.1pp |

31101's interval is comfortably tight (6.0pp wide) because its
denominator (209) is two orders of magnitude larger than every other rule
here — this is the one number in this table precise enough to defend as
a point estimate. **Every other rule's interval is 20–81 percentage
points wide** — several span from near-zero all the way to 100%. The
existing report language (`ew_carrier_classification.md`) already
described these as "1–22 times" occurrences and did not overstate them as
precise rates; this Wilson-interval treatment makes that caveat
quantitative rather than qualitative, and should be the version cited in
the manuscript response: e.g. "rule 550: 3/6 (50%, Wilson 95% CI
18.8–81.2%)" rather than "50%" bare.

## d. Does any conclusion change under variance?

**No — stated explicitly, as requested.** Checked against every number
above:

- The model-vs-lookup **gap** (Task 1's central finding) stays in a
  narrow, non-zero-crossing band under 10 seeds on both splits (§b) — the
  "gap survives" verdict is unaffected.
- The ablation ordering (`full` ≈ `no_identity` ≫ `behav_only`, i.e.
  removing rule-identity features costs ~0 F1 while removing everything
  *but* behavioral features costs ~0.5 F1) is unchanged and, for
  `behav_only`, exactly reproduced at every seed.
- None of the small-denominator per-rule FPRs in §c change which side of
  a meaningful threshold they fall on merely by widening to their Wilson
  interval — 31101 remains clearly low (upper bound 8.6%, well under the
  ~50%+ every other rule's interval reaches), and every other rule's
  interval already spans wide enough that the manuscript should not have
  been citing them as precise percentages regardless of seed variance —
  this is a **presentation** correction (state the interval), not a
  **conclusion** correction (nothing here reverses).

The one thing this task changes is emphasis, not substance: report
`behav_only`'s F1 without a ± (it has none), report the gap with its
interval instead of as a bare 4-decimal number, and replace every bare
small-*n* percentage in the manuscript with its Wilson interval.

---
**CHECKPOINT — deliverable for Tasks 2–4 batch, see also
`newCol/rev_dataset_characterisation.csv`, `newCol/rev_dataset_table.tex`,
`newCol/rev_model_config.md`.**
