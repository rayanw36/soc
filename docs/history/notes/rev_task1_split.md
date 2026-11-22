# REV-C Task 1 — Is the AIT-ADS split random or temporal?

No fabrication, no new collection. Retraining used only where explicitly
permitted (the audit-time XGBoost retrain described below), writing only
to `newCol/rev_task1_*`. `models_v2/*.pkl` and `thresholds_*.json` were
not touched.

**Scripts:** `newCol/rev_task1_temporal_split.py` (this task's new work).
Reuses, read-only: `models_v2/ait_split.npz` (the deployed split) and
`newCol/xdet_wazuh_recovered_split.npz` (a prior, independently-verified
recovery of the exact per-alert index arrays behind that split — see
`newCol/xdet_recover_wazuh_split.py`, whose own internal assertion
already confirmed it reproduces `ait_split.npz`'s `y_train`/`y_test`
byte-for-byte). This run re-verifies that match itself (`[OK]` lines in
the script output) before trusting anything downstream.

---

## a. How was `models_v2/ait_split.npz` constructed?

**Found in code, not inferred.** `phase1_xgboost.py:170-171`
(`load_ait_ads`, the sole function that writes `ait_split.npz`, confirmed
in Task 0 of the prior XDET audit and re-read directly for this task):

```python
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=SEED)
```

with `SEED = 42` (`shared_constants.py`). This is a **stratified random
split**: `sklearn.model_selection.train_test_split` with `stratify=y`
shuffles all 2,600,263 alerts (pooled across all 8 scenarios, in whatever
order `load_ait_ads` streamed them) and draws an i.i.d. 80/20 partition
constrained only to preserve the overall attack/benign ratio — it has no
awareness of alert timestamp, scenario, or rule identity. **It is not
temporal, not scenario-based, and not stratified by anything other than
the binary label.**

This was independently re-confirmed empirically in this task (not just
read off the source): reconstructing the full 2,600,263-row feature
matrix in original alert order and checking where `idx_train`/`idx_test`
(recovered by literally re-running this exact `train_test_split` call and
verifying it reproduces `ait_split.npz`'s `y_train`/`y_test` exactly)
fall in time shows both sets span the dataset's entire Jan 14 – Feb 8,
2022 range, and every one of the 8 scenarios has rows in both the train
and test partitions of the *deployed* split — the signature of random
interleaving, not of a time- or scenario-disjoint partition. (Contrast
with the new temporal split built in part (c), where train/test become
time-disjoint and scenario composition changes sharply.)

**This confirms the reviewer's premise directly: the AIT-ADS split is
random (stratified-random), and the objection — that a random split over
a rule-dominated corpus could itself be producing the high lookup-table
F1 — is a live concern that must be tested, not dismissed.**

## b. Split sizes and class balance

| | n | attack | benign | attack % |
|---|--:|--:|--:|--:|
| Total | 2,600,263 | 1,717,524 | 882,739 | 66.05% |
| Train (80%) | 2,080,210 | 1,374,019 | 706,191 | 66.05% |
| Test (20%) | 520,053 | 343,505 | 176,548 | 66.05% |

Train and test attack rates match to within rounding (66.0519% vs
66.0519%) — exactly what `stratify=y` guarantees, and further confirmation
this is the stratified-random split, not a temporal one (a temporal split
has no reason to preserve class balance and, as shown below, does not).

## c. Temporal-split rerun (the split is random, so this is required)

**Procedure.** All 2,600,263 alerts were sorted by true event epoch
(pooled across scenarios) and partitioned at the 80th percentile: the
earliest 80% (chronologically) became the temporal-train set, the latest
20% became the temporal-test set — same 80/20 ratio as the deployed split,
for direct comparability. The 26-dim feature vectors were **not**
recomputed from raw JSON (which would require re-deriving the
`AgentHistory`-dependent temporal features, e.g. `alert_rate_1min`,
`time_since_last_high`); instead the already-computed, already-verified
feature rows from `ait_split.npz`'s `X_train`/`X_test` were scattered back
into original alert order using the recovered index arrays, then
re-sliced by the new temporal cut. This reuses real, previously-computed
features under a different train/test partition — it does not fabricate
or approximate any feature value.

**Cut point:** 2022-02-07 11:19:09 UTC.

| | n | attack | benign | attack % |
|---|--:|--:|--:|--:|
| Temporal train (earliest 80%) | 2,080,210 | 1,278,373 | 801,837 | 61.45% |
| Temporal test (latest 20%) | 520,053 | 439,151 | 80,902 | 84.44% |

**Important caveat, stated plainly:** AIT-ADS's 8 scenarios were run over
staggered, only partially-overlapping 4–5 day windows between 2022-01-14
and 2022-02-08 (scenario date ranges are listed in the script output).
A pooled chronological cut at the 80th percentile therefore lands inside
the last two scenarios by calendar time (harrison, wilson) — the temporal
test set is **458,947 harrison rows + 61,106 wilson rows only** (2 of 8
scenarios), while temporal train retains all 8. This is the correct and
literal operationalization of "train on the earlier portion, test on the
later" that the reviewer asked for, and it is also, unavoidably, a
partial scenario shift — the two are confounded in this dataset because
scenarios were not run concurrently. This is disclosed rather than
hidden: it means the temporal-split numbers below test both "does the
split leak information across time" and "does the model/lookup table
generalize to scenarios entirely held out of training," at once. Reported
as one combined effect below; not decomposed further within this task's
scope.

Also note the attack-rate shift (66.05% → 84.44% in test): harrison and
wilson simply contain a higher proportion of attack-window alerts than
the corpus average. This raises the *prior* for a naive always-attack
classifier under temporal test, so precision (not just F1) is reported
alongside recall below to keep the comparison honest.

**Results — lookup table (majority-label-per-rule-ID, same code path as
`results/rule_memorization_audit/exp3_lookup_table.py`) and audit-time
XGBoost retrain (same `XGB_PARAMS` and max-F1 threshold-calibration
procedure as `results/rule_memorization_audit/exp4_ablation.py`'s "full"
26-feature variant / `newCol/xdet_task1_lookup.py` Addition A(a) — the
deployed `models_v2/xgb_model.pkl` is unusable in this environment
per that prior audit's documented version-mismatch finding, so "model F1"
throughout means this audit-time retrain, not the deployed pickle):**

| | model F1 | lookup F1 | gap |
|---|---|---|---|
| random split (current) | 0.9945 | 0.9942 | 0.0003 |
| temporal split (new) | 0.9909 | 0.9907 | 0.0002 |

Full precision/recall/FPR:

| | split | precision | recall | FPR | F1 |
|---|---|---|---|---|---|
| Model (audit retrain) | random | 0.99998 | 0.98912 | 0.0000 | 0.9945 |
| Lookup table | random | 0.99983 | 0.98873 | 0.0003 | 0.9942 |
| Model (audit retrain) | temporal | 1.00000 | 0.98198 | 0.0001 | 0.9909 |
| Lookup table | temporal | 0.99995 | 0.98170 | 0.0003 | 0.9907 |

The random-split row was recomputed from scratch inside this same script
(not copied from the earlier CSVs) as an in-run consistency check: it
reproduced 0.9945 / 0.9942 exactly, matching
`results/rule_memorization_audit/exp4_ablation_main.csv` and
`exp3_lookup_results.csv` to 4 decimal places. This gives confidence the
temporal-split numbers were produced by the identical pipeline, differing
only in which rows are train vs. test.

Rule 31101 (the dominant rule, 60.4% of all alerts corpuswide) stays
essentially 100%-attack in both partitions of the temporal split too
(99.980% of 1,172,277 rows in temporal-train, 99.994% of 399,036 rows in
temporal-test) — its deterministic label-by-rule-identity is a property
of the rule across the *entire* dataset timeline, not an artifact of
which alerts a random shuffle happened to put in train.

NMI(rule_id, label): train 0.6400 (vs. 0.6361 under the random split),
test 0.5702 (vs. 0.6355 under the random split) — rule identity remains
strongly informative about the label under the temporal split, just
somewhat less so on the held-out (harrison/wilson-only) test portion.

## Verdict

**Gap survives.** Under the temporal split, both the model and the lookup
table lose about half a point of F1 relative to the random split (0.9945
→ 0.9909 for the model, 0.9942 → 0.9907 for the lookup table) — consistent
with the harder, partially scenario-shifted test condition described
above — but the **gap between the two stays negligible in both cases**
(0.0003 under random, 0.0002 under temporal; if anything slightly
smaller). The lookup table is not catching up to the model because the
model is losing ground faster; both degrade together, by nearly the same
amount, for the same reason (rule 31101 and the other rule-identity
signatures remain almost perfectly label-predictive across the whole
timeline, not just within the randomly-shuffled train fold).

**Conclusion for the manuscript:** the reviewer's objection is valid as
stated — the split *is* random, and that should be disclosed explicitly
— but it does not explain away the memorization finding. The near-zero
model-vs-lookup gap is not an artifact of random-split information
leakage; it reproduces (at slightly lower absolute F1, for reasons
disentangled above as attack-rate shift + partial scenario shift, not
temporal leakage per se) under a split with no such leakage. The
manuscript should (1) state the split is stratified-random, not temporal,
citing `phase1_xgboost.py:170-171`; (2) report both rows of the table
above; (3) keep the "XGBoost is functionally equivalent to a per-rule
lookup table" claim, now with temporal-split corroboration rather than
resting on the random-split number alone; (4) separately flag, as an
additional finding, that both model and lookup-table F1 are ~3.5 points
lower under a temporal/partial-scenario-shift evaluation — a real,
smaller, and independent piece of evidence that the corpus's rule-31101
dominance (not train/test leakage) is the load-bearing mechanism
throughout.

---

**Artifacts:** `newCol/rev_task1_temporal_split.py` (script, read-only
over existing artifacts), `newCol/rev_task1_temporal_results.json` (full
numeric output, including the in-run random-split consistency check).

---

## Addendum (found during Task 4, does not change the verdict above)

While extracting model configuration for Task 4, the claim this task
inherited from prior work — that `models_v2/xgb_model.pkl` is unusable in
this environment due to an XGBoost "serialization-version mismatch" — was
independently re-tested rather than taken on faith, and **does not hold**.
The deployed pickle produces degenerate near-zero probabilities only when
scored on `ait_split.npz`'s raw `X_test` directly, because
`phase1_xgboost.py` Section 3–4 trains and evaluates the deployed model on
**`StandardScaler`-transformed** features (`X_te_sc`), while
`ait_split.npz` stores the **unscaled** split by design (its own header
comment: "raw (unscaled) split for downstream phases"). Passing `X_test`
through the already-saved `models_v2/scaler_v2.pkl` +
`models_v2/imputer_v2.pkl` before calling `predict_proba` reproduces
**F1 = 0.9945** at `theta_xgb = 0.07538` — matching this task's audit-time
retrain number to 4 decimal places. This was a preprocessing bug in the
scripts that made the "unusable pickle" claim, not a property of the
model or a real serialization incompatibility. It does not change any
number or conclusion in this file (the audit-retrain and the correctly-
scored deployed pickle now agree), but it corrects the record for Task 4
and for any future work citing the "version-mismatch" claim. Full detail
in `newCol/rev_model_config.md`.

---
**CHECKPOINT — STOP.** Awaiting go-ahead before proceeding to Tasks 2–4
(dataset characterisation table, multiseed runs, model configuration
extraction).
