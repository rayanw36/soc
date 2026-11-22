# Correction to `exp1_feature_classification.csv` — `time_since_last_high`

`results/rule_memorization_audit/exp1_feature_classification.csv` is a
committed, pre-existing artifact and is **not edited in place** (project
rule). This file is the append/supersede correction record for one row of
that CSV, per FIG-C Task 2.

## The correction

`exp1_feature_classification.csv` row 23 classifies `time_since_last_high`
as **BEHAVIORAL**, with its own justification text already flagging this as
"Borderline but placed here as the temporal gap carries independent signal
beyond rule identity."

The TEMPO-AIT check (`newCol/figures_ms/tempo_ait_check.md`, Task 2) and
Fig 3a's right panel established directly from `shared_features.py` that
this feature measures **seconds since the last alert with `rule.level >=
10`** — i.e., proximity to a rule-**severity** event. `rule_level` itself
is classified **RULE-IDENTITY** in this same exp1 CSV (row 2: "Wazuh rule
severity level ... is set in the rule XML definition and is constant per
rule"). A feature whose defining event-detector is itself rule-identity
metadata is not measuring an independent behavioral pattern; it is
measuring elapsed time relative to a rule-metadata event, which is closer
in kind to the RULE-CORRELATED features that already aggregate rule
metadata over a window — `high_sev_ratio_20` ("Fraction of last 20 alerts
with rule.level >= 8 ... aggregates rule severity metadata over a window,
not an independent behavioral signal") and `rule_diversity_10min` ("counts
distinct rule identifiers ... an aggregation of rule-identity values over
time"), both RULE-CORRELATED in the original file for exactly this reason.

**Correction: `time_since_last_high` is reclassified from BEHAVIORAL to
RULE-CORRELATED**, for the same reasoning already applied to
`high_sev_ratio_20` and `rule_diversity_10min` in the original file. No
other row is changed. `exp1_feature_classification.csv` itself is left
untouched; this file is the authoritative correction going forward.

## Revised bucket counts (of 26 features)

| bucket | original count | corrected count |
|---|--:|--:|
| RULE-IDENTITY | 3 | 3 (unchanged) |
| RULE-CORRELATED | 20 | **21** |
| BEHAVIORAL | 3 | **2** |

BEHAVIORAL is now `alert_rate_1min` and `unique_src_ip_10min` only.

## Revised gain shares

Source: `results/rule_memorization_audit/exp2_importance_gain.csv`
(`gain_pct` column, summed per bucket; `time_since_last_high`'s own
`gain_pct` = 2.8150628664271693%, moved from the BEHAVIORAL sum to the
RULE-CORRELATED sum).

| bucket | original gain share | corrected gain share |
|---|--:|--:|
| RULE-IDENTITY | 0.7709% | 0.7709% (unchanged) |
| RULE-CORRELATED | 95.4914% | **98.3065%** |
| BEHAVIORAL | 3.7376% | **0.9226%** |

Recomputed directly from the CSV (script: ad hoc, summed `gain_pct` grouped
by `bucket`, with `time_since_last_high`'s row moved between groups before
summing); the three corrected shares sum to 100.0004% (rounding of the
underlying `gain_pct` column, same as the original three summed to
100.0000% exactly only because rounding happened to cancel — not a new
discrepancy introduced by this correction).

**Consequence for the paper's strongest quantitative claim:** after this
correction, genuinely BEHAVIORAL features carry only **0.92% of the
26-feature model's split gain** — not 3.7%. Combined with RULE-IDENTITY's
0.77%, **rule-definition metadata of some form (RULE-IDENTITY +
RULE-CORRELATED) accounts for 99.08% of gain**, essentially the entire
model.

## Fig 2 caption one-liner — updated

Old (`captions.md`, Fig 2 caveats): "of the 26 features, 3 are
RULE-IDENTITY, 20 are RULE-CORRELATED, 3 are BEHAVIORAL."

New: "of the 26 features, 3 are RULE-IDENTITY, 21 are RULE-CORRELATED, 2
are BEHAVIORAL (`time_since_last_high` reclassified from BEHAVIORAL to
RULE-CORRELATED — see `feature_classification_correction.md` — since its
mechanism is proximity to a rule-severity event, the same category of
signal as `high_sev_ratio_20`/`rule_diversity_10min`)."

Applied directly to `captions.md` in this same pass.

## Is Fig 2's plotted bar affected? Checked, not assumed.

Fig 2 plots `is_web_attack`'s gain share (94.99%, "95.0%") against the sum
of the other 25 features' gain share (5.01%, "5.0%"). This split is by
**individual feature identity** (`is_web_attack` vs. everyone else), not
by bucket label. `time_since_last_high` was one of "the other 25 features"
under the old taxonomy and remains one of "the other 25 features" under
the corrected taxonomy — its bucket relabeling moves it between
BEHAVIORAL and RULE-CORRELATED, but it never was, and still is not,
`is_web_attack` itself. Verified directly: re-ran the summation in
`fig2_feature_composition.py` with `time_since_last_high`'s bucket field
changed and confirmed `other_gain_pct` (which sums `gain_pct` over every
non-`is_web_attack` row, regardless of bucket) is numerically identical
either way, since it was never computed by bucket in the first place. **No
change to Fig 2's plotted bar or its 95.0%/5.0% values.** Only the
caption's feature-count breakdown note changes.
