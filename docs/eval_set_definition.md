# Evaluation set / config definition (frozen, canonical)

This file exists because three tables in a row this week had to be forensically
recovered (the "241/8" Windows provenance predicate, the §6.2 confusion-matrix
source script, and now Table 7.1's config). Each recovery cost a session. This is
the manuscript methods-section content, written down once so it never has to be
re-derived again.

## Config archaeology result (Table 7.1 discrepancy)

One timeboxed pass, as instructed — no historical config surfaced:
- Not a git repository (`git log` fails at the project root) — no version history
  available for any file.
- File mtimes on the three production-config files (all mid-to-late June 2026,
  self-consistent, no earlier/later duplicate found):
  - `models_v2/ocsvm_nu05.pkl` — 2026-06-18 20:38:41
  - `models_v2/thresholds_production_v3.json` — 2026-06-19 00:24:49
  - `models_v2/rule_confound_fixes_v5.json` — 2026-06-20 23:39:38
- No other `thresholds_*.json` in `models_v2/` corresponds to a v5-production
  config (`thresholds_v2.json` and `thresholds_rl_adapted.json` are earlier,
  unrelated experimental configs from 2026-06-17).
- `phase4_transfer.py` / `results_v2/phase4_results.csv` / `phase4_run.log`
  (2026-06-17) — the only "phase4-era, outside newCol/" script found — is CORAL
  domain-transfer scenario testing, unrelated data, and **predates** the July 2026
  collection labeled_lnx.csv is built from, so it cannot be the source of a
  shell-rc number computed on that data.
- **Conclusion: the historical config that produced "shell-rc 3/6" is untraceable
  from this repository.** Per instruction, not pursued further. The published
  Table 7.1 draft numbers (cron 6/6, systemd 6/6, ssh-key 6/6, shell-rc 3/6) are
  superseded below.

## Canonical config (frozen, used for all numbers from this point forward)

| artifact | file | sha256 (first 16) | mtime |
|---|---|---|---|
| L1 | `models_v2/xgb_model.pkl` | `26d6d577c69a6c57` | — |
| L2 (v5) | `models_v2/ocsvm_nu05.pkl` | `957f4c8b24173065` | 2026-06-18 20:38:41 |
| thresholds | `models_v2/thresholds_production_v3.json` | `0624e3a33043ead4` | 2026-06-19 00:24:49 |
| confound-fix (defer) | `models_v2/rule_confound_fixes_v5.json` | `894673705c534bd0` | 2026-06-20 23:39:38 |

- `theta_xgb = 0.07537688442211056`
- `theta_ocsvm = -0.3349956708403319`
- defer rules: `{31101, 31151, 5710, 5501}` (host-scoped, `agent_criticality==1.0`)
- scikit-learn **1.9.0** (matches the version the pickled models were trained
  with — installed into the Python 3.11 environment used for all scoring this
  session, confirmed via clean unpickle with no version-mismatch warnings)
- Model pipeline: `combined_decision_v6.score_alert()` with `models["ocsvm"]`
  overridden to `ocsvm_nu05.pkl` (v5) — everything else (L1, thresholds, defer
  config) is v6's own default load.

## Evaluation predicate (recovered, validated)

**Source:** `newCol/verify_labels_lnx.py`, §2.3 "ARTIFACT-PATH CONFUSION."
Confirmed by direct re-run to reproduce the published §6.2 confusion-matrix
diagonal **exactly**: 6 (T1053.003), 6 (T1098.004), 151 (T1136.001), 6 (T1543.002),
6 (T1546.004) — 175/175 agreement, 0 mislabeled. This validates
`labeled_lnx.csv`'s `technique` column (assigned by time window) as independently
confirmed against `syscheck.path`-derived ground truth for every FIM alert.

**Predicate:** `label=='attack'`, `rule_id` in the discriminative set
`{550, 553, 554, 5710, 5712, 5901, 5902, 5903, 31101, 31104, 31151, 31516}`,
grouped by the `technique` column.

**Resulting per-technique n (all confirmed against Table 7.1's other two named
values):**

| technique | n | source rule(s) |
|---|--:|---|
| T1053.003 (cron) | 6 | 554 |
| T1543.002 (systemd) | 6 | 554 |
| T1546.004 (shell-rc) | 6 | 554 |
| T1098.004 (ssh-key) | 6 | 550 |
| T1110.001 | 119 | 5710 (113) + 5712 (6) |
| T1136.001 | 163 | 550 (90) + 553 (20) + 554 (41) + 5901 (6) + 5902 (6) |

(Rule 554's 59 total attack alerts split 6/6/6/41 across cron/systemd/shell-rc/
T1136.001 by path; rule 550's 96 total split 6/90 across ssh-key/T1136.001 by
path — confirming the v8 FIM-check finding that most of rule 550's volume is
incidental account-management side effects, not SSH-key events.)

## Feature extraction

26-feature v2 (`shared_features.extract_features_v2`), event-time ordered
(`newCol/label_lnx_timeonly.event_time`, not raw alert timestamp — variable
18–80s Wazuh ingestion lag), per-agent `AgentHistory` built fresh over the whole
`collection_lnx_alerts.json` session in event-time order.

## EW block v1 — Phase 1 methodology decisions (Entity-Window experiment)

Appended, not an edit to any block above. Governs `entity_window_extractor_ew.py`
and everything built on its output. The full EW eval-contract block (split
definition, window grid, pivot keys, feature list hash, forbidden-feature
list, metric definitions) is Phase 5 work and will be appended as its own
dated block when that phase runs; this entry records one methodology decision
made in Phase 1 and confirmed at checkpoint, so it doesn't have to be
re-derived later the way the Table 7.1 config did.

**Decision: "26 features minus deferred rule-identity block" (from the EW
experiment prompt) means the *decision-time* defer override
(`models_v2/rule_confound_fixes_v5.json`, applied to specific rule_ids'
final verdicts), not a feature-vector ablation.** `entity_window_extractor_ew.
attach_v2_features()` therefore emits all 26 `FEATURE_COLS_V2` columns
unmodified on every EW-augmented alert table; no column is zeroed or dropped
at extraction time. Which arms apply defer, and how EW features interact with
it, is a Phase 4 evaluation-arm question, not an extractor-construction one.
Confirmed by the user at the Phase 1 checkpoint (2026-07-25).

**Decision: the `user` entity-window pivot is actor-only.** `data.srcuser`
only, on Linux; `dstuser` is never used as a fallback. A real bug caught in
Phase 1 sample review: rule 5902 ("New user added") carries only
`data.dstuser` (the newly-created account — the passive object of the
action, not the actor who ran `useradd`), and rule 5901 carries no user
field at all. The original srcuser-or-dstuser fallback let the created
account masquerade as an actor with its own empty history, which silently
defeated the acctmgmt-after-auth cross-stage flag (it checked the new
account's history instead of whoever actually ran the command). Fixed by
removing the dstuser fallback: these alerts now correctly have no actor
identity and fall back to the GLOBAL pivot, which does see the real chain
(verified on real data: `ew_acctmgmt_after_auth_flag` went from 0→1 on every
5902 alert once the global auth history it's actually downstream of became
visible). See `newCol/ew_feature_preregistration.md` for the original
finding.

## EW block v2 — Phase 4 restructuring around the deferral result

Appended, not an edit to any block above. Phase 4 was restructured (user
instruction, 2026-07-25) from the original 4-arm/full-technique-table plan
to a narrower question: for the 4 rule families
`models_v2/rule_confound_fixes_v5.json` defers to L2-alone on Linux
(`{31101, 31151, 5710, 5501}`), can EW features do better than "trust L2
alone" — reported honestly including where the data can't answer that.
Full results: `newCol/ew_phase4_deferral_report.md`.

**Canonical per-rule baseline (reproduced from the live `combined_decision_v6`
pipeline, v5 OC-SVM, θ_ocsvm=-0.33500, θ_xgb from `thresholds_production_v3.json`):**

| rule | n_attack | n_benign | L1 recall | L2 recall | L1 FPR | L2 FPR |
|---|--:|--:|--:|--:|--:|--:|
| 31101 | 20,665 | 209 | 99.96% | 2.25% | 99.52% | 4.78% |
| 31151 | 1,585 | 0 | 100.00% | 98.49% | N/A | N/A |
| 5710 | 113 | 0 | 100.00% | 76.11% | N/A | N/A |
| 5501 | 43 | 22 | 30.23% | 83.72% | 22.73% | 4.55% |

**Decision: 31151 and 5710 are out of scope for any EW-vs-L2 FPR
comparison** — zero benign alerts of either rule exist in the fresh
collection, so there is no benign side to compare against. Not substituted
with anything synthetic; carried to Phase 6 as a collection gap.

**Finding: whole-collection capture tempo differs 135× between the Linux
attack round (8.944 alerts/s over 43 min) and the Linux benign round
(0.066 alerts/s over 67 min).** This number is the quantitative anchor for
why every rate/volume-shaped EW feature tested under this restructuring —
GLOBAL `alert_count` for 31101 (Phase 3), USER `max_rate_10s` for 5501
(this phase) — could not be distinguished from a testbed-pacing artifact
rather than attacker-specific behavior, even after switching pivots
specifically to escape the host-wide version of the confound. Any future
work computing a rate/volume-shaped feature on this Linux collection pair
must check it against this 135× baseline before trusting it as signal.

## EW block v3 — carrier-classification, tempo, and final not-evaluable list (Phase 5)

Appended, not an edit to any block above. Closes out the carrier-
classification pass (`newCol/ew_carrier_classification.md`, including its
A1–A10 corrections) as the frozen reference for the manuscript. Full
derivations, per-alert swap/ablation scripts, and intermediate numbers
live in that file and its cited CSVs; this block records only the final,
checkpointed figures.

### Feature view (unchanged from block v1, restated for completeness)

All EW/Phase-4/Phase-5 work scores the same 26-column `FEATURE_COLS_V2`
vector via `combined_decision_v6.score_alert()`, L2 = `ocsvm_nu05.pkl`
(v5), defer mechanism live for `{31101, 31151, 5710, 5501}` on
`agent_criticality==1.0`. No feature was added to, removed from, or
zeroed in the production vector at any point in Phase 2–5; every ablation
number in this project is a *scoring-time substitution* on a copy of the
real feature vector, never a retrained or re-extracted model.

### Deferral baseline predicates (restated, see block v2 for full table)

Defer set `{31101, 31151, 5710, 5501}`; 31151 and 5710 have zero benign
representation in the fresh collection and are out of scope for any
FPR-side comparison (block v2). This block extends that same
zero-benign-representation fact to the NOVEL_RULES side (below).

### Carrier-classification buckets — final definitions (two independent axes, not one partition)

**Axis 1 — carrier-type** (what the swap/ablation evidence shows drives
detection):
- **rate-shaped**: collapses to nowhere near threshold under benign-typical
  substitution of the 9-feature `AgentHistory` temporal block. Contaminated
  by the tempo asymmetry below.
- **structural/identity**: survives temporal ablation; traced by direct
  feature swap to a coarse rule-identity proxy (`rule_level`,
  `rule_id_encoded`) rather than to content or temporal features.
- **untraced**: no swap/ablation test in this repository isolates a
  carrier. Not assumed to be any of the above.

**Axis 2 — measurability** (whether a benign-side FPR comparison exists
at all, independent of axis 1): **measurable** if the alert's `rule_id`
has nonzero representation in the fresh benign collection, **not
measurable** if it has zero.

**These two axes must be read as a cross-tab, not a single partition —**
a rule population can be identity-carried *and* unmeasurable at once
(account-management, 5901/5902, is the confirmed case: A9/A10). Collapsing
them into one bucket either double-counts or silently drops one of the two
facts.

**Frozen cross-tab, n=306 (the discriminative NOVEL_RULES population behind
the F1=0.8702 headline, `f1_final_summary.md`):**

| carrier-type ↓ / measurable? → | measurable (benign N>0) | not measurable (benign N=0) | row total |
|---|--:|--:|--:|
| rate-shaped | 169 (rules 550/553/554) | 0 | 169 (55.2%) |
| structural/identity | 6 (ssh-key, rule 550) | 12 (account-mgmt, 5901/5902) | 18 (5.9%) |
| untraced | 0 | 119 (T1110.001, 5710/5712) | 119 (38.9%) |
| **column total** | **175 (57.2%)** | **131 (42.8%)** | 306 |

**Per-rule recall/FPR/N table** (production-v5defer scoring, grouped by
`rule_id`, the only granularity where both sides are jointly defined —
`newCol/a10_recall_fpr_per_rule_table.csv`):

| rule | attack N | recall | benign N | FPR |
|---|--:|--:|--:|--:|
| 550 | 96 | 94.8% | 6 | 50.0% |
| 553 | 20 | 100.0% | 1 | 100.0% |
| 554 | 59 | 72.9% | 2 | 50.0% |
| 5710 | 113 | 76.1% | 0 | N/A |
| 5712 | 6 | 100.0% | 0 | N/A |
| 5901 | 6 | 100.0% | 0 | N/A |
| 5902 | 6 | 100.0% | 0 | N/A |
| 5903 | 0 | n/a | 0 | N/A |

Pattern (holds exactly, not approximately): every rule with a measurable
FPR falls in 50.0–100.0%; every rule without one has benign N=0. (Rule
31101 is excluded from this table by design — its low 4.8% FPR is a
*different*, separately-documented mechanism: memorization of the benign
class, mirroring Finding #1's memorization of the attack class, detailed
as A8 in `ew_carrier_classification.md`. It is a KNOWN-rule finding, not
a NOVEL-rule one, and does not belong in the same row set.)

### Tempo asymmetry (Task 1c, frozen)

| platform | mean-rate ratio (attack:benign) | peak-10s ratio |
|---|--:|--:|
| Linux | 135.2× | 820.8× |
| Windows | 1.5× | 0.5× (benign peak *exceeds* attack peak) |

Linux's asymmetry is the mechanism behind every retracted EW result in
this study (Phase 3's GLOBAL `alert_count`, Phase 4's USER
`max_rate_10s`, and the rate-shaped 55.2% of the carrier-classification
table above). Windows shows no comparable asymmetry in either direction —
ruling out this specific mechanism for the Windows/v8 result (A6), though
not the separate population-mismatch defect that result carries.

### Final not-evaluable-with-collected-data list (permanent, not pending)

| gap | affected claim | reason it cannot be closed with what was collected |
|---|---|---|
| 31151 benign FPR | block v2 defer baseline | 0/267 benign alerts of rule 31151 |
| 5710 benign FPR | block v2 defer baseline; carrier-classification row | 0/267 benign alerts of rule 5710 |
| 5712 benign FPR | carrier-classification row | 0/267 benign alerts of rule 5712; additionally a Wazuh frequency/composite rule, so no individual alert-level feature vector can ever be scored against a benign baseline for it even in principle (A4) |
| 5901/5902 benign FPR | carrier-classification row, A9/A10 | 0/267 benign alerts of either rule — despite a positive carrier finding (structural/identity) on the recall side |
| T1110.001 carrier trace (5710/5712) | carrier-classification "untraced" row | no benign-typical ablation or feature-swap script exists in this repository for this rule pair, and none can be constructed without a benign side to define "benign-typical" against |
| benign-burst control | Phase 2/3 preregistration; Windows-vs-Linux asymmetry interpretation | both benign collections are single, un-repeated capture sessions (Linux 267 alerts/67 min, Windows 201 alerts/81 min) — no second benign round exists to test whether burst variance within "normal" benign traffic could itself explain any retracted result |
| benign auth-failure control | Phase 2 zero-failures check | 0 benign auth-failure alerts on either platform (rules 5710/5712/60122/60204) — cannot check whether the model would false-positive on a genuine authentication failure that is not part of an attack |
| provenance arm (matched attacker profile diversity) | generalization claims for any NOVEL_RULES finding | single attacker script/session per platform; no second, independently-authored attack run exists to separate "this technique" from "this specific script's timing signature" |

Every row above is permanent for this dataset, per the no-further-
collection rule governing this phase — none is "pending," all are closed
questions for this study.

---

## PRE-MS FIX 2 — per-rule FPR restated as counts (append-only correction, block v3 untouched above)

The block-v3 "Per-rule recall/FPR/N table" above (550/553/554 FPR shown as
50.0%/100.0%/50.0%) rests on benign N of 6/1/2. At N=1 (rule 553),
"100.0%" is a single alert, not a measured rate — the percentage form
overstates precision the data cannot support. Restated as counts, the
same table's benign side:

| rule | benign N | benign alerts flagged (raw count) |
|---|--:|--:|
| 550 | 6 | 3 of 6 |
| 553 | 1 | 1 of 1 |
| 554 | 2 | 1 of 2 |
| 5710 / 5712 / 5901 / 5902 / 5903 | 0 | not measurable (benign N=0) |

Aggregate: **5 of the 9 benign alerts across rules 550/553/554 were
flagged** by the production v5-defer pipeline. Attack-side recall
percentages (94.8%/100.0%/72.9%, denominators 96/20/59) are unaffected —
those N's are large enough to support a percentage — only the benign/FPR
side is restated.

**"Pattern (holds exactly, not approximately)" — this exact phrase is
withdrawn, not merely softened.** At benign N=1, "exactly 100%" is a
denominator artifact, not a demonstrated pattern. Honest replacement:
every rule with any measurable FPR (550, 553, 554) has *at least one*
benign alert flagged; every rule without one (5710/5712/5901/5902/5903)
has benign N=0. No claim of exactness at any specific percentage is made.

**What the 9 benign alerts actually are (not previously stated plainly in
this file):** per `newCol/art_contamination_check.md` (ART-C), 8 of the 9
are CUPS's own periodic subscription-lease file rewrite
(`/etc/cups/subscriptions.conf` and its `.O`/`.N` shadow copies) and 1 is
an organic SSH `known_hosts` append — **daemon state-file churn**, not a
representative sample of organizational file-change activity. This bears
on how far these FPR figures should be expected to generalize, separately
from the small-N caveat above. Full derivation: `newCol/pre_ms_number_fixes.md` FIX 2.

## EW block v4 — tempo-ratio methodology reconciliation (FIG-D F1)

Appended, not an edit to any block above. A manuscript-figure draft
(`newCol/figures_ms/fig5_tempo_asymmetry.py`, first version) recomputed
the Task 1c tempo ratio directly from the raw collection CSVs
(`collection_lnx_alerts.csv` etc.) and got **136.2×**, not the 135.2×
already frozen above and already propagated into
`ew_carrier_classification.md`, `ew_supervisor_summary.md`, and the
drafted abstract. Root-caused rather than dismissed as rounding, since
this project treats a second value for one quantity as a drift risk
(the same class of defect behind the earlier n=241→160 incident):

**The two values use two different timestamp fields, not two different
spans of the same field:**
- **135.2× (canonical)** uses `ts` from
  `newCol/ew_features/ew_augmented_per_alert.csv`, built by
  `entity_window_extractor_ew.py:build_canonical()`, which sets
  `ts = event_time_utc if available else raw Wazuh timestamp` — the
  function's own inline comment states this preference explicitly:
  "prefer validated event_time_utc (eval_set_definition.md methodology)".
  `event_time_utc` is this project's own corrected event time
  (`newCol/label_lnx_timeonly.py`), built specifically because Wazuh's
  raw alert `timestamp` lags the true event by a **variable 18.2s-80.4s**
  (median ~36s) of ingestion delay — not a constant offset, and
  documented as large enough to misattribute technique/window
  membership if used uncorrected.
- **136.2× (superseded, figure-draft-only)** used the raw Wazuh
  `timestamp` field directly from the `collection_*.csv` files — the
  uncorrected, ingestion-lagged value `event_time_utc` exists specifically
  to fix.

**Canonical methodology (stated explicitly here for the first time,
previously only implicit in code):** any alert-tempo/rate/span
computation for the fresh Linux/Windows collections must use the
corrected `ts` field from `ew_augmented_per_alert.csv` (or an
equivalent `event_time_utc`-preferring derivation), not the raw Wazuh
`timestamp` field, unless the raw ingestion-time behavior of the live
production system is specifically what is being measured (see the one
documented exception below). Span = `ts.max() - ts.min()` per
`source` group (lnx_attack/lnx_benign/win_attack/win_benign),
inclusive of both endpoints, whole-collection (not per-agent, since
each of these four collections is already single-agent). Recomputed
under this methodology: lnx_attack rate=8.943718/s, lnx_benign
rate=0.066137/s, win_attack rate=0.062476/s, win_benign
rate=0.041411/s — **Linux ratio = 135.2302..× (135.2×), Windows ratio
= 1.5087..× (1.5×)**, matching this file's existing Task 1c table to
full precision. This is now the canonical value; 136.2× is superseded
and must not be cited.

**One documented exception, checked, not a second drift risk:** FIG-C
Task 3 (`newCol/figures_ms/fig_corrections.md`) computed
`alert_rate_1min` for the Linux collections using the raw `timestamp`
field, not `ts`. This was deliberate, not an oversight — that check's
question was specifically whether the *deployed, real-time* pipeline's
capped feature is symmetrically censored, and a live production system
scoring alerts as they arrive only ever has the raw ingestion timestamp
available to it, never a post-hoc-corrected `event_time_utc`. That
figure's own numbers (99.22% attack / 0.00% benign at cap) are therefore
correctly computed on the field production actually sees and are not
revised by this note. Only descriptive/collection-tempo claims (this
block, and `fig5_tempo_asymmetry.py`) use the corrected `ts` field.

**Propagation check (FIG-C's own tempo-ratio citation):**
`newCol/figures_ms/fig_corrections.md` Task 3 states "recomputed mean
rate = 9.01 alerts/s (attack) vs. 0.066 alerts/s (benign)... differs
slightly, ~0.7%... not a discrepancy that changes anything below" — this
was the same raw-`timestamp` draft value, dismissed at the time as
inconsequential rounding. It is superseded by this note for the
*mean-rate-ratio* citation specifically; `fig_corrections.md`'s own Task
3 conclusions (which concern the capped `alert_rate_1min` feature
computed on the correctly-scoped raw-timestamp field per the exception
above, not the mean-rate ratio) are unaffected and not revised.
