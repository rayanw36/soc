# FIG-C: Figure corrections + caption externalization — Tasks 1-3

Checkpoint deliverable per the FIG-C prompt. No new experiment, no
retraining, no threshold change to any deployed artifact — every number
below is either read directly from a committed CSV/artifact or computed
directly from `models_v2/ait_split.npz` / the two committed raw-alert
collection CSVs, with the computation shown.

---

## Task 1 — Fig 3a left panel retitled

**Old title:** "Three unrelated feature subsets each separate AIT-ADS."
**New title:** "Every subset that separates AIT-ADS carries
rule-definition metadata."

The three ablation variants (`full`, `no_identity`, `behav_only`) are not
independent shortcuts:

| variant's carrier | what actually drives it | rule-definition link |
|---|---|---|
| `full` / `no_identity` | `is_web_attack` (Fig 2, 94.99% of gain) | RULE-CORRELATED — a rule-group/description flag |
| `behav_only` (3 nominal BEHAVIORAL features) | `time_since_last_high` (2.815% of gain, the dominant BEHAVIORAL contributor) | proximity to a rule-**severity** event; `rule_level` is itself RULE-IDENTITY |
| — | `alert_rate_1min` (0.307% of gain) | the one feature in this set that is *not* rule-derived — see Task 3 |

All three routes to separability trace back to rule-definition metadata
(rule group/description, rule identity, or rule severity) in some form.
Applied to `fig3a_ablation_separability.py` (title, left-panel
annotations, module docstring) and `captions.md` (Revision note 3, with
an explicit "do not restore 'unrelated'" guard). Figure regenerated and
visually checked — no overlap between the two left-panel annotations or
with the bars (this required repositioning both annotations above/beside
the bars and widening the x-axis, since the corrected annotation text ran
longer than the original and initially collided with the "Behavioural
only" bar).

---

## Task 2 — Feature taxonomy correction

Full derivation: `newCol/figures_ms/feature_classification_correction.md`
(new file — `exp1_feature_classification.csv` itself is not edited, per
the project's read-only/append rule).

**Correction:** `time_since_last_high` reclassified from BEHAVIORAL to
RULE-CORRELATED. Its defining event (`rule.level >= 10`) is itself a
rule-metadata field (`rule_level` = RULE-IDENTITY in the same CSV), so
elapsed-time-to-that-event sits with the other RULE-CORRELATED features
that already aggregate rule metadata over a window
(`high_sev_ratio_20`, `rule_diversity_10min`) rather than with the two
features that are genuinely rule-agnostic counts (`alert_rate_1min`,
`unique_src_ip_10min`).

**Revised bucket counts (of 26):**

| bucket | before | after |
|---|--:|--:|
| RULE-IDENTITY | 3 | 3 |
| RULE-CORRELATED | 20 | **21** |
| BEHAVIORAL | 3 | **2** |

**Revised gain shares** (`exp2_importance_gain.csv`, `gain_pct` summed
per bucket):

| bucket | before | after |
|---|--:|--:|
| RULE-IDENTITY | 0.7709% | 0.7709% |
| RULE-CORRELATED | 95.4914% | **98.3065%** |
| BEHAVIORAL | 3.7376% | **0.9226%** |

Rule-definition metadata (RULE-IDENTITY + RULE-CORRELATED, corrected)
now accounts for **99.08%** of the 26-feature model's split gain; the
genuinely behavioral bucket carries **0.92%**, not 3.7%.

**Fig 2 caption one-liner updated** to "3 RULE-IDENTITY / 21
RULE-CORRELATED / 2 BEHAVIORAL" in `captions.md`.

**Fig 2's plotted bar is unaffected — checked, not assumed.** Fig 2
splits by individual feature (`is_web_attack` vs. every other feature
summed), not by bucket. `time_since_last_high` was one of "the other 25"
before the correction and still is after — its bucket label changes, not
which side of the `is_web_attack`/other-25 split it falls on. Verified
directly against `fig2_feature_composition.py`'s summation logic (see
`feature_classification_correction.md`, final section). No change to the
95.0%/5.0% values or the figure file.

---

## Task 3 — Does the `alert_rate_1min` cap censor the Linux tempo signal?

**Question:** `alert_rate_1min` is derived from a 20-alert rolling buffer
(`AgentHistory(maxlen=20)`, `shared_features.py:157`) and counts buffered
alerts within the trailing 60s. If both the Linux attack *and* benign
collections saturate this cap, the feature would read as a binary
"surge occurred" flag for both classes alike, and the well-established
135× raw-timestamp tempo asymmetry (`newCol/eval_set_definition.md`)
would be largely invisible to the production model through this specific
feature, even though it was fully visible to the EW extractor's own
rate/volume features (computed directly from raw timestamps, not through
this capped buffer).

**Data:** the same two collections that produced the 135× figure —
`newCol/collection_lnx_alerts.csv` (attack round, n=23,081 alerts, single
agent `lnx-dmz-VirtualBox`, span 42m42s) and
`newCol/collection_benign_lnx_alerts.csv` (benign round, n=267 alerts,
same agent, span 1h7m17s). Confirmed these are the 135× pair: recomputed
mean rate = 9.01 alerts/s (attack) vs. 0.066 alerts/s (benign) against
`eval_set_definition.md`'s "8.944 alerts/s / 0.066 alerts/s."

**Correction (FIG-D F1, appended — supersedes the "~0.7%, not a
discrepancy" dismissal above):** the ~0.7% gap is not rounding. It is
Wazuh's raw alert `timestamp` field (used here) lagging the true event
time by a variable 18.2s-80.4s, vs. `eval_set_definition.md`'s canonical
figure, which uses the project's own corrected `event_time_utc`-preferring
`ts` field. Full reconciliation: `eval_set_definition.md` EW block v4,
`newCol/figures_ms/fig_followups.md` F1. **This does not change this
Task's own conclusions**, because Task 3's question — whether the
*deployed, real-time* pipeline's `alert_rate_1min` feature is
symmetrically censored — is correctly scoped to the raw `timestamp`
field: a live production system only ever sees raw ingestion time when
scoring an alert, never a post-hoc-corrected event time. Using `ts`
instead here would have answered a different, less relevant question.
Only the *mean-rate-ratio* citation above was imprecise; it is now
stated as 9.01 alerts/s on the raw-timestamp field specifically (not
"the 135× figure," which is a `ts`-field number) to avoid conflating the
two.

`alert_rate_1min` was recomputed alert-by-alert for both collections
using the **exact same logic** as `shared_features.py`'s `AgentHistory`
(deque, `maxlen=20`; for each alert, count prior buffered alerts with
`0 <= dt <= 60` seconds *before* adding the current alert to the buffer —
matching the real call order, `compute_features()` then `add()`,
confirmed at `shared_features.py:430-432`). Single continuous per-agent
stream per round, as the real pipeline would process it.

### (a) Distribution and fraction at cap

| | attack round (n=23,081) | benign round (n=267) |
|---|--:|--:|
| mean | 19.92 | 3.99 |
| median | 20 | 4 |
| min / max | 0 / 20 | 0 / 10 |
| **fraction at cap (==20)** | **99.22%** (22,901/23,081) | **0.00%** (0/267) |

Full value-count histogram, attack round: values 0-19 each occur 7-14
times (a small population of alerts near the start of the round, before
the buffer fills, or after a >60s gap), then value 20 occurs 22,901
times (99.22%). Benign round: 0→7, 1→18, 2→40, 3→48, 4→53, 5→45, 6→26,
7→16, 8→10, 9→3, 10→1 — a roughly bell-shaped distribution peaking at 4,
never reaching 11 let alone the cap of 20.

### (b) Confirm or refute: was Linux benign also largely at cap?

**Refuted.** The premise in the prompt (benign peak ~5 alerts/10s, i.e.
~30/min, above the 20-alert cap) is directionally right as an
**instantaneous** burst statistic — recomputed directly: the benign
round's true peak is 6 alerts in any 10-second window (36/min
extrapolated), vs. 2,200 alerts in 10s for the attack round (13,200/min
extrapolated). But `alert_rate_1min` measures a **sustained trailing
60-second count**, not an extrapolated instantaneous rate, and the
benign round's bursts are too brief and too sparse to sustain 20 alerts
within any real 60-second window — the empirical max is 10, exactly half
the cap, and 0% of benign rows reach it. Attack, by contrast, sustains
well above the cap for nearly the entire round (99.22% at cap).

### (c) Consequence

Both classes are **not** largely at cap — only attack is. The specific
failure mode the prompt raised (symmetric saturation erasing the
asymmetry, making it invisible to the v5 model) **does not occur** for
this Linux collection pair. The cap still discards *magnitude*
information on the attack side only (the model cannot distinguish a
sustained 20/min rate from the round's true ~540/min rate — `9.01
alerts/s` — since both read as a flat 20), but it does not discard the
asymmetry itself: attack (99.22% at cap, max=20) and benign (0% at cap,
max=10) remain cleanly, if coarsely, separated through this exact
feature.

**Which existing claims does this touch?** The "rate-shaped" carrier
bucket in `newCol/eval_set_definition.md`/`ew_carrier_classification.md`
(169/306 = 55.2% of the NOVEL_RULES population, rules 550/553/554) is
defined by collapse under benign-typical substitution of the
`AgentHistory` temporal block, which includes `alert_rate_1min`. Since
`AgentHistory`'s buffer holds every alert on the agent regardless of
rule, the whole-collection distribution computed here is exactly the
distribution that fed `alert_rate_1min` for every alert in these rounds,
including 550/553/554 alerts (both rule_ids are present in both
collections — confirmed: rule 550 appears 177×/6×, 553 85×/1×, 554
82×/2× in attack/benign respectively). This finding is **consistent
with, not contradicting,** the existing rate-shaped classification: the
temporal block (including this feature) still carries a real,
detectable asymmetry for Linux, uncensored by symmetric saturation. **No
existing Linux/rate-shaped/135× claim needs retraction or softening as a
result of this check.** This is a genuinely different outcome from the
AIT-ADS case (`tempo_ait_check.md`), where benign *did* reach the same
cap in 32.9% of rows — the two datasets' capture regimes are not alike,
and the cap's effect is regime-dependent, not a fixed property of the
feature.

### (d) Threats to validity (recorded regardless of outcome)

`alert_rate_1min`'s hard 20-alert buffer is a **limitation of the
measurement instrument**, not of the collected data: it structurally
cannot represent any true rate above ~20/60s window's worth of buffered
history, for any dataset, any class. On this Linux collection it happens
not to have erased the attack/benign asymmetry (benign never approaches
the cap), but this is a property of *this specific* benign round's burst
duration being short relative to 60s — a benign round with longer
sustained bursts (not collected, and per the project's no-further-data
rule, not collectable) could, in principle, saturate the same cap the
way AIT-ADS's benign traffic does. Recorded as a permanent instrument
limitation for any future rate/volume feature analysis on this pipeline,
independent of whether it was found to bite in either dataset examined
so far.

---

## Files touched in this pass

- `newCol/figures_ms/fig3a_ablation_separability.py` — left-panel title,
  annotations, docstring (Task 1); regenerated `.pdf`/`.png`.
- `newCol/figures_ms/feature_classification_correction.md` — new file
  (Task 2).
- `newCol/figures_ms/captions.md` — Fig 2 caveat (corrected counts), Fig
  3a revision note 3 + caveat rewording (Tasks 1-2).
- `newCol/figures_ms/sources.md` — Fig 2 feature-count row, Fig 3a left
  panel header note.
- `newCol/figures_ms/fig_corrections.md` — this file (Task 3 + summary
  of Tasks 1-2).

No other committed artifact was modified. `exp1_feature_classification.csv`
and `exp2_importance_gain.csv` remain untouched, as required.
