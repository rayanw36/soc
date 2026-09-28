# TEMPO-AIT — does AIT-ADS benign traffic ever burst?

Checks whether Fig 3a's right panel ("capture-tempo artifact") is
correctly named, by testing the specific asymmetry that made the
project's own 135× Linux finding an artifact (scripted-fast attack
rounds vs. an idle-host benign round that never approaches attack
density) against AIT-ADS's `alert_rate_1min` and `time_since_last_high`.

Data: `models_v2/ait_split.npz` (n=2,600,263; attack=1,717,524;
benign=882,739 — train+test concatenated; both splits checked separately
below and are consistent with the combined figures). No retraining, no
new collection — descriptive statistics and code inspection only.

---

## Task 1 — AIT-ADS rate distributions, benign vs. attack

### `alert_rate_1min`

| | n | min | median | p90 | p95 | p99 | max |
|---|--:|--:|--:|--:|--:|--:|--:|
| attack | 1,717,524 | 0.0 | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |
| benign | 882,739 | 0.0 | 10.0 | 20.0 | 20.0 | 20.0 | 20.0 |

Full value-count histogram (integer-valued, 0–20):

| value | attack n (%) | benign n (%) |
|--:|--:|--:|
| 0 | 823 (0.05%) | 33,216 (3.76%) |
| 1 | 774 (0.05%) | 30,711 (3.48%) |
| 2 | 763 (0.04%) | 29,922 (3.39%) |
| 3 | 792 (0.05%) | 30,780 (3.49%) |
| 4 | 838 (0.05%) | 34,593 (3.92%) |
| 5 | 838 (0.05%) | 34,595 (3.92%) |
| 6 | 1,106 (0.06%) | 72,469 (8.21%) |
| 7 | 1,106 (0.06%) | 72,333 (8.19%) |
| 8 | 893 (0.05%) | 46,240 (5.24%) |
| 9 | 778 (0.05%) | 42,342 (4.80%) |
| 10 | 588 (0.03%) | 24,297 (2.75%) |
| 11 | 584 (0.03%) | 24,279 (2.75%) |
| 12 | 456 (0.03%) | 17,706 (2.01%) |
| 13 | 443 (0.03%) | 17,586 (1.99%) |
| 14 | 444 (0.03%) | 17,873 (2.02%) |
| 15 | 370 (0.02%) | 15,033 (1.70%) |
| 16 | 344 (0.02%) | 13,337 (1.51%) |
| 17 | 344 (0.02%) | 13,332 (1.51%) |
| 18 | 276 (0.02%) | 10,835 (1.23%) |
| 19 | 274 (0.02%) | 10,791 (1.22%) |
| **20 (cap)** | **1,704,690 (99.25%)** | **290,469 (32.91%)** |

Train/test splits checked separately — same shape in both (attack
median=20 / benign median=10 in both train and test; percentiles
identical to the combined table above).

### `time_since_last_high`

| | n | min | median | p90 | p95 | p99 | max |
|---|--:|--:|--:|--:|--:|--:|--:|
| attack | 1,717,524 | 0.0 | 0.0 | 999.0 | 999.0 | 999.0 | 184,678.2 |
| benign | 882,739 | 0.0 | 999.0 | 999.0 | 999.0 | 999.0 | 186,401.3 |

Raw counts at the two structurally meaningful values:

| | attack | benign |
|---|--:|--:|
| ==0 (a level≥10 alert just fired) | 1,380,201 (80.36%) | **9,121 (1.03%)** |
| ==999 (sentinel: none seen in buffer) | 299,640 (17.45%) | 696,360 (78.89%) |
| neither 0 nor 999 (n, median of that subset) | 37,683 (2.19%), median=1.0s | 177,258 (20.08%), median=33.1s |

3,020 distinct values on the attack side vs. 66,072 on the benign side
(consistent with benign having a long, spread tail rather than the
attack side's near-bimodal 0-or-999 pattern).

### a. Does AIT-ADS benign traffic ever burst?

**Yes, non-trivially.** Benign `alert_rate_1min` reaches the same
structural ceiling (20) as attack in **32.9% of benign rows** — this is
not the Linux testbed's pattern, where benign never got near the attack
round's peak (Phase 2: benign topped out at 0.1% of attack peak
density). Benign's own 70th percentile is already at the cap. **0% of
attack rows exceed the benign maximum** — both classes share the same
literal ceiling, so "does attack exceed benign's range" is the wrong
question for this feature; the real difference is *how often* each
class reaches that shared ceiling (99.25% of attack rows vs. 32.91% of
benign rows), not whether benign can reach it at all.

Finer overlap: attack exceeds benign's median (10) in 99.46% of rows;
benign itself exceeds 10 in 48.85% of rows. Both distributions are
right-skewed toward the same cap, one more consistently than the other.

### b. Is `time_since_last_high == 0` ever true for benign rows?

**Yes — 9,121 of 882,739 benign rows (1.03%), not zero.** Rare but real.
The much larger, structurally distinct majority of benign rows (78.89%)
sit at the sentinel value 999 (no level≥10 alert anywhere in the
trailing ≤20-alert buffer), which is what actually drives the FPR
figure quoted in Fig 3a.

### c. Overlap statement

- `alert_rate_1min`: **0% of attack rows exceed the benign maximum** —
  the two classes share an identical ceiling and both distributions
  pile up against it; attack does so far more consistently (99.25% at
  cap) than benign (32.91% at cap). This is a difference in *frequency
  of saturation*, not a difference in *achievable range* — meaningful
  overlap exists in the upper distribution, unlike the Linux 135× case.
- `time_since_last_high`: **80.36% of attack rows sit at or below
  benign's own 1st percentile (0.0)** — this is a much sharper
  separation with far less distributional overlap than `alert_rate_1min`
  shows. 82.45% of attack rows are ≤5 seconds from a level≥10 alert,
  vs. only 7.02% of benign rows.

**The two features behave differently and should not be described with
one blanket "capture-tempo artifact" claim** — see Task 3.

---

## Task 2 — Threshold provenance

Checked directly against `shared_features.py` (the feature-engineering
source, not reconstructed from behavior):

- **`alert_rate_1min >= 20` — the cap is a hard structural ceiling, not
  a fitted or inspected value.** `AgentHistory.__init__` (line 157) sets
  `self.buf = deque(maxlen=20)` — a rolling buffer of **at most the 20
  most recently seen alerts per agent, of any rule**. `alert_rate_1min`
  (line 212) counts how many of those ≤20 buffered alerts fall within
  the trailing 60 seconds. Because the buffer itself can never hold more
  than 20 records, **the feature cannot exceed 20 by construction**,
  regardless of true alert volume — a genuinely faster attack burst and
  a merely-fast one are indistinguishable once both saturate the
  20-slot buffer within 60s. `20` was used in the figure because it is
  the feature's literal, code-defined maximum, not because it scored
  well on the eval split — no eval-split inspection informed this
  choice.
- **`time_since_last_high == 0` — zero is the feature's natural floor,
  not a fitted value.** `compute_features` (lines 179–234) initializes
  `time_since_last_high` to the sentinel `999.0` (line 187) and
  overwrites it with `dt` — seconds since the closest buffered
  level≥10 alert — only when such an alert exists in the buffer (lines
  224–226); `dt` is elapsed seconds and is explicitly floored at 0 by
  construction (line 208: rows with `dt < 0` are skipped entirely, i.e.
  only non-negative, already-elapsed gaps are considered). The current
  alert is computed from history **before** being added to its own
  buffer (`combined_decision`-adjacent call site, lines 430–432:
  `compute_features(ts)` precedes `hist.add(oa, ts)`), so a value of
  exactly 0 reflects a genuinely distinct, immediately-prior buffered
  alert, not the alert scoring itself. `0` was used because it is the
  feature's structural floor (elapsed time cannot be negative), not
  because it was the best-performing cutoff on the eval split.

**Neither threshold was chosen by looking at eval-split performance.**
The "unfitted" label is accurate for how the thresholds were selected.
It does not, on its own, mean the resulting separation is an artifact
of collection asymmetry — see Task 3.

---

## Task 3 — Verdict

**Mixed — the two features do not support the same verdict, and Fig
3a's single "capture-tempo artifact" claim overstated what both bars
show.**

- **`alert_rate_1min`: partially artifact, partially real, and weaker
  than implied.** Benign traffic *does* burst to the same structural
  ceiling as attack in a third of rows — this is not the Linux
  testbed's clean asymmetry (benign there never approached attack
  density at all). The separation that exists (99.25% vs. 32.91% at
  cap) is real but coarse, and is additionally capped/undercounted by a
  20-alert buffer design that cannot register true attack density above
  that buffer size. This feature also carries the least gain of the
  three BEHAVIORAL features in the full model (0.307% per
  `results/rule_memorization_audit/exp2_importance_gain.csv`) — it is
  not doing much real work in the trained model either.
- **`time_since_last_high`: a much sharper asymmetry (1.03% vs. 80.36%),
  but not cleanly a "capture-tempo/rate" artifact in the same sense as
  the 135× Linux finding.** That finding was about raw alert *volume*
  differing between capture rounds. This feature instead measures
  temporal proximity to a **rule-severity** event (level≥10) — and rule
  severity (`rule_level`) is itself classified RULE-IDENTITY in
  `exp1_feature_classification.csv`, with severity-derived aggregates
  like `high_sev_ratio_20` classified RULE-CORRELATED for the same
  reason. `exp1`'s own justification already flagged
  `time_since_last_high` as "borderline" between BEHAVIORAL and
  rule-derived. Its separation power more plausibly reflects "AIT-ADS
  attack scenarios reliably trigger high-severity rules close together
  in time" — which could be genuine attacker behavior, an artifact of
  how the scenarios were scripted, or (most likely) some mix — not
  disentangled by this check, and not the same mechanism as
  `alert_rate_1min`'s buffer-saturation pattern. This feature carries
  by far the most gain of the three BEHAVIORAL features (2.815%,
  `exp2_importance_gain.csv`) — it is doing most of `behav_only`'s real
  work, and its mechanism is the least "pure tempo" of the two.

**Neither the clean "artifact confirmed" nor the clean "legitimate
signal" box applies to both features at once.** Per the task's own
instruction for any verdict other than "artifact confirmed," Fig 3a's
right panel is retitled to the factual, already-proven claim:
**"Unfitted single-feature rate thresholds separate AIT-ADS without
training."** The figure and its caption now report what was measured
(the thresholds are structurally unfitted; the separation is real) and
flag, per-feature, how much of that separation is attributable to a
tempo/volume confound (`alert_rate_1min`, partial) vs. a
severity-proximity mechanism closer in kind to the RULE-CORRELATED
bucket (`time_since_last_high`, likely the larger contributor) — rather
than asserting one unified "capture-tempo artifact" cause.

This check used the same control methodology (capture-tempo/burst
asymmetry testing) that caught the 135× Linux finding, applied here to
a second, independent dataset (AIT-ADS) — but the outcome differs: the
Linux case was a clean asymmetry (benign never bursts), AIT-ADS is not
(benign bursts less often, not never, on the rate feature; and the
sharper-separating feature isn't a pure rate/volume signal at all).
Report this difference plainly rather than forcing AIT-ADS into the
same "artifact confirmed" box the Linux testbed produced.
