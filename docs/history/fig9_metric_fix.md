# FIG9-M — Fig 9 metric fix (F1 vs. trivial baseline) + AMiner model bar

Scripts: `newCol/fig9m_task1_baselines.py` (Task 1; output
`newCol/fig9m_task1_results.json`), `newCol/fig9m_task2_aminer_model.py`
(Task 2; output `newCol/fig9m_task2_aminer_model_results.json`). Both are
read-only over already-committed splits (`newCol/xdet_task1_results.json`,
`newCol/xdet_aminer_split.npz`, raw `data/ait_ads/raw/*_aminer.json`);
neither retrains any deployed model. Figure rebuilt:
`newCol/figures_ms/fig9_cross_detector_lookup.{py,pdf,png}`;
`captions.md`/`sources.md` updated in place (Fig 9's section rewritten,
not duplicated).

## Task 1 — Per-detector metrics, lookup/model vs. trivial baseline

### a. Full P/R/F1/FPR, all three series, per detector (eval split)

| detector | series | precision | recall | F1 | FPR |
|---|---|--:|--:|--:|--:|
| Wazuh-native (n=458,517, 74.66% attack) | lookup | 0.9998 | 0.9922 | **0.9960** | 0.0005 |
| | model (audit retrain) | 1.0000 | 0.9924 | **0.9962** | 0.0000 |
| | trivial always-attack | 0.7466 | 1.0000 | **0.8549** | 1.0000 |
| Suricata (n=61,536, 1.93% attack) | lookup | 1.0000 | 0.0277 | **0.0540** | 0.0000 |
| | model (audit retrain) | 0.9808 | 0.0429 | **0.0821** | 0.0000 |
| | trivial always-attack | 0.0193 | 1.0000 | **0.0379** | 1.0000 |
| AMiner (n=11,112, 84.70% attack) | lookup | 0.9614 | 0.9937 | **0.9773** | 0.2212 |
| | model† (non-identity, Task 2) | 0.9931 | 0.9886 | **0.9908** | 0.0382 |
| | trivial always-attack | 0.8470 | 1.0000 | **0.9172** | 1.0000 |

The trivial baseline's precision equals the eval-split base rate by
construction, and both its recall and FPR are the structural values
(1.0, 1.0) the task brief describes. Every trivial row above is computed
from the *same* confusion-matrix denominators (`tp+fn`, `fp+tn`) already
committed for that detector's lookup table in `xdet_task1_results.json`
— i.e. scored on the identical population, not a separately drawn one.

### b. Does the lookup table beat the trivial baseline on F1?

| detector | lookup F1 | trivial F1 | gap |
|---|--:|--:|--:|
| Wazuh-native | 0.9960 | 0.8549 | **+0.1411** |
| AMiner | 0.9773 | 0.9172 | **+0.0601** |
| Suricata | 0.0540 | 0.0379 | **+0.0160** |

**Yes, on every detector — but the margin is what actually distinguishes
"identity predicts the label" from "identity roughly tracks the base
rate," and the three detectors land in three very different places.**
Wazuh-native's +0.141 gap is large and unambiguous — this is a genuine,
substantial identity effect, consistent with the existing rule-31101
memorization narrative. AMiner's +0.060 gap is real (not noise — it
persists across precision moving from 0.847→0.961 while recall barely
moves) but an order of magnitude smaller than Wazuh-native's. Suricata's
+0.016 gap is technically positive but both numbers are close to zero;
this detector shows essentially no exploitable signature-identity signal,
consistent with prior work already on record for Suricata.

### c. Fig 9 rebuilt on F1 with per-detector trivial baselines

Done — `newCol/figures_ms/fig9_cross_detector_lookup.py` rewritten (F1
instead of recall, third bar per group for the trivial baseline, since
base rates differ too much for one shared reference line: 74.7%/1.9%/
84.7%). `captions.md` and `sources.md` updated with the new values,
provenance, and caveats (not appended as a duplicate section — Fig 9's
existing entries were rewritten in place, old recall-based numbers
removed). `$n$ and base rate per detector are in the caption text (Task
1c's requirement), not baked into the figure's rendered pixels, matching
this project's established convention of keeping in-figure text to axis/
legend/value labels only.

### d. Verdict on the AMiner claim

**The claim survives, but its current wording ("99.4% recall from
signature identity alone") must be replaced — it was never actually
supportable, and the reason is exactly the mechanism the task brief
named.** AMiner's lookup recall (0.9937) is *below* the trivial
baseline's recall (1.0000) — a recall-only claim about AMiner was always
comparing an identity-based classifier unfavorably against a baseline
that requires no identity at all, the opposite of what "the label proxy
argument" needs. **On the right metric (F1), the claim is not "signature
identity predicts the label" so much as "signature identity provides a
moderate, real improvement in precision over the base rate"**: F1 0.977
vs. 0.917 (+0.060), driven almost entirely by precision (0.961 vs. 0.847)
since recall was already near-ceiling for both. That is a legitimate,
if modest, finding — smaller than Wazuh-native's, larger than Suricata's.

**Corrected wording for the manuscript:**
> On AMiner, a majority-label-per-signature lookup table achieves F1 =
> 0.977, exceeding a trivial always-predict-attack baseline (F1 = 0.917
> at this detector's 84.7% base rate) by 0.060 — a real but moderate
> identity effect, not the 99.4%-recall figure previously cited, which
> was in fact *below* the trivial baseline's recall of 1.000 and cannot
> by itself support a memorization claim.

This wording should additionally note the Task 2 finding below, since it
changes what "the strongest available signal" means for this detector.

## Task 2 — The AMiner model bar

**Both (a) and (b) apply, and needed to be stated together.**

**(a) Structural, confirmed directly:** AMiner's native alert schema
(`AnalysisComponent.AnalysisComponentName/Type/Identifier`,
`LogData.RawLogData/Timestamps/DetectionTimestamp/LogLinesCount`,
`AMiner.ID`) shares no fields with the Wazuh `rule.*`/`agent.*` schema
`shared_features.py:extract_features_v2` requires, so the 26-feature
Wazuh vector genuinely cannot be computed for AMiner alerts. The original
figure's `n/a` was correct as far as it went, but read (correctly, per
the task brief) as potentially indistinguishable from "we did not
bother" — it is now stated explicitly in the caption rather than left
implicit.

**(b) Possible but not previously attempted — now built.** Non-identity
fields do exist in the raw AMiner records:

| field | source | used? |
|---|---|---|
| `LogData.RawLogData` (raw log line text) | present on every record | yes — as `raw_log_len` (total character length) |
| `LogData.LogLinesCount` | present on every record | yes — as-is |
| `AMiner.ID` (source host/IP) | present on every record | yes — as the causal-history key for 3 temporal features below, never used as a value itself |
| `LogData.DetectionTimestamp` | present on every record | yes — as the causal-history clock |
| `AnalysisComponent.AnalysisComponentName/Type/Identifier`, `PersistenceFileName`, `Message`, `AffectedLogAtomPaths/Values` | present | **excluded** — every one of these names or is a near-1:1 proxy for which AMiner detector fired; using any of them would not be a non-identity model |

Built model (`newCol/fig9m_task2_aminer_model.py`): 5 features
(`raw_log_len`, `log_lines_count`, `alert_rate_1min`, `alerts_10min`,
`time_since_last_alert`, the last three computed causally per source
exactly like `shared_features.py`'s `AgentHistory`, reset per scenario
file), same audit-time `XGB_PARAMS` used throughout this response
(`n_estimators=50, max_depth=5, subsample=0.5, learning_rate=0.1`), fit
on the exact same `idx_train`/`idx_test` split as the AMiner lookup
table. Not fit with more capacity than 5 numeric features supports — same
shallow-tree budget as every other audit-time model in this response, no
larger.

**Result — this is a finding, not a gap, but not the one the task brief
flagged as the interesting failure case:**

| | F1 | vs. lookup (0.9773) | vs. trivial (0.9172) |
|---|--:|--:|--:|
| AMiner non-identity model | **0.9908** | **+0.0135** | **+0.0736** |

The model **beats** the lookup table, not the other way around. Feature
importance is concentrated almost entirely in `alert_rate_1min` (94.95%
of gain; `raw_log_len` 3.31%, everything else <1% each,
`log_lines_count` exactly 0%). Read plainly: **for AMiner, per-source
alert tempo — not signature identity — is the strongest available signal
in this split.** This narrows the identity-based claim further than
Task 1's F1 comparison alone already did: not only is AMiner's
identity-vs-trivial gap the smallest of the three non-degenerate cases
(+0.060), a simple non-identity feature set exceeds what identity alone
achieves.

**Caveat that must travel with this result, not be dropped:** this
project has already documented, for a structurally similar Wazuh feature
(`alert_rate_1min`, Figs 3a/8), that a rate-capped feature's apparent
separability can be partly or wholly a capture-tempo artifact rather than
a real behavioral signal — diagnosed there by testing whether benign
traffic ever approaches the same rate as attack traffic in an independent
collection. **No independent AMiner benign population exists in this
project's holdings, and per the no-new-collection rule none was
collected to test this here.** The 94.95%-importance concentration on
`alert_rate_1min` is exactly the pattern that turned out to be a partial
artifact for the Wazuh feature; it is reported as a real, computed result
on the available split, with this specific open question flagged
explicitly rather than either asserted as artifact-free or left
unmentioned.

---
**CHECKPOINT — STOP.** Awaiting go-ahead before proceeding to Task 3
(volume-weighted purity restatement, `newCol/lbl_purity_restatement.md`)
and Task 4 (population-labelled attack-rate statements).
