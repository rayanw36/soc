# FIG9-C1 — Control C1 on the AMiner tempo model, Suricata restatement, FPR contrast

Script: `newCol/fig9c1_task1_check.py` (output
`newCol/fig9c1_task1_results.json`). Read-only: re-parses
`data/ait_ads/raw/*_aminer.json` with the identical `alert_rate_1min`
computation as `newCol/fig9m_task2_aminer_model.py`, and reuses
`newCol/xdet_aminer_split.npz`'s existing `idx_train`/`idx_test`/`y_all`.
No new collection, no retraining. `models_v2/*` untouched.

---

## Task 1 (blocking) — Control C1 on the AMiner tempo feature

### a. `alert_rate_1min` distribution, attack vs. benign, AMiner eval split

Eval split: n=11,112 (attack=9,412, 84.70%; benign=1,700, 15.30% —
matches the 15.30%-of-11,112 figure the task brief cites exactly).

| | n | min | median | p90 | p95 | p99 | max |
|---|--:|--:|--:|--:|--:|--:|--:|
| ATTACK | 9,412 | 0 | 20.0 | 20.0 | 20.0 | 20.0 | 20 |
| BENIGN | 1,700 | 0 | 2.0 | 17.0 | 20.0 | 20.0 | 20 |

The feature is low-cardinality (21 distinct integer values, 0–20 — it
inherits the same 20-alert rolling-buffer cap convention as the Wazuh
pipeline's `AgentHistory`, since `fig9m_task2_aminer_model.py`'s
`SourceHistory` was deliberately built to the same `maxlen=20`
discipline). Full value counts:

| value | attack n | attack % | benign n | benign % |
|--:|--:|--:|--:|--:|
| 0 | 25 | 0.27% | 570 | 33.53% |
| 1 | 15 | 0.16% | 231 | 13.59% |
| 2 | 10 | 0.11% | 162 | 9.53% |
| 3 | 11 | 0.12% | 97 | 5.71% |
| 4 | 8 | 0.08% | 72 | 4.24% |
| 5 | 5 | 0.05% | 70 | 4.12% |
| 6 | 9 | 0.10% | 46 | 2.71% |
| 7 | 11 | 0.12% | 52 | 3.06% |
| 8 | 10 | 0.11% | 42 | 2.47% |
| 9 | 9 | 0.10% | 28 | 1.65% |
| 10 | 8 | 0.08% | 29 | 1.71% |
| 11 | 6 | 0.06% | 28 | 1.65% |
| 12 | 6 | 0.06% | 26 | 1.53% |
| 13 | 8 | 0.08% | 24 | 1.41% |
| 14 | 9 | 0.10% | 20 | 1.18% |
| 15 | 6 | 0.06% | 13 | 0.76% |
| 16 | 8 | 0.08% | 12 | 0.71% |
| 17 | 4 | 0.04% | 13 | 0.76% |
| 18 | 9 | 0.10% | 9 | 0.53% |
| 19 | 6 | 0.06% | 13 | 0.76% |
| **20 (cap)** | **9,229** | **98.06%** | **143** | **8.41%** |

### b. C1 decision rule — PASS or FAIL

**Rule as given:** fail if the benign maximum does not reach the range in
which attack rows sit (benign never approaches a level attack rows
commonly occupy).

- Attack rows overwhelmingly occupy the cap: 98.06% sit at value 20
  (median = p90 = p95 = p99 = max = 20).
- **Benign max = 20 — identical to the attack max, not merely close to
  it.** Benign is not a thin tail brushing the edge of attack's range:
  8.41% of benign rows (143 of 1,700) sit at the same cap value that
  98.06% of attack rows occupy, and benign's own p95/p99 are already at
  that value.

**Verdict: PASS.** Benign does reach — repeatedly, not as a rare outlier
— the exact level attack rows commonly occupy. This is not the pattern
of the FAIL cases this project has already retracted on the same control
(Linux testbed benign for `alert_rate_1min`: maximum observed value 10 of
20, *never* reaching the cap at all — `fig_corrections.md` Task 3, cited
in Fig 8's caption). It also is not a clean, artifact-free PASS either —
see the honest caveat below.

### c. Share of attack rows above benign's p99 / above benign's max

**Both are 0.00% — and this number is structurally uninformative here,
stated plainly rather than left to imply a stronger separation than
exists.** Benign's own p99 is already 20 (the same hard cap attack rows
saturate at), and the feature cannot exceed 20 for *either* class — the
20-alert rolling-buffer cap is a hard ceiling applied identically to both
(the same structural-cap caveat Fig 8 already carries for the analogous
Wazuh feature). "Share of attack above benign's max" is guaranteed to be
0% whenever benign's max already sits at the feature's structural
ceiling, regardless of how the two distributions actually differ in
shape — it does not distinguish this case from a hypothetical case where
benign also saturated 98% of the time.

**The number that actually makes the separation legible is the density
at the shared cap, already in the table above: 98.06% of attack rows sit
at the cap vs. 8.41% of benign rows.** That is a real, substantial
difference in shape (attack is heavily concentrated at the ceiling;
benign is spread across the full 0–20 range with a mode near 0), even
though both classes' *range* is identical. This is the correct
replacement for the requested "share above p99/max" statistics in a
capped feature, and is reported here instead of a 0.00%/0.00% pair that
would otherwise misleadingly read as "complete separation."

### d. Verdict and consequence

**PASS.** Benign and attack `alert_rate_1min` distributions overlap
substantially — same 0–20 range, same maximum, benign repeatedly (8.41%
of the time) reaching the identical value that dominates the attack
class. **The AMiner non-identity model (F1=0.9908,
`newCol/fig9_metric_fix.md` Task 2) is a genuine finding under this
control, and the model bar stays in Fig 9.** `captions.md`/`sources.md`
updated (not the rendered bars — their values do not change) to cite this
C1 result as the supporting evidence the prior caveat flagged as missing.

**This is not a clean, unqualified PASS, and the caption says so.** AIT-ADS's
own analogous Wazuh feature (Fig 8) showed benign at the cap 32.9% of the
time — nearly 4× AMiner benign's 8.41% rate here. AMiner's overlap is
real (unlike the Linux-testbed FAIL case, which was exactly zero) but
thinner than the already-partial AIT-ADS Wazuh case. The 94.95%-gain
concentration on this one feature (Task 2) is explained by density, not
by the classes occupying disjoint ranges: a classifier reading
"`alert_rate_1min` = 20" is right about 98% of the time on this split
because 98.06% of attack rows land there, not because no benign row ever
does.

### e. Consistency with time-window labelling

**AIT-ADS labels are time-window intervals** (`newCol/lbl_provenance.md`
Task 1c: `scenario, attack, start, end`, no per-alert or per-log-line
join key). A per-source tempo feature computed purely from event
timestamps is exactly the kind of feature most exposed to inheriting that
labelling mechanism rather than a causal detection signal: **any** source
whose alerts happen to cluster in time near a labelled attack window
receives a high `alert_rate_1min` reading and an attack label together,
whether or not that specific source's burst of activity is the attack
itself or simply ambient/co-located traffic active during the same
window. **The C1 PASS result is consistent with this mechanism, not
independent evidence against it.** C1 only tests whether benign ever
reaches the same feature range as attack (it does); it cannot and does
not test whether the *reason* attack rows saturate the cap is a genuine
per-source behavioral signature of the attack technique, versus
elevated background alert tempo during labelled attack windows more
generally (testbed activity ramping up dataset-wide, not just for the
attacked host). Distinguishing those two explanations would require
checking whether high-tempo attack rows are concentrated on the
specific host/service actually targeted by each named attack phase, not
just "some host was busy while an attack was nominally running
somewhere in the scenario" — that check was not run here (out of this
task's scope) and should be flagged as the natural next control, not
assumed resolved by C1's pass.

---

## Task 2 — Suricata restated honestly

### a. Raw counts (eval split, n=61,536; 1,190 actual attack alerts, 1.93%)

The lookup table flags **33 alerts** as attack — `tp=33, fp=0` — **all 33
are correct** (precision 1.0000). It flags nothing else: the remaining
61,503 alerts (99.9464% of the eval split) are predicted benign,
including 1,157 of the 1,190 actual attack alerts it misses entirely
(recall 2.77%).

33 flagged alerts out of 61,536 = **0.0536% of Suricata's eval volume.**
Scaled to Suricata's full population (306,635 alerts,
`newCol/lbl_provenance.md` Task 1b), this is the same phenomenon already
measured there directly: 5 of 29 Suricata signatures are attack-only,
covering 201 of 306,635 alerts (0.07%) — the eval-split figure here
(33/61,536, one fold of that same population) is consistent with that
population-wide number, not a separate measurement.

### b. Honest summary

**Reporting "lookup beats trivial by +0.016 F1" is technically true and
substantively misleading — both anchor numbers are near zero, and F1 at
a 1.93% base rate is dominated by precision on a vanishingly small
flagged set, not by any broad identity signal.** The correct claim is not
a marginal F1 win over a weak reference point; it is the **absence of an
exploitable identity shortcut** for this detector: when a Suricata
signature happens to be attack-majority in training, the lookup table is
essentially always right about it (precision 1.0000, 33/33) — but such
signatures are rare and cover a negligible share of volume (5 of 29
signatures dataset-wide, ~0.07% of alerts). For the other 99.93% of
Suricata's volume, signature identity provides no usable signal at all;
this is why recall stays at 2.77% even though precision is perfect.

### c. Wording for the manuscript and Fig 9's caption

> On Suricata, the per-signature lookup table flags only 33 of 61,536
> eval-split alerts (0.05%) and is correct on all 33 (precision 1.0000),
> but this covers a negligible share of Suricata's volume — 5 of its 29
> signatures are attack-majority, accounting for ~0.07% of all Suricata
> alerts dataset-wide. The correct reading is not that identity provides
> a small edge over a trivial baseline (F1 0.054 vs. 0.038), but that
> Suricata shows no exploitable identity-based label proxy at any
> meaningful scale: precision is perfect only because almost nothing is
> ever flagged.

---

## Task 3 — AMiner lookup FPR as a contrast

| detector | lookup FPR |
|---|--:|
| Wazuh-native | 0.000508 |
| AMiner | 0.221176 |

**Ratio: 0.221176 / 0.000508 ≈ 435×** (task brief's "roughly 400" is
directionally correct; 435–436× is the precise figure from the committed
confusion-matrix counts, `newCol/xdet_task1_results.json`).

**This is the sharper form of the cross-detector finding and belongs in
the manuscript stated directly, not left to be inferred from the F1
table:**

> The two non-trivial detectors' lookup tables differ by more than two
> orders of magnitude in false-positive rate at comparable precision
> targets — Wazuh-native's FPR is 0.05% versus AMiner's 22.1%, a
> ~435× gap. This reflects two qualitatively different mechanisms rather
> than one finding at two strengths: on Wazuh-native, signature identity
> is close to deterministic for the label (FPR near zero because
> almost every signature is overwhelmingly one class), whereas on
> AMiner, identity is a weak prior riding on top of an already-high
> (84.7%) base rate — good enough to beat a trivial always-attack
> classifier on F1, but nowhere near strong enough to avoid flagging
> roughly one in five actual benign alerts.

---

## Fig 9 caption/sources updates made for this task

`newCol/figures_ms/captions.md` and `sources.md`'s Fig 9 entries updated
(not the rendered `.pdf`/`.png` — Task 1's PASS verdict does not change
any plotted bar value) to:
1. Cite the C1 PASS result (§1b–d above) as the resolution of the
   previously-open tempo-artifact caveat on the AMiner model bar, stated
   with its own honest qualifier (thinner overlap than the AIT-ADS Wazuh
   analog, density-driven not range-driven separation).
2. Replace the Suricata "+0.016 F1" framing with the raw-count framing
   from Task 2c.
3. Add the Wazuh-native-vs-AMiner FPR contrast (Task 3) as an explicit
   sentence, not left implicit in the per-series F1 numbers.

---
**CHECKPOINT — STOP.** Awaiting go-ahead before the two previously
deferred FIG9-M tasks (Task 3: volume-weighted purity restatement,
`newCol/lbl_purity_restatement.md`; Task 4: population-labelled
attack-rate statements).
