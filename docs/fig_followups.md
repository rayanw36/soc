# FIG-D: Figure follow-ups (F1-F5)

Checkpoint deliverable per the FIG-D prompt. No retraining, no new
collection, no threshold change to any deployed artifact. F1 and F2 were
flagged as submission blockers; both are resolved below with a traced
mechanism, not a rounded-away dismissal.

---

## F1 (BLOCKER) — 135.2× vs 136.2× tempo-ratio reconciliation

**Root cause, determined directly from code, not guessed:** the two
values use two different timestamp fields for the Linux/Windows fresh
collections, not two different span conventions on the same field.

- **135.2× (canonical, already frozen in `eval_set_definition.md`)** uses
  the `ts` column of `newCol/ew_features/ew_augmented_per_alert.csv`.
  `entity_window_extractor_ew.py:build_canonical()` sets
  `ts = event_time_utc if available else raw Wazuh timestamp`, with the
  function's own inline comment stating the preference explicitly:
  *"prefer validated event_time_utc (eval_set_definition.md
  methodology)."* `event_time_utc` is this project's own corrected event
  time (`newCol/label_lnx_timeonly.py`), built because Wazuh's raw alert
  `timestamp` lags the true event by a **variable 18.2s-80.4s** (median
  ~36s) of ingestion delay — documented there as large enough to
  misattribute technique/window membership if used uncorrected (74.1% of
  alerts would land on the wrong technique).
- **136.2× (superseded, was only ever in an unfinalized `fig5` draft)**
  used the raw Wazuh `timestamp` field directly from the four
  `collection_*.csv` files — the uncorrected, ingestion-lagged value
  `event_time_utc` exists specifically to fix.

**(a) Exact computation of each, side by side:**

| | 135.2× (canonical) | 136.2× (superseded) |
|---|---|---|
| field | `ts` (event_time_utc-preferred) | raw `timestamp` (Wazuh ingestion time) |
| source file | `ew_features/ew_augmented_per_alert.csv` | `collection_lnx_alerts.csv` / `collection_benign_lnx_alerts.csv` |
| span definition | `ts.max() - ts.min()`, inclusive, per `source` group | `timestamp.max() - timestamp.min()`, inclusive, per file |
| grouping | whole-collection (each of the 4 collections is single-agent already) | same |
| Linux attack rate | 8.943718 alerts/s (span 2580.694s) | 9.009431 alerts/s (span 2561.871s) |
| Linux benign rate | 0.066137 alerts/s | 0.066137 alerts/s (same, `ts`≈`timestamp` for this round) |
| ratio | **135.2302×** | 136.2× |

Only the Linux *attack*-side span differs (2580.694s vs. 2561.871s, a
~18.8s gap) — the attack round's first alert has a larger ingestion lag
than typical (raw `timestamp` starts 18.8s later than the corrected
`ts`), consistent with `label_lnx_timeonly.py`'s documented 18.2s-80.4s
lag range landing near its low end for this specific alert.

**(b) Canonical choice and appended note:** **135.2× (event-time-corrected
`ts`) is canonical.** Appended as `eval_set_definition.md` EW block v4
(not an edit to any frozen block above it) — states the methodology
explicitly for the first time (previously only implicit in code), gives
the full per-source recomputation (lnx_attack=8.943718/s,
lnx_benign=0.066137/s, win_attack=0.062476/s, win_benign=0.041411/s →
Linux ratio 135.2302×/135.2×, Windows ratio 1.5087×/1.5×, both matching
the existing frozen table to full precision), and records one documented
exception (below).

**One documented exception, not a second drift risk:** FIG-C Task 3
(`fig_corrections.md`) computed the deployed model's `alert_rate_1min`
feature using the raw `timestamp` field, not `ts` — correctly, because
that check's question was whether the *live production* pipeline's
capped feature is symmetrically censored, and a live system scoring
alerts as they arrive only ever has the raw ingestion timestamp
available, never a post-hoc-corrected `event_time_utc`. That check's own
conclusions (99.22%/0.00% at cap) are unaffected by this reconciliation.
Fig 8 (F5, below) uses the same raw-`timestamp` field for the same
reason.

**(c) Propagation — every site carrying the wrong value, and its fix:**

| artifact | old value | status |
|---|---|---|
| `newCol/figures_ms/fig5_tempo_asymmetry.py` | 136.2×/1.5× | **fixed** — now reads `ts` from `ew_augmented_per_alert.csv`, reproduces 135.2×/1.5× exactly |
| `newCol/figures_ms/fig5_tempo_asymmetry.png`/`.pdf` | 136.2× in panel title | **regenerated** |
| `newCol/figures_ms/captions.md` (Fig 5 prose + LaTeX block) | 136.2× | **fixed**, revision note added |
| `newCol/figures_ms/sources.md` (Fig 5 table) | 136.2× | **fixed**, revision note added |
| `newCol/figures_ms/fig_corrections.md` Task 3 | "9.01 alerts/s... ~0.7%... not a discrepancy" | **corrected in place** (appended correction, root cause stated; Task 3's own capped-feature conclusions unaffected) |

**Checked and NOT affected** (no fix needed): `eval_set_definition.md`
itself (already correct, source of truth), `ew_carrier_classification.md`,
`ew_supervisor_summary.md`, the drafted abstract — grepped directly for
"136" and "8.944"/"9.00"/"9.01" across `newCol/*.md`; 136.2× never
appeared anywhere outside the one unfinalized `fig5` draft and its own
documentation trail, listed above in full.

---

## F2 (BLOCKER) — labeling the three known-attack recall numbers

| value | population / config | source |
|---|---:|---|
| **99.96%** | rule 31101 alone, n=20,665 — **raw L1 (XGBoost) recall, no defer applied** | `eval_set_definition.md` block v1 canonical per-rule table |
| **2.25% (~2%)** | rule 31101 alone, n=20,665 — **v5+defer deployed combined decision** (= L2-only recall, since defer fully suppresses L1's vote for this rule) | same table |
| **9.11% (9.1%)** | rules 31101+31151 **combined**, n=22,250 — **v5+defer deployed combined decision, Fig 7 Panel A** | `newCol/threshold_sweep.csv`, `newCol/fnr_tp_threshold_v5defer.py` |

These are three different scopes, not three measurements of the same
quantity: 99.96% is a raw-L1 diagnostic (not what's deployed); 2.25% is
the deployed pipeline's actual rule-31101 recall; 9.11% is the deployed
pipeline's recall on a *different, larger* population that also includes
rule 31151.

**Specific hypothesis checked (per the prompt): are the 2,026 TPs behind
Fig 7 Panel A's 9.11% driven by rule 31151's L1 vote escaping defer while
31101's is suppressed? Checked directly against the production models —
FALSE.**

Verification (live recomputation, not assumed; full transcript below):

```
defer rules: ['31101', '31151', '5501', '5710']
known population rule_id counts:
  31101    20665
  31151     1585
known population agent_criticality values:
  1.0    22250   (100% of both rules, on the deferring agent)

fraction deferred overall: 1.0
deferred by rule_id:
  rule 31101: n=20665, deferred=20665, not_deferred=0
  rule 31151: n=1585,  deferred=1585,  not_deferred=0
```

Both rules are **100% deferred** — `is_deferred()` requires
`agent_criticality==1.0 AND rule_id in DEFER_RULES`, and every row of
both rules satisfies both conditions. L1 gets zero vote for either rule,
not just 31101. The hypothesis in the prompt is refuted.

**What actually produces 2,026 TPs**, recomputed directly:

```
overall known: TP= 2026 FN= 20224
rule 31101: n=20665, TP=465,  FN=20200, recall=0.0225 (2.25%)
rule 31151: n=1585,  TP=1561, FN=24,    recall=0.9849 (98.49%)
L2-only recall 31101: 0.02250181466247278
L2-only recall 31151: 0.9848580441640379
```

Rule 31151's *L2* (OC-SVM) recall is genuinely 98.49% — matching
`eval_set_definition.md` block v2's existing "31151 | 1,585 | 0 | 100.00%
| 98.49% | N/A | N/A" row exactly — while rule 31101's L2 recall is
2.25%. Panel A's 9.11% is the **volume-weighted blend** of these two
very different per-rule L2 recalls: $20{,}665 \times 2.25\% + 1{,}585
\times 98.49\% = 465 + 1{,}561 = 2{,}026$, matching
`threshold_sweep.csv`'s Panel-A TP exactly. The mechanism is per-rule L2
recall heterogeneity plus a 13:1 volume imbalance toward the low-recall
rule (31101 is 92.9% of the combined population) — not an L1-suppression
escape for either rule.

**Applied to Fig 7:** Panel A's title now reads "v5+defer combined
decision, known attacks (31101+31151 blended)"; an inline annotation on
the plot decomposes the 9.1% into its two per-rule components with an
arrow to the flat recall line; `captions.md`'s Fig 7 caveats and LaTeX
block both state the three-number distinction and the refuted
hypothesis explicitly.

---

## F3 — Fig 4 retitled to the below-chance finding

Old title: "attack and benign OC-SVM scores overlap heavily at the
per-alert level." True but weaker than what the data shows: at the
deployed threshold, **FPR (4.78%) exceeds recall (2.25%)** — verified
in-script (`assert fpr_l2 > recall_l2`). FPR exceeding recall places this
specific operating point at or below the chance diagonal: the novelty
layer is not merely uninformative for this rule at this threshold, it is
anti-informative (flags benign more often than attack). Retitled to
*"At the deployed threshold, the novelty layer flags benign rule-31101
alerts more often than attack."* The existing threshold-pointing
annotation is unchanged; `captions.md`'s prose and LaTeX caption both
carry the below-chance framing now.

---

## F4 — Fig 6 rule descriptions + combined benign-realism reading

Axis labels now carry a short `rule.description` beside each rule ID
(source: the four raw `collection_*.csv` files' own `description`
column, first occurrence per `rule_id`, truncated to ~28 characters) —
bare numbers were uninterpretable. E.g. 31101 → "Web server 400 error
code", 92004 → "Powershell process spawned...".

Combined reading added to `captions.md`'s Fig 6 caveats and LaTeX
caption: Linux benign's 78.3% (rule 31101) is bare `curl/8.5.0` polling
three fixed endpoints (each non-2xx hit firing this rule, per Fig 3b's
existing caveat); the file-integrity remainder (rule 550 and related) is
CUPS's own periodic subscription-lease file rewrite
(`/etc/cups/subscriptions.conf` and its `.O`/`.N` shadow copies), not
human file activity — confirmed via `art_contamination_check.md` and
`pre_ms_number_fixes.md` FIX 1/2 (already-established findings, not
re-derived here). Stated together: **the Linux benign corpus is
machine-generated daemon traffic almost end to end, not human
activity** — the concrete, visible form of this study's benign-realism
limitation.

---

## F5 — Cross-dataset cap comparison: new standalone Fig 8

**Chosen as a standalone figure, not a third Fig 5 panel.** Fig 5 plots
a single scalar (mean alerts/s) per collection round using the
event-time-corrected `ts` field; this figure plots the full per-alert
distribution of one specific capped feature (`alert_rate_1min`), using
the raw-timestamp field production actually sees, for the benign class
only, across two datasets. Combining them would force two different
x-axis quantities and two different timestamp-field conventions onto one
plot — clearer as two figures, each making one point.

**What it shows:** the same unfitted rule (`alert_rate_1min >= 20`,
the feature's hard `AgentHistory(maxlen=20)` buffer cap,
`shared_features.py:157`) applied identically to the benign class of two
datasets gives opposite verdicts, using only the benign distribution:

| | benign at cap | benign max value | rule FPR | verdict |
|---|--:|--:|--:|---|
| AIT-ADS | 32.9% | 20 (the cap itself) | 0.3291 | partial, genuine signal |
| Linux testbed | 0.00% | 10 (of 20) | 0.0000 | pure collection artifact |

Both datasets' summary numbers were already established
(`tempo_ait_check.md` for AIT-ADS; `fig_corrections.md` Task 3 for
Linux); this figure plots the full distributions rather than only their
summary percentages, making the mechanism (where the benign mass sits
relative to the cap) visible directly. This is the paper's own
methodological contribution made visible — the same control that
diagnosed the testbed's capture-tempo defect applies unchanged to a
second, independent dataset and correctly distinguishes signal from
artifact using the benign side alone.

---

## Files touched in this pass

- `newCol/eval_set_definition.md` — EW block v4 appended (F1).
- `newCol/figures_ms/fig5_tempo_asymmetry.py/.pdf/.png` — fixed to use
  `ts` (F1).
- `newCol/figures_ms/fig_corrections.md` — Task 3 tempo-ratio citation
  corrected in place (F1).
- `newCol/figures_ms/fig7_threshold_sweep_v5defer.py/.pdf/.png` —
  Panel A retitled + annotated (F2).
- `newCol/figures_ms/fig4_31101_score_overlap.py/.pdf/.png` — retitled
  (F3).
- `newCol/figures_ms/fig6_benign_composition.py/.pdf/.png` — rule
  descriptions added (F4).
- `newCol/figures_ms/fig8_cap_censoring_cross_dataset.py/.pdf/.png` —
  new figure (F5).
- `newCol/figures_ms/captions.md` — all five figures' prose and LaTeX
  blocks updated/added.
- `newCol/figures_ms/sources.md` — all five figures' source tables
  updated/added.
- `newCol/figures_ms/fig_followups.md` — this file.

No other committed artifact was modified.
