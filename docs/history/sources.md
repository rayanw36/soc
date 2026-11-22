# Figure sources — Figs 1–3

Every value plotted, with the committed artifact it was read from. No
value in Figs 1–3 is hardcoded in a plotting script; each script prints
its source path(s) at run time (see script stdout, reproduced below).

## Fig 1 — `fig1_lookup_vs_model`

| value plotted | number | source file | field |
|---|--:|---|---|
| Lookup-table F1 | 0.9942 | `results/rule_memorization_audit/exp3_lookup_results.csv` | `Lookup-table F1 (rule_id only)` |
| XGBoost F1 (26 feat., audit retrain) | 0.9945 | `results/rule_memorization_audit/exp4_ablation_main.csv` | row `variant=full`, column `ait_f1` |
| gap (annotated) | +0.0003 | computed as XGBoost F1 − lookup F1 (script-computed, both operands committed) | — |

**Value checked but NOT plotted:** `exp3_lookup_results.csv`'s own
`XGBoost F1 (published)` field = 0.0000. Not used — confirmed to be a
degenerate measurement caused by an XGBoost model-serialization version
mismatch when loading `models_v2/xgb_model.pkl` in this environment
(xgboost 3.3.0; load raises an explicit version-mismatch warning).
`exp4_ablation.py`'s own docstring independently corroborates this
("fresh retrain; used as baseline since pkl has version mismatch").

**Values requested by the FIG prompt but NOT available in any committed
artifact, and therefore NOT plotted:** precision (either series),
recall (lookup-table series only). No committed CSV, log, or notebook
output in this repository contains them for these two series.

## Fig 2 — `fig2_feature_composition`

*(Redesigned from a two-panel bucket-composition chart to a single bar
after review — TEMPO-AIT Task 4: both panels were orange-dominated and
read as the same fact twice. See captions.md revision note.)*

| value plotted | source file | field |
|---|---|---|
| `is_web_attack` gain share: 94.9920% (labeled 95.0%) | `results/rule_memorization_audit/exp2_importance_gain.csv` | row `feature=is_web_attack`, column `gain_pct` |
| other 25 features combined: 5.0080% (labeled 5.0%) | same file | sum of `gain_pct` over all other rows |
| feature-count note (caption only, not plotted): RULE-IDENTITY=3, RULE-CORRELATED=21, BEHAVIORAL=2 of 26 (corrected, FIG-C Task 2) | `results/rule_memorization_audit/exp1_feature_classification.csv` `bucket` column, with `time_since_last_high` reclassified BEHAVIORAL→RULE-CORRELATED | see `feature_classification_correction.md` for the full correction and recomputed gain shares |

Consistency check performed before use: exp1's and exp2's `bucket`
column were compared for all 26 features and found identical (see
`fig2_feature_composition.py`'s predecessor script header; not
re-verified in the redesigned script since it no longer uses exp1's
`bucket` column for anything plotted, only for the caption's count
note, which is read directly from exp1 independent of exp2).

## Fig 3a — `fig3a_ablation_separability`

*(Split from a single combined `fig3_two_level_identity` draft after
review — that framing contradicted its own left panel. See captions.md
revision note.)*

### Left panel — 26-feature pipeline ablation

*(Retitled from "Three unrelated feature subsets each separate AIT-ADS"
to "Every subset that separates AIT-ADS carries rule-definition metadata"
— FIG-C Task 1. See `feature_classification_correction.md` for the
supporting taxonomy correction and `captions.md`'s revision note 3.)*

| value plotted | source file | field |
|---|---|---|
| `full`: recall=0.9891, FPR=0.0000, F1=0.9945 | `results/rule_memorization_audit/exp4_ablation_main.csv` | row `variant=full`, columns `ait_recall`,`ait_fpr`,`ait_f1` |
| `no_identity`: recall=0.9891, FPR=0.0000, F1=0.9945 | same file | row `variant=no_identity` |
| `behav_only`: recall=0.9886, FPR=0.0187, F1=0.9895 | same file | row `variant=behav_only` |

### Right panel — unfitted rate thresholds on AIT-ADS

All values computed directly from `models_v2/ait_split.npz` (n=2,600,263;
attack=1,717,524; benign=882,739 — the same split `exp3`/`exp4` use),
via group-wise descriptive statistics and unfitted single-feature
threshold rules. No model is trained or retrained for this panel.

| value plotted | derivation |
|---|---|
| `alert_rate_1min`: 99.3% of attack rows at cap (20) vs. 32.9% of benign | `(col[y==1] >= 20).mean()` / `(col[y==0] >= 20).mean()` on the `alert_rate_1min` column |
| `time_since_last_high`: 80.4% of attack rows = 0 vs. 1.0% of benign; 78.9% of benign at sentinel (999) | same treatment on the `time_since_last_high` column |
| threshold rule `time_since_last_high==0`: recall=0.8036, FPR=0.0103 | unfitted rule applied to the full concatenated split, scored against `y` |
| threshold rule `alert_rate_1min>=20`: recall=0.9925, FPR=0.3291 | same treatment |

This was checked here for the first time in this project (grepped
`newCol/*.md` for prior AIT-ADS-specific burst/tempo/rate mentions
before running it — none found; the existing 135× finding in
`newCol/eval_set_definition.md` is scoped to the custom Linux/Windows
testbed, not AIT-ADS) — and then **follow-up verified** in the TEMPO-AIT
check below, which changed how the panel is titled/captioned.

### TEMPO-AIT check — full provenance for the right panel's framing

Full report: `newCol/figures_ms/tempo_ait_check.md`. Summary of what it
established (all from `models_v2/ait_split.npz` and `shared_features.py`,
no retraining):

| question | finding | verdict impact |
|---|---|---|
| Does benign ever reach `alert_rate_1min`'s cap? | Yes — 32.9% of benign rows, vs. 99.3% of attack rows (full histogram in `tempo_ait_check.md` Task 1) | Not a clean artifact like the 135× Linux case (benign there never approached attack density); a partial, coarse signal |
| Is `time_since_last_high==0` ever true for benign? | Yes — 9,121 of 882,739 rows (1.03%), not zero | Rare but real; the dominant benign mode (78.9%) is the 999 sentinel, not a hard zero |
| Where does the cap (20) come from? | `shared_features.py:157`, `AgentHistory.__init__(maxlen=20)` — a hard buffer-size ceiling, not a fitted/inspected value | "Unfitted" label for the rule confirmed accurate |
| Where does the floor (0) come from? | `shared_features.py:187,224-226,208` — sentinel default 999.0, `dt` (elapsed seconds) explicitly floored via a `dt < 0: continue` skip | "Unfitted" label for the rule confirmed accurate |
| Is `time_since_last_high` a pure tempo/volume signal? | No — it measures proximity to a rule-severity (level≥10) event; `rule_level` is itself classified RULE-IDENTITY in `exp1_feature_classification.csv` | Reclassifies this feature's likely mechanism as closer to rule metadata than to behavioral tempo |

Verdict: **mixed**, not "artifact confirmed" — per the TEMPO-AIT task's
own instruction, the right panel's title was changed from "a
capture-tempo artifact" to the factual claim already proven by the bars:
"Unfitted single-feature rate thresholds separate AIT-ADS without
training."

## Fig 3b — `fig3b_31101_tier_study`

### Raw HTTP tier study (rule 31101)

| value plotted | source | derivation |
|---|---|---|
| Tier A: TP=3464,FN=0,FP=0,TN=42 → recall=1.0000, FPR=0.0000 | `newCol/fr_31101_report.md`, Task 3 table | counts transcribed from the frozen table; recall/FPR recomputed from those counts in-script (display convenience, not a re-evaluation) |
| Tier B: TP=3464,FN=0,FP=28,TN=14 → recall=1.0000, FPR=0.6667 (labeled "28/42" on the bar) | same table | same treatment; raw FP/(FP+TN) = 28/42 printed alongside the rate per TEMPO-AIT Task 4 (denominator too small to state as a bare percentage) |
| trivial "always attack" baseline: TP=3464,FN=0,FP=42,TN=0 → FPR=1.0000, F1=0.9940 | same table | same treatment |
| n confirmation (test: 3,464 attack / 42 benign) | `newCol/fr_31101_features.csv` | counted directly: rows where `split=="test"`, grouped by `cls` — matches the report table's n exactly (assertion in script) |
| Tier C reference ratio: 1,519× (`ew_global_trail60m_distinct_url_count`) | `newCol/ew_phase3_31101_per_alert_combined.csv` | median of the column for `label=="attack"` (4,557) ÷ median for `label=="benign"` (3) — recomputed directly from the committed per-alert feature file, verified equal to `ew_phase3_31101_case_study.md` §3b's printed value before use (assertion in script) |

### Values NOT plotted from Task 2/4/5 of the FR-31101 report

No Tier C per-alert recall/FPR exists in any committed artifact — the
FR-31101 report itself did not fit Tier C as a per-alert classifier
(scoped "reference only" in its own Task 2). Nothing was reconstructed
to fill that gap; the panel instead cites the aggregate ratio as a
labeled reference figure, not a fourth bar.

## Fig 4 — `fig4_31101_score_overlap`

*(Left panel only of the pre-existing `newCol/ew_fig_31101_before_after.png`
-- the right panel there, entity-window aggregation, is a retracted
positive result and is not reproduced. Approved as part of the FIG-C
Task 5 Figs 4-7 list.)*

| value plotted | source file | field |
|---|---|---|
| per-alert `ocsvm_score` density, attack (n=20,665) vs. benign (n=209) | `newCol/ew_phase3_31101_per_alert_combined.csv` | `ocsvm_score`, `label` columns |
| deployed threshold theta_ocsvm = -0.3349956708403319 | `models_v2/thresholds_production_v3.json` | `theta_ocsvm` field |
| L2 recall=2.25%, L2 FPR=4.78% (annotated on plot) | computed in-script: `(ocsvm_score >= theta_ocsvm)` per class | decision direction confirmed against `combined_decision_v3.py`'s documented convention; reproduces `eval_set_definition.md`'s rule-31101 row exactly |
| below-chance confirmation: FPR (4.78%) > recall (2.25%) (title, FIG-D F3) | same in-script computation | `assert fpr_l2 > recall_l2` in-script |

## Fig 5 — `fig5_tempo_asymmetry`

*(FIG-D F1 correction: first draft used the raw `timestamp` field from
`collection_*.csv` directly, giving 136.2x/1.5x. Corrected to use the
project's own event-time-corrected `ts` field, per
`eval_set_definition.md` EW block v4 / `fig_followups.md` F1. Table
below reflects the corrected version.)*

| value plotted | source file | derivation |
|---|---|---|
| Linux attack rate = 8.943718 alerts/s | `newCol/ew_features/ew_augmented_per_alert.csv` | rows `source=="lnx_attack"`, row count ÷ (max(`ts`) − min(`ts`)) |
| Linux benign rate = 0.066137 alerts/s | same file | rows `source=="lnx_benign"`, same treatment |
| Windows attack rate = 0.062476 alerts/s | same file | rows `source=="win_attack"`, same treatment |
| Windows benign rate = 0.041411 alerts/s | same file | rows `source=="win_benign"`, same treatment |
| Linux ratio = 135.2x, Windows ratio = 1.5x (panel titles) | computed from the four rates above | matches `eval_set_definition.md` Task 1c's frozen 135.2x/1.5x table exactly |

## Fig 6 — `fig6_benign_composition`

| value plotted | source file | field |
|---|---|---|
| Linux benign top-5 rule_id shares (31101=78.3%, 5501=8.2%, 5502=4.1%, 5402=3.7%, 550=2.2%, other=3.4%) | `newCol/ew_features/ew_augmented_per_alert.csv` | rows where `source=="lnx_benign"`, `rule_id.value_counts(normalize=True)` |
| Windows benign top-5 rule_id shares (92004=38.8%, 60106=28.9%, 92219=13.9%, 92200=4.5%, 92052=2.0%, other=11.9%) | same file | rows where `source=="win_benign"`, same treatment -- reproduces `figure_inventory.md`'s cited 92004/60106 values exactly |
| confirmation: rules 60122/60204 absent from win_benign | same file | `assert` in-script that neither rule_id appears in the `win_benign` subset |
| rule descriptions (axis labels, FIG-D F4), e.g. 31101="Web server 400 error code", 92004="Powershell process spawned..." | `newCol/collection_lnx_alerts.csv`, `collection_benign_lnx_alerts.csv`, `collection_win_alerts.csv`, `collection_benign_win_alerts.csv` | `description` column, first occurrence per `rule_id` across the four files, truncated to ~28 chars for the axis |

## Fig 7 — `fig7_threshold_sweep_v5defer`

*(Replot, in the manuscript's shared style, of the figure
`figure_inventory.md` itself flags as "current, publication-quality
as-is, no outstanding caveat" -- sweep itself is not rerun.)*

| value plotted | source file | field |
|---|---|---|
| Panel A recall/FPR curves vs. theta_xgb | `newCol/threshold_sweep.csv` | rows `panel=="A_known_L1_sweep"`, `recall=tp/(tp+fn)`, `fpr=fp/(fp+tn)` computed in-script |
| Panel B recall/FPR curves vs. theta_ocsvm | same file | rows `panel=="B_novel_L2_sweep"`, same treatment |
| deployed threshold lines (theta_xgb=0.07538, theta_ocsvm=-0.33500) | `models_v2/thresholds_production_v3.json` | `theta_xgb`, `theta_ocsvm` fields |
| Panel A flat-recall check: TP=2026, FN=20224 constant across all 400 rows | `newCol/threshold_sweep.csv` | `assert a.tp.nunique()==1 and a.fn.nunique()==1` in-script |
| Panel A FPR range 18-47 (of 267 benign) -- NOT flat, checked directly | same file | `a.fp.min()`, `a.fp.max()` -- see caption for why (mixed, partly-non-deferred benign population) |
| Panel A 9.1% recall blend annotation: rule 31101 recall=2.25% (n=20,665), rule 31151 recall=98.49% (n=1,585) | `newCol/eval_set_definition.md` block v2, canonical per-rule table | hardcoded from this frozen, already-committed table (same pattern as Fig 3b's TIER_COUNTS); arithmetic check `20665*0.0225 + 1585*0.9849 = 2026` verified in-script against threshold_sweep.csv's Panel-A TP |
| Alternative-hypothesis check (rule 31151 escapes defer): FALSE, both rules 100% deferred | live recomputation against `combined_decision_v6.load_production_models()` + `models_v2/ocsvm_nu05.pkl`, not committed as a CSV | one-off verification script, full transcript in `fig_followups.md` F2; not re-run inside the fig script itself (fig script only reads the pre-committed `threshold_sweep.csv` and cites the frozen per-rule table for the annotation, per FIG RULE 2 plotting-only) |

## Fig 8 — `fig8_cap_censoring_cross_dataset`

*(New figure, FIG-D F5 -- standalone rather than a third Fig 5 panel;
see captions.md for the stated reason.)*

| value plotted | source file | derivation |
|---|---|---|
| AIT-ADS benign `alert_rate_1min` distribution (n=882,739), frac at cap=0.3291 | `models_v2/ait_split.npz` | rows `y==0`, `alert_rate_1min` column (same array `fig3a_ablation_separability.py`'s right panel already summarizes as two scalars) |
| Linux testbed benign `alert_rate_1min` distribution (n=267), frac at cap=0.0000, max=10 | `newCol/collection_benign_lnx_alerts.csv` | recomputed via `AgentHistory` replication on the raw `timestamp` field (same method and result as `fig_corrections.md` Task 3's summary stats; this figure plots the full distribution) |
| cap marker (20) | `shared_features.py:157`, `AgentHistory(maxlen=20)` | structural buffer-size constant, not fitted |

## Fig 9 — `fig9_cross_detector_lookup`

*(New figure, XDET audit Task 4 -- the audit's cross-detector companion
to Fig 1, generalized from one detector to three. AMiner's dominant
signature (49.2% of its volume, ratio 373.5) was independently verified
post-hoc (XDET-V Task 1): `newCol/xdet_aminer_signature_check.md`,
`newCol/xdet_aminer_dominant_sig_records.csv` -- it separates on a
single, exact User-Agent string (`WPScan v3.8.20 ...`), the same
fragile-identity mechanism already documented for Wazuh rule 31101 Tier A,
not independently-verified generalizable detection. The Wazuh
86601/Suricata contrast was similarly re-labelled with exact
per-configuration numbers: `newCol/xdet_86601_numbers.md`. Full audit report:
`newCol/xdet_results.md`, `newCol/xdet_task0_composition.md`.)*

**REVISION (FIG9-M Tasks 1–2, supersedes the original recall-only
version and its `n/a` AMiner model bar):** recall alone cannot separate
signature-identity memorization from class imbalance, since a trivial
always-predict-attack classifier scores recall=1.000 on every detector
regardless of base rate. Rebuilt on F1, with a per-detector trivial
baseline bar (base rates differ sharply: 74.7% Wazuh-native, 1.9%
Suricata, 84.7% AMiner, so one shared reference line would misrepresent
two of the three groups). Full derivation, per-detector precision/recall/
FPR (not just F1), and the verdict on whether each lookup table beats its
trivial baseline: `newCol/fig9_metric_fix.md`.

| value plotted | source file | field |
|---|---|---|
| Wazuh-native lookup F1 = 0.9960 | `newCol/fig9m_task1_results.json` | row `detector=Wazuh-native, series=lookup` |
| Wazuh-native model F1 = 0.9962 | same file | row `detector=Wazuh-native, series=model` |
| Wazuh-native trivial F1 = 0.8549 | same file | row `detector=Wazuh-native, series=trivial` |
| Suricata lookup F1 = 0.0540 | same file | row `detector=Suricata, series=lookup` |
| Suricata model F1 = 0.0821 | same file | row `detector=Suricata, series=model` |
| Suricata trivial F1 = 0.0379 | same file | row `detector=Suricata, series=trivial` |
| AMiner lookup F1 = 0.9773 | same file | row `detector=AMiner, series=lookup` |
| AMiner trivial F1 = 0.9172 | same file | row `detector=AMiner, series=trivial` |
| AMiner model† F1 = 0.9908 | `newCol/fig9m_task2_aminer_model_results.json` | `f1` (5-feature non-identity model — see caveat below, NOT the same construction as the other two model bars) |
| all `n`/base-rate annotations | `newCol/xdet_task1_results.json` | `{wazuh_native,suricata,aminer}.n_eval`; base rate is `fig9m_task1_results.json`'s `trivial.precision` row |

`newCol/fig9m_task1_results.json` and `fig9m_task1_baselines.py` compute
the trivial-baseline row directly from the *same* confusion-matrix
denominators (`tp+fn`, `fp+tn`) already committed for each detector's
lookup table in `xdet_task1_results.json` — i.e. the trivial baseline is
scored on the identical eval population, not a separately-drawn one.

**Provenance of `xdet_task1_results.json` itself** (i.e., where these
numbers come from, one level up):
- Wazuh-native / Suricata lookup tables: built on the training portion,
  scored on the eval portion, of the *exact* recovered `ait_split.npz`
  train/test partition (`newCol/xdet_recover_wazuh_split.py` — verified
  byte-identical to the deployed split's `y_train`/`y_test` before use),
  keyed on `rule.id` (Wazuh-native, excluding rule 86601) or
  `rule.description` (Suricata, the rule-86601 subset only).
- AMiner lookup table: same train/eval discipline, on a freshly
  constructed 80/20 stratified split (`newCol/xdet_build_aminer.py`,
  same `test_size`/`SEED` convention as the Wazuh split but explicitly
  *not* a recovery of any deployed split, since AMiner was never part of
  one) — keyed on `AnalysisComponentName`.
- Wazuh-native/Suricata model bars: **not** the deployed
  `models_v2/xgb_model.pkl` scored naively — the original claim that this
  pickle was version-mismatched and unusable was re-tested in REV-C Task
  4 and found to be a **scaling bug**, not a version mismatch: scored
  through its own `scaler_v2.pkl`/`imputer_v2.pkl` it reproduces F1=0.9945
  on the full eval split. This figure still uses the audit-time retrain
  (`exp4_ablation.py`'s "full" 26-feature variant — same hyperparameters,
  same raw features, threshold chosen by max-F1 on the eval split, 0.3798,
  not the deployed `theta_xgb`) because that is what `xdet_task1_results.json`
  already committed broken out by rule 86601 vs. Wazuh-native; the
  deployed pickle was not separately rescored per-subset for this figure.
- **AMiner model bar† (new, FIG9-M Task 2 — read before citing this
  number as comparable to the other two model bars):** AMiner alerts have
  no Wazuh 26-feature vector at all (native schema is
  `AnalysisComponentName`/`LogData`/`AMiner.ID`, structurally incompatible
  with `extract_features_v2` — this is why the original figure showed
  `n/a`, and that gap is structural, not a choice not to try). What is
  shown instead is a **deliberately identity-free** model on 5 non-identity
  fields: `raw_log_len`, `log_lines_count` (from `LogData`), and 3 causal
  per-source (`AMiner.ID`) temporal features (`alert_rate_1min`,
  `alerts_10min`, `time_since_last_alert`) computed the same
  forward-only, per-scenario-reset history discipline as the Wazuh
  pipeline's `AgentHistory`. `AnalysisComponentName`,
  `AnalysisComponentType`, `AnalysisComponentIdentifier`,
  `PersistenceFileName`, `Message`, and `AffectedLogAtomPaths/Values` were
  all deliberately excluded — every one of them directly or indirectly
  encodes which AMiner detector fired. Script:
  `newCol/fig9m_task2_aminer_model.py` (same audit-time `XGB_PARAMS` used
  throughout this response: `n_estimators=50, max_depth=5, subsample=0.5`).
  This model's F1 (0.9908) exceeds the AMiner lookup table's F1 (0.9773)
  by +0.0135 — feature importances show `alert_rate_1min` alone carries
  94.95% of the model's gain, so this is best read as evidence that
  per-source alert tempo, not signature identity, is AMiner's dominant
  signal in this split; see `newCol/fig9_metric_fix.md` Task 2 for the
  original caveat.
- **AMiner tempo feature, tested against Control C1 (FIG9-M-C1, resolves
  the caveat above — read this, not just the original caveat, before
  citing the AMiner model bar):** `newCol/fig9c1_task1_check.py` /
  `newCol/fig9c1_task1_results.json` re-parse the same raw
  `*_aminer.json` files and reuse `xdet_aminer_split.npz`'s exact
  `idx_test`/`y_all` to split the eval population's `alert_rate_1min`
  values by class. **Result: PASS.** Benign reaches the same value
  (20, the rolling-buffer cap) that 98.06% of attack rows occupy, in
  8.41% of benign rows (143/1,700) — not the zero-overlap pattern of this
  project's already-retracted FAIL cases (Linux-testbed benign for the
  analogous Wazuh feature never reached the cap, max 10/20), though
  thinner than AIT-ADS's own Wazuh-side analog (32.9% benign-at-cap,
  Fig 8). Separation is density-driven (98.06% vs. 8.41% at the shared
  cap), not range-driven. Full table, decision-rule application, and the
  time-window-labelling consistency note: `newCol/fig9_c1_check.md`.
- **Suricata restatement (FIG9-C1 Task 2)** and **Wazuh-native-vs-AMiner
  FPR contrast (FIG9-C1 Task 3):** both computed directly from
  `newCol/xdet_task1_results.json`'s existing confusion-matrix counts
  (`suricata.lookup.{tp,fp,tn,fn}`; `wazuh_native.lookup.fpr` vs.
  `aminer.lookup.fpr`) — no new computation, only a different framing of
  already-committed numbers. Full derivation: `newCol/fig9_c1_check.md`
  Tasks 2–3.

## Reproducing these figures

```
cd newCol/figures_ms
python3 fig1_lookup_vs_model.py
python3 fig2_feature_composition.py
python3 fig3a_ablation_separability.py
python3 fig3b_31101_tier_study.py
python3 fig4_31101_score_overlap.py
python3 fig5_tempo_asymmetry.py
python3 fig6_benign_composition.py
python3 fig7_threshold_sweep_v5defer.py
python3 fig8_cap_censoring_cross_dataset.py
python3 fig9_cross_detector_lookup.py
```

Fig 9 additionally requires `newCol/xdet_task1_results.json` to exist,
which is produced by running `newCol/xdet_recover_wazuh_split.py`,
`newCol/xdet_build_aminer.py`, then `newCol/xdet_task1_lookup.py` (in
that order) from the project root first; and (FIG9-M revision)
`newCol/fig9m_task1_results.json` and
`newCol/fig9m_task2_aminer_model_results.json`, produced by running
`newCol/fig9m_task1_baselines.py` then `newCol/fig9m_task2_aminer_model.py`
from the project root, after the files above exist.

Each script prints every source path and every derived value to stdout
before writing its `.pdf`/`.png` pair — the printed log is a fuller,
line-by-line duplicate of the tables above.
