# Manuscript figure captions — Figs 1–3

Per FIG RULE 4, none of these figures presents F1=0.8702, v8 F1=0.80, an
entity-window positive result, or a pre-fresh-collection FPR as current.
Fig 3 cites the entity-window 1,519× ratio explicitly as a **reference
figure with its own separate provenance and caveats** (Phase 3 §3b), not
as this figure's result.

---

## Fig 1 — `fig1_lookup_vs_model`

**What is plotted:** F1 of the full 26-feature XGBoost model vs. a
majority-label-per-rule-ID lookup table, both measured on the same
AIT-ADS eval split (`models_v2/ait_split.npz`). Gap = +0.0003.

**Source:** `results/rule_memorization_audit/exp3_lookup_results.csv`
(lookup F1 = 0.9942) and `exp4_ablation_main.csv`, variant=`full`
(XGBoost F1 = 0.9945). See `sources.md` for the exact fields.

**Caveats (required, do not drop on edit):**
- **Metric scope narrowed from the original brief.** The brief asked for
  grouped precision/recall/F1 bars. Only F1 is a committed number for
  *both* sides — `exp3_lookup_results.csv` records lookup-table F1 only
  (no precision/recall column, and no captured log of the underlying
  script's `classification_report` exists anywhere in the repository).
  Per the no-fabrication rule this figure was narrowed to the one metric
  actually available for both series, rather than reconstructing the
  missing ones.
- **The XGBoost bar is not the deployed production model.** The
  audit's own attempt to score the deployed pickle
  (`models_v2/xgb_model.pkl`) for this comparison produced a degenerate
  F1 = 0.0000 (`exp3_lookup_results.csv`'s own "XGBoost F1 (published)"
  field) — traced to an XGBoost model-serialization version mismatch on
  load (confirmed directly: loading the pkl in this environment,
  xgboost 3.3.0, raises a version-mismatch warning). That number is not
  plotted. The XGBoost F1 shown instead comes from `exp4_ablation_main.csv`'s
  `full` variant: same 26 features, same eval split, but it is an
  **audit-time retrain**, and its threshold was selected by maximizing
  F1 directly on this same eval split — not the deployed
  `theta_xgb=0.07538`. State this if the figure is used to claim
  anything about deployed-model performance specifically.
- The lookup table's F1 is a **ceiling-adjacent, not a floor**: 31101 is
  100% attack in both train and test folds of this split
  (`exp3_lookup_results.csv`), so the lookup table's near-parity with
  the full model illustrates rule-ID memorization risk, not that the
  full model adds nothing — see Fig 2/3 for the mechanism.

---

## Fig 2 — `fig2_feature_composition`

**What is plotted:** the 26-feature AIT-ADS pipeline's feature set,
**Revision note (TEMPO-AIT Task 4):** originally a two-panel chart
(feature-count share vs. gain share, both split into three buckets).
Both panels were orange-dominated and read as the same fact stated
twice, so it was replaced with the one comparison that actually carries
the point: a single horizontal bar, `is_web_attack` alone vs. every
other feature combined.

**What is plotted:** `is_web_attack` (94.99% of XGBoost split gain,
shown rounded to 95.0%) vs. the other 25 features of the 26-feature
AIT-ADS pipeline combined (5.01%).

**Source:** `results/rule_memorization_audit/exp2_importance_gain.csv`
(gain_pct per feature, summed for "other 25 features"); bucket
assignment for the caption note below cross-checked identical to
`exp1_feature_classification.csv` for all 26 features before use.

**Caveats:**
- `is_web_attack` is a RULE-CORRELATED feature (rule-definition
  metadata — rule groups / description phrases — not an independent
  observation of the event payload); in effect a rule-type indicator
  (see `exp1_feature_classification.csv`'s own justification text for
  this feature).
- **Feature-count breakdown (moved here from the former second panel,
  not separately plotted; corrected per FIG-C Task 2 — see
  `feature_classification_correction.md`):** of the 26 features, 3 are
  RULE-IDENTITY, **21 are RULE-CORRELATED, 2 are BEHAVIORAL**
  (`exp1_feature_classification.csv`, with `time_since_last_high`
  reclassified from BEHAVIORAL to RULE-CORRELATED — its mechanism is
  proximity to a rule-**severity** event, the same category of signal
  as `high_sev_ratio_20`/`rule_diversity_10min`, both already
  RULE-CORRELATED in the original file). `is_web_attack` is one of the
  21 RULE-CORRELATED features and individually accounts for essentially
  all of that bucket's combined gain share. This bucket relabeling does
  **not** change this figure's plotted bar or its 95.0%/5.0% values —
  that split is by individual feature (`is_web_attack` vs. every other
  feature), not by bucket; checked directly, not assumed (see
  `feature_classification_correction.md`, final section).

---

## Fig 3a — `fig3a_ablation_separability`

**Revision note:** this and Fig 3b were originally drafted as a single
combined figure (`fig3_two_level_identity`) under the title "the same
identity-only result shape recurring at two levels." That framing
directly contradicted its own left panel (identity removal changed
nothing) and was split into two figures with independent, honest claims
on review, before any deliverable was finalized.

**What is plotted:** the 26-feature AIT-ADS pipeline's rule-identity
ablation (`results/rule_memorization_audit/exp4_ablation_main.csv`) —
recall and FPR for `full` (26 features), `no_identity` (23 features, the
3 RULE-IDENTITY features removed), and `behav_only` (3 BEHAVIORAL
features only) — left panel; and, right panel, evidence for what
actually explains `behav_only`'s near-full performance: two unfitted
single-feature threshold rules computed directly from
`models_v2/ait_split.npz`.

**Revision note 2 (TEMPO-AIT check):** the right panel was originally
titled "behav_only's separation is largely a capture-tempo artifact."
`newCol/figures_ms/tempo_ait_check.md` tested that claim directly — the
same asymmetry test that made the project's own 135× Linux finding an
artifact (benign never approaches attack density) — and returned a
**mixed** result, not a clean confirmation. The title was corrected to
the factual, already-proven claim the bars actually support: *"Unfitted
single-feature rate thresholds separate AIT-ADS without training."* Do
not restore the "capture-tempo artifact" title without re-reading
`tempo_ait_check.md` Task 3 first.

**Revision note 3 (FIG-C Task 1):** the left panel was originally titled
"Three unrelated feature subsets each separate AIT-ADS." That framing is
contradicted by the evidence already in this figure and in Fig 2:
`is_web_attack` (driving `full`/`no_identity`) is rule-group/description
metadata; the 3 RULE-IDENTITY features are rule identity directly; and
`time_since_last_high` (the dominant BEHAVIORAL contributor, right
panel) measures proximity to a rule-**severity** event, and `rule_level`
itself is RULE-IDENTITY. None of the three routes to separability is an
independent, unrelated shortcut — all three are rule-definition metadata
in different forms. Retitled to *"Every subset that separates AIT-ADS
carries rule-definition metadata."* Full reasoning and the corrected
feature taxonomy behind this: `feature_classification_correction.md`.
Do not restore "unrelated" without re-reading that file first.

**Caveats (required, do not drop on edit):**
- **No true identity-only ablation exists.** RULE-IDENTITY has only 3
  features and no committed run isolates them alone; the left panel's
  three bars are exactly what was run (`full`, `no_identity`,
  `behav_only`), not a clean identity-vs-behavioural split.
- **`no_identity` is *identical* to `full`** (F1 0.9945, recall 0.9891,
  FPR 0.0000, both, to 4 decimal places) — removing the 3 rule-identity
  features changed nothing on this eval, because the dominant carrier is
  `is_web_attack`, a RULE-CORRELATED feature (Fig 2), not a
  RULE-IDENTITY one. Do not caption this panel as "identity features are
  necessary" — the data says the opposite for this specific ablation.
- **`behav_only`'s near-full performance (recall 0.9886, FPR 0.0187) has
  two distinct, unequal mechanisms behind it — not one "capture-tempo"
  cause** (full detail: `tempo_ait_check.md`):
  - `alert_rate_1min`: a **partial, coarse** tempo signal. 99.3% of
    attack rows saturate at the feature's cap (20) vs. 32.9% of benign
    — but benign *also* reaches that same cap in a third of rows,
    unlike the Linux testbed's benign, which never approached attack
    density at all (Phase 2: 0.1% of peak). The cap itself is a hard
    structural ceiling (`AgentHistory`'s 20-alert rolling buffer,
    `shared_features.py`) that undercounts true rate for both classes
    once saturated. Only 0.307% of the full model's gain
    (`exp2_importance_gain.csv`) — not doing much real work even in the
    trained model.
  - `time_since_last_high`: a much sharper asymmetry (80.4% of attack
    rows = 0 vs. 1.0% of benign), and carries most of BEHAVIORAL's gain
    (2.815%). But its mechanism is proximity to a **rule-severity**
    event (level≥10), not raw volume — `rule_level` itself is
    classified RULE-IDENTITY (`exp1_feature_classification.csv`), so
    this feature sits closer to a rule-derived signal than a pure
    capture-tempo one; `exp1`'s own justification already flagged it as
    "borderline."
  - Both threshold *values* (20, 0) were confirmed against
    `shared_features.py` to be structural/natural boundaries in the
    feature-engineering code (buffer size; elapsed-time floor), not
    values selected by inspecting eval-split performance — the
    "unfitted" label for the **rules** is accurate; what was corrected
    is the causal claim about *why* they separate.
- **Per FIG-C Task 1/2, these are not "mostly-unrelated shortcuts" — they
  are the same shortcut (rule-definition metadata) taking three forms.**
  `is_web_attack` (driving `full`/`no_identity`) is rule-group/description
  metadata; the 3 RULE-IDENTITY features are rule identity directly;
  `time_since_last_high` is proximity to a rule-severity event and has
  been reclassified RULE-CORRELATED, not BEHAVIORAL
  (`feature_classification_correction.md`). After that correction, the
  genuinely BEHAVIORAL bucket is just `alert_rate_1min` and
  `unique_src_ip_10min`, carrying **0.92%** of the full model's gain
  combined — not 3.7%. The correct reading is that AIT-ADS is separable
  almost entirely by rule-definition metadata (99.08% of gain,
  RULE-IDENTITY + corrected RULE-CORRELATED combined), not by
  generalizable learned behavior.

---

## Fig 3b — `fig3b_31101_tier_study`

**What is plotted:** the raw-HTTP tier study on rule 31101
(`newCol/fr_31101_report.md` Task 3 table) — recall and FPR for Tier A
(identity: exact User-Agent string) and Tier B (structural: path
depth/length/entropy/extension-class/etc.), against the trivial "always
predict attack" baseline (dashed line, FPR=1.00). Each bar's raw
numerator/denominator is printed directly on the bar (e.g. Tier B's FPR
is labeled "0.6667 (28/42)") since the benign denominator is small
enough (n=42) that a bare percentage would understate how few alerts
it's computed from. This is an independent check, on a different data
representation (raw per-alert HTTP fields for one specific rule) than
Fig 3a's 26-feature AIT-ADS ablation — the two are not the same claim
and are not paired in one figure. Legend is figure-level (above the
title), not inside the plot area, so it never sits on top of a bar.

**Caveats (required, do not drop on edit):**
- **Tier A's perfect separation is defeated by one HTTP header.** It is
  carried 100% by the exact User-Agent string
  (`newCol/fr_31101_report.md`, Task 3) and is trivially evadable by an
  attacker setting `User-Agent: curl/8.5.0`.
- **Tier B's result rests on a 3-endpoint benign baseline.** The 66.67%
  FPR is not a validated structural signal: the nominal top-ranked
  feature does not survive a causal swap-to-benign-typical test (recall
  unchanged), and the real, small effect traces to `path_depth`
  correctly catching exactly one of the three benign endpoints
  (`/api/status`) while missing the other two entirely
  (`newCol/fr_31101_report.md` §3a–3c). This would not necessarily
  survive contact with a benign population that used more than 3 fixed
  paths — untested, and per this project's no-further-collection rule,
  untestable with the collected data.
- **Both rule-31101 populations are tool-generated.** Attack-side
  traffic is `dirb` (spoofed MSIE User-Agent); benign-side is bare
  `curl/8.5.0` polling 3 fixed endpoints. Neither is organic human
  browsing (`newCol/ew_phase3_31101_case_study.md` §3e).
- **Tier C (aggregate features, e.g. `distinct_url_count`) is not
  plotted as a recall/FPR bar** and should not be read as a third tier
  result comparable to A/B. It was not evaluated as a per-alert
  classifier in the FR-31101 check (a single alert cannot have a
  "distinct path count" — that quantity requires aggregating multiple
  alerts). The 1,519× figure (formerly an in-figure footnote, moved to
  this caveat and to the LaTeX caption below per FIG-C Task 4) is Phase
  3 §3b's
  entity-window separation, recomputed here directly from
  `newCol/ew_phase3_31101_per_alert_combined.csv` and confirmed to match
  §3b's printed value exactly; it carries its own, separate caveat
  (Phase 3 §3d/§2e: the Linux benign collection never approaches the
  attack round's peak density, so this magnitude of separation is not
  established to hold in a busier benign environment).

---

## Fig 4 — `fig4_31101_score_overlap`

**Revision note (FIG-D F3):** retitled from "attack and benign OC-SVM
scores overlap heavily at the per-alert level" to state the sharper,
already-computed finding directly: at the deployed threshold, FPR
(4.78%) exceeds recall (2.25%), so the novelty layer flags benign
rule-31101 alerts *more* often than attack. FPR exceeding recall places
this specific operating point at or below the chance diagonal — this is
below-chance discrimination, not merely overlap. The existing
threshold-pointing annotation is unchanged; only the panel title and
docstring were rewritten. Verified in-script: `assert fpr_l2 > recall_l2`.

**What is plotted:** per-alert OC-SVM anomaly score density for rule
31101, attack (n=20,665) vs. benign (n=209), both classes drawn from the
same evaluation population as `eval_set_definition.md`'s per-rule table.
The deployed operating threshold (θ_ocsvm = -0.3350,
`models_v2/thresholds_production_v3.json`) is shown as a vertical
reference line. This is the **left panel only** of the pre-existing
`newCol/ew_fig_31101_before_after.png`; the right panel there (entity-
window aggregation) is a retracted positive result and is not reproduced
in any form here, per FIG RULE 4.

**Source:** `newCol/ew_phase3_31101_per_alert_combined.csv` (`ocsvm_score`,
`label`); `models_v2/thresholds_production_v3.json` (`theta_ocsvm`).
Decision direction (flagged-as-attack iff `ocsvm_score >= theta_ocsvm`)
confirmed directly against `combined_decision_v3.py`'s own documented
convention ("anomaly score = -decision_function, higher = more
anomalous"), and cross-checked numerically: applying this rule to the
plotted data reproduces `eval_set_definition.md`'s rule-31101 row (L2
recall 2.25%, L2 FPR 4.78%) to two decimal places (script computes
2.25%/4.78% directly).

**Caveats (required, do not drop on edit):**
- This is a **mechanism/undecidability demonstration**, not a novel
  result — `figure_inventory.md` already flags the source figure as
  "current, publication-quality as-is." What is new here is only the
  replot in this manuscript's shared style, left-panel-only.
- **Both populations are tool-generated HTTP traffic**, not organic
  browsing (`dirb` with a spoofed User-Agent for attack; bare `curl`
  polling fixed endpoints for benign) — the same caveat already carried
  by Fig 3b for the same underlying rule.
- The heavy overlap shown here (both classes' score mass concentrated
  near -2.3), combined with benign carrying more relative density into
  the tail past the threshold than attack, is exactly what produces the
  below-chance operating point (2.25% recall vs. 4.78% FPR) — this
  figure should be read as explaining *why* aggregation (entity-windows)
  was explored for this rule, not as a result in its own right.

## Fig 5 — `fig5_tempo_asymmetry`

**Revision note (FIG-D F1):** an earlier draft computed span from the raw
Wazuh alert `timestamp` field directly (`collection_*.csv`), giving
136.2×/1.5× — close to, but not exactly, the frozen 135.2×/1.5× used
throughout `eval_set_definition.md` and the drafted abstract. Root-caused:
raw `timestamp` is ingestion time, which lags the true event by a
variable 18.2s-80.4s; `eval_set_definition.md`'s canonical figure uses
this project's own corrected `event_time_utc`-preferring `ts` field
instead. This script now uses `ts` and reproduces 135.2×/1.5× exactly.
Full reconciliation: `eval_set_definition.md` EW block v4,
`fig_followups.md` F1. Do not revert to the raw `timestamp` field.

**What is plotted:** mean alert rate (alerts/s) for the attack round vs.
the benign round of each platform's fresh collection, Linux and Windows
side by side, with each panel's attack:benign ratio annotated in its
title (Linux 135.2×, Windows 1.5× — matching `eval_set_definition.md`
Task 1c's frozen table exactly). Note the two panels use different
y-axis scales (Linux's rates are roughly two orders of magnitude larger
than Windows's); this is necessary to show each platform's own
within-round contrast and is not a way of concealing the cross-platform
difference, which is already the point of comparing the ratio
annotations, not the raw axis heights.

**Source:** `newCol/ew_features/ew_augmented_per_alert.csv` (`source`,
`ts` columns) — mean rate = row count ÷ (max(`ts`) − min(`ts`)) per
`source` group. `ts` is the corrected event-time field (see revision
note above); descriptive statistics only, no new experiment.

**Caveats (required, do not drop on edit):**
- This figure **restates**, rather than newly establishes, the tempo
  asymmetry already on record in `eval_set_definition.md` (Task 1c) and
  `ew_carrier_classification.md` — its purpose here is to make that
  asymmetry, and its absence on Windows, visible as a figure rather than
  a table row only.
- **This is the mechanism behind every retracted Linux rate/volume EW
  finding** (Phase 3's `alert_count`, Phase 4's `max_rate_10s`, and the
  55.2% rate-shaped carrier bucket) — but per FIG-C Task 3, this project
  also directly tested whether the v5 pipeline's own capped
  `alert_rate_1min` feature (distinct from the EW rate features shown as
  contaminated here) is symmetrically censored by this asymmetry, and
  found it is **not** (Linux benign never approaches the cap; see
  `fig_corrections.md` Task 3). This figure should not be read as
  implying every rate-derived feature on this pipeline is equally
  affected — the mechanism is real, but its *consequence* is
  feature-specific.
- Windows's 1.5× ratio is not zero; a small residual asymmetry exists but
  is far below the magnitude that made Linux's rate/volume EW features
  uninterpretable, and does not by itself explain any known finding.

## Fig 6 — `fig6_benign_composition`

**Revision note (FIG-D F4):** axis labels now carry a short
`rule.description` beside each rule ID (source: the raw collection
CSVs' own `description` field, first occurrence per rule_id, truncated
to ~28 characters) — bare rule numbers were uninterpretable to a reader.
Added the cross-panel reading below as a caveat.

**What is plotted:** the top-5 `rule_id`s (by share), each labeled with
its rule description, in each platform's fresh benign collection, plus
an "all other rules" bar. Linux benign is 78.3% rule 31101 ("Web server
400 error code") alone; Windows benign is 38.8% rule 92004 (PowerShell
process-spawn) + 28.9% rule 60106 (logon success), reproducing
`figure_inventory.md`'s own citation of these two Windows values exactly.

**Source:** `newCol/ew_features/ew_augmented_per_alert.csv` (`source`,
`rule_id`), grouped by `source` ∈ {`lnx_benign`, `win_benign`}; rule
descriptions from the four raw `collection_*.csv` files' own
`description` column.

**Caveats (required, do not drop on edit):**
- **Combined reading across the Linux panel (FIG-D F4):** rule 31101's
  78.3% share is bare `curl/8.5.0` polling three fixed endpoints (Fig 3b's
  caveat), each 400-error hit firing this rule; the file-integrity
  remainder (rule 550, 2.2%, plus small 553/554 contributions elsewhere
  in this study) is CUPS's own periodic subscription-lease file rewrite
  (`/etc/cups/subscriptions.conf` and its shadow copies), not human file
  activity (`art_contamination_check.md`, `pre_ms_number_fixes.md` FIX
  1/2). Stated together: **the Linux benign corpus is machine-generated
  daemon traffic almost end to end, not human activity** — the concrete,
  visible form of this study's benign-realism limitation, not a new
  finding but the clearest place to see it.
- **This figure is the data behind a caveat already used elsewhere in
  this document, not a new finding.** It grounds the population-mismatch
  defect (A3/A4-style, `ew_carrier_classification.md`) that explains why
  several rules in this study have no measurable benign-side FPR at all,
  and why the retracted v8 F1=0.80 headline's 14.9% FPR is not a
  false-positive rate on the T1110.001 brute-force rule family it is
  nominally scoring — confirmed directly here: rules 60122/60204 (the
  rules that headline was evaluated against) have **zero** representation
  in `win_benign` (checked, not assumed — the script asserts this).
- Linux benign's dominant rule (31101, 78.3%) is the **same rule** whose
  per-alert undecidability is shown in Fig 4 and whose memorization risk
  is discussed in Figs 1/2 — this is not a coincidence highlighted by the
  figure itself, but worth noting when reading Figs 1, 2, 4, and 6
  together: a large share of this project's Linux benign evidence for
  rule 31101 specifically is what Fig 4's benign-side histogram mass is
  built from.
- Neither collection is large (Linux n=267, Windows n=201); the "all
  other rules" aggregate bar in each panel should not be over-interpreted
  as a stable estimate of a long tail — it is what remains after the
  named top-5, no more precise than that.

## Fig 7 — `fig7_threshold_sweep_v5defer`

**Revision note (FIG-D F2):** Panel A's title now states its exact
configuration (v5+defer combined decision, known attacks blended) and the
figure carries an inline annotation decomposing its 9.1% recall, because
this project has three same-sounding "known-attack recall" numbers with
no distinguishing label otherwise: 99.96% (rule 31101's raw L1 recall,
no defer applied — `eval_set_definition.md` block v1), ~2% (rule 31101's
deployed v5+defer recall, equal to its L2-only recall since defer
suppresses L1 for this rule — same table), and this panel's 9.1% (the
v5+defer combined decision's recall on the *blended* 31101+31151
population). These are three different scopes/configurations, not three
measurements of the same thing, and the 9.1% must not be read as
contradicting the ~2% figure.

**What is plotted:** recall and FPR vs. threshold for the deployed
v5+defer production config. Panel A sweeps θ_xgb (L1) against known
attacks (rules 31101/31151) and the whole fresh Linux benign collection,
with θ_ocsvm held fixed at the deployed value. Panel B sweeps θ_ocsvm (L2)
against novel attacks and the same benign collection, with θ_xgb held
fixed. Both panels mark the deployed operating threshold as a vertical
reference line.

**Source:** `newCol/threshold_sweep.csv` (pre-committed sweep output,
columns `panel`/`threshold`/`tp`/`fn`/`fp`/`tn`) — replotted only, the
sweep itself is not rerun. Deployed thresholds from
`models_v2/thresholds_production_v3.json`. Config identity (L1 =
`models_v2/xgb_model.pkl`, L2 = `ocsvm_nu05.pkl` v5, defer =
`rule_confound_fixes_v5.json`) per the original producing script,
`newCol/fnr_tp_threshold_v5defer.py`'s own docstring.

**Caveats (required, do not drop on edit):**
- **Panel A's recall is flat by construction; its FPR is not — checked
  directly, not assumed from the producing script's own docstring.**
  TP=2026/FN=20224 for every one of the 400 swept θ_xgb values (confirmed
  in-script, `threshold_sweep.csv`), because both known-attack rules are
  wholly deferred to L2 regardless of θ_xgb. But Panel A's benign side is
  the *entire* fresh Linux benign collection (`fnr_tp_threshold_v5defer.py`:
  `benign = Xb.copy()`), not restricted to rule-31101 benign rows; per
  Fig 6, only ~78% of that collection is rule 31101 (rule 31151 has zero
  benign representation), so the remaining ~22% (rules 5501/5502/5402/550,
  etc.) are **not** deferred and their L1 vote still moves with θ_xgb —
  FP ranges from 18 to 47 of 267 benign rows (6.7%-17.6%) across the
  sweep. The producing script's own docstring describes only the
  attack-side invariance; describing the whole panel as "flat" would
  overstate what the data shows.
- **The flat 9.1% is a volume-weighted blend of two very different
  per-rule recalls, not a fourth mechanism.** Rule 31101 (n=20,665) has
  L2 recall 2.25%; rule 31151 (n=1,585) has L2 recall 98.49%
  (`eval_set_definition.md` block v2). $20{,}665 \times 2.25\% + 1{,}585
  \times 98.49\% = 465 + 1{,}561 = 2{,}026$, exactly matching Panel A's
  TP. A specific alternative hypothesis — that 31151's L1 vote escapes
  defer while 31101's does not — was checked directly against the
  production models and is **false**: both rules are 100% deferred
  (`agent_criticality==1.0` for all 22,250 known-attack rows; both
  rule_ids in the defer set). The blend is driven by heterogeneous L2
  recall across the two rules plus their 13:1 volume imbalance, not by
  any L1 vote surviving for either rule. Full verification: `fig_followups.md` F2.
- Panel B's genuine trade-off (recall 23.9%-100%, FPR 4.5%-100%) spans a
  much wider raw threshold range (-2.5 to 27.3) than Panel A (0 to 1) —
  the two x-axes are not on comparable scales and are not meant to be
  read against each other directly; each panel's own deployed-threshold
  marker is the only cross-reference point that matters.
- This figure evaluates the same fresh Linux benign collection used
  throughout this project's post-fresh-collection work (n=267) — it
  carries the same small-benign-sample caveat as every other FPR number
  in this document, not a new one specific to this figure.

## Fig 8 — `fig8_cap_censoring_cross_dataset`

**What is plotted:** the benign-side distribution of `alert_rate_1min`
for two datasets, AIT-ADS (n=882,739) and the Linux testbed (n=267),
with the feature's hard cap (20, `AgentHistory(maxlen=20)`,
`shared_features.py:157`) marked as a vertical reference line on both
panels. Same unfitted rule (`alert_rate_1min >= 20`) applied identically
to both: AIT-ADS benign reaches the cap in 32.9% of rows (rule FPR
0.3291); Linux testbed benign never reaches it at all (max observed
value 10 of 20; rule FPR 0.0000).

**Chosen as a standalone figure, not a third panel on Fig 5 (stated per
FIG-D F5's instruction to state and justify the choice):** Fig 5 plots a
single scalar (mean alerts/s) per collection round, using the
event-time-corrected `ts` field, across four bars; this figure plots a
full per-alert distribution of one specific capped feature, using the
raw-timestamp field production actually sees, for the benign class only,
across two datasets. Combining them would force two different x-axis
quantities and two different timestamp conventions onto one plot.

**Source:** `models_v2/ait_split.npz` (AIT-ADS benign rows, `y==0`,
`alert_rate_1min` column) and `newCol/collection_benign_lnx_alerts.csv`
(Linux testbed benign round), the latter's `alert_rate_1min` recomputed
alert-by-alert using the exact `AgentHistory` logic from
`shared_features.py` on the raw `timestamp` field — the same computation
`fig_corrections.md` Task 3 already performed and summarized as two
scalars (0% at cap, max 10); this figure replots that full distribution
rather than just its summary statistics, plus an equivalent computation
for the AIT-ADS side (previously summarized in Fig 3a's right panel and
`tempo_ait_check.md`).

**Caveats (required, do not drop on edit):**
- **This is the paper's methodological contribution made visible, not a
  new empirical claim.** Every number plotted here is already established
  elsewhere (`tempo_ait_check.md` for AIT-ADS, `fig_corrections.md` Task
  3 for Linux) — what is new is showing both full distributions side by
  side so the *mechanism* of the artifact-vs-signal distinction (where
  the benign mass sits relative to the cap) is visible directly, not only
  as two summary percentages.
- AIT-ADS's benign distribution is not simply "at the cap or not" — it
  has real internal structure (a secondary mode around 6-8) below the
  cap, consistent with `tempo_ait_check.md`'s characterization of this as
  a partial, coarse signal rather than pure noise.
- The two panels have very different sample sizes (882,739 vs. 267) and
  are shown as percentage shares specifically so their shapes are
  comparable despite that; this figure does not claim the two benign
  populations are otherwise similar in any other respect.

---

## Fig 9 — `fig9_cross_detector_lookup`

**Revision note (FIG9-M Tasks 1–2):** the original figure plotted recall
only. A trivial always-predict-attack classifier scores recall $=1.000$
on every detector regardless of base rate, so recall alone cannot
distinguish signature-identity memorization from class imbalance — the
same trivial-baseline problem Fig 3b already handles correctly for rule
31101. Rebuilt on F1, with each detector's own trivial always-attack
baseline drawn as a third bar per group (base rates differ too sharply
for one shared reference line: 74.7% Wazuh-native, 1.9% Suricata, 84.7%
AMiner). The AMiner model bar, `n/a` in the original figure, is now a
deliberately identity-free 5-feature model (marked † — see below); this
was a structural gap (no Wazuh-style feature vector exists for AMiner
alerts), not a choice not to attempt one.

**What is plotted:** per-detector F1 (Wazuh-native, Suricata embedded in
Wazuh rule 86601, AMiner) for three series, all on the same eval split
per detector: a majority-label-per-signature lookup table; a model
(Wazuh-native/Suricata: audit-time 26-feature XGBoost retrain,
`exp4_ablation.py`-style, same as Fig 1; AMiner†: a 5-feature model with
**no signature-identity input at all**); and a trivial always-predict-
attack baseline computed on the identical population as its detector's
other two bars. $n$ (eval split) and base rate per detector: Wazuh-native
$n=458{,}517$, 74.7% attack; Suricata $n=61{,}536$, 1.9% attack; AMiner
$n=11{,}112$, 84.7% attack.

**Source:** `newCol/fig9m_task1_results.json` (lookup/model/trivial F1
for Wazuh-native and Suricata, and the trivial row for AMiner),
`newCol/fig9m_task2_aminer_model_results.json` (AMiner's non-identity
model†), `newCol/xdet_task1_results.json` ($n$/base-rate annotations and
the underlying lookup tables). Full derivation and the per-detector
"does the lookup table beat the trivial baseline" verdict:
`newCol/fig9_metric_fix.md`.

**Caveats (required, do not drop on edit):**
- **The lookup table beats its trivial baseline on every detector, but by
  very different margins.** Wazuh-native: F1 0.996 vs. 0.855 ($+0.141$) —
  a large, unambiguous margin. AMiner: F1 0.977 vs. 0.917 ($+0.060$) —
  real but much smaller; recall alone (the original figure's metric) was
  actually *below* the trivial baseline's recall of 1.000 here, which is
  exactly why F1 (which also credits the trivial baseline's poor
  precision) is the metric that must be used.
- **Suricata's F1 comparison (0.054 vs. 0.038 trivial, revised
  FIG9-C1):** stated as an F1 gap this reads as a marginal win over a
  near-meaningless reference point at a 1.93% base rate. The honest
  statement is in raw counts: the lookup table flags only 33 of 61,536
  eval-split alerts (0.05%) and is correct on all 33 (precision 1.0000),
  but this covers a negligible share of Suricata's volume — only 5 of its
  29 signatures are attack-majority, accounting for ~0.07% of all
  Suricata alerts dataset-wide (`newCol/lbl_provenance.md` Task 1b). The
  correct claim is the **absence of an exploitable identity shortcut** at
  any meaningful scale for this detector, not a small F1 edge — precision
  is perfect here only because almost nothing is ever flagged.
- **Wazuh-native vs. AMiner lookup FPR, stated directly (FIG9-C1 Task
  3):** 0.0005 vs. 0.2212 — a ~435$\times$ gap, two qualitatively
  different mechanisms rather than one finding at two strengths. On
  Wazuh-native, signature identity is close to deterministic for the
  label; on AMiner it is a weak prior riding on an already-high (84.7%)
  base rate, good enough to beat a trivial baseline on F1 but not to
  avoid flagging roughly one in five actual benign alerts.
- **The AMiner model bar (†) is not constructed the same way as the other
  two model bars and must not be read as a like-for-like comparison.**
  Wazuh-native/Suricata's model bars include rule/signature-identity
  features (`rule_id_encoded`, `desc_len`, `rule_level`) alongside
  behavioral ones. AMiner's does not — no Wazuh-style feature vector
  exists for AMiner's native schema
  (`AnalysisComponentName`/`LogData`/`AMiner.ID`), so a comparable
  identity-inclusive model cannot be built without inventing features.
  What is shown is deliberately identity-free: `raw_log_len`,
  `log_lines_count`, and 3 causal per-source temporal features
  (`alert_rate_1min`, `alerts_10min`, `time_since_last_alert`).
  `AnalysisComponentName` and every other field that names or implies
  which AMiner detector fired were excluded by design.
- **AMiner's non-identity model (F1 0.991) exceeds its own lookup table
  (F1 0.977) by +0.014 — signature identity is not AMiner's strongest
  available signal.** Feature importance is concentrated almost entirely
  in `alert_rate_1min` (94.95% of gain): per-source alert tempo, not
  signature identity, drives most of this detector's separability. This
  is the same feature shape (94.95% gain concentration) that produced
  retracted results elsewhere in this project, so it was tested rather
  than assumed real: **Control C1, applied directly (FIG9-C1 Task 1),
  PASSES.** Benign `alert_rate_1min` reaches the identical value (20, a
  20-alert rolling-buffer cap) that 98.06% of attack rows occupy, in
  8.41% of benign rows (143 of 1,700) — not a rare outlier brushing the
  edge of attack's range, but repeated overlap at the shared maximum.
  This is not the pattern of this project's already-retracted FAIL cases
  (the Linux-testbed benign analog for the same Wazuh feature never
  reached the cap at all, max observed 10 of 20). It is, however, a
  thinner overlap than AIT-ADS's own analogous Wazuh feature, where
  benign reaches the cap 32.9% of the time (Fig 8) — nearly 4$\times$
  AMiner's 8.41% here — so this is reported as a real but partial signal,
  separated from attack mainly by *density* at the shared cap (98.06% vs.
  8.41%) rather than by occupying a disjoint range. Full check:
  `newCol/fig9_c1_check.md`. A further, un-run caveat: AIT-ADS labels are
  time-window intervals (`newCol/lbl_provenance.md`), so this feature may
  partly encode proximity to a labelled window rather than a per-source
  behavioral signature specific to the attacked host — C1's pass is
  consistent with, and does not rule out, that mechanism.
- **Both audit-time model bars (Wazuh-native, Suricata) are not the
  deployed `models_v2/xgb_model.pkl`, but the reason has changed from
  earlier drafts of this project's figures.** The pickle is not actually
  version-mismatched or broken — that claim was re-tested and traced to a
  scaling bug in the scoring scripts that made it (raw unscaled features
  fed to a model trained on scaled ones); scored correctly, the deployed
  pickle reproduces F1$=0.9945$ on the full eval split. The audit retrain
  is used here only because it is what the underlying per-subset (86601
  vs. native) breakdown was already computed against.

---

## Ready-to-paste LaTeX blocks (FIG-C Task 4)

Per Task 4, all in-figure footnote/explanatory text has been removed
from the rendered PDF/PNG for Figs 3a and 3b (Figs 1 and 2 never had
baked-in footnote text — checked directly, nothing to remove) and moved
here as continuous prose. Every caveat bulleted above is preserved in
these blocks; nothing was dropped, only reformatted from bullets into
prose suitable for `\caption{}`. What remains rendered inside each
figure is limited to axis labels, tick labels, bar value annotations,
legends, short panel titles, and the inline pointer annotations/dashed-
baseline label that identify a specific bar or line — none of that is
caption prose.

Figs 4-7 (Task 5) were built with captions externalized from the start,
per the same rule — none of their scripts contains a `fig.text()`
footnote block; every caveat lives only in the prose below.

### Fig 1 — `fig1_lookup_vs_model`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig1_lookup_vs_model.pdf}
  \caption{F1 of the full 26-feature XGBoost model versus a
  majority-label-per-rule-ID lookup table, both measured on the same
  AIT-ADS evaluation split (gap $=+0.0003$). Only F1 is shown because it
  is the sole metric committed for both series; precision and recall for
  the lookup-table baseline are not available in any committed artifact
  and were not reconstructed. The XGBoost bar is not the deployed
  production model: scoring the deployed pickle for this comparison
  produced a degenerate F1 of 0.0000, traced to an XGBoost
  model-serialization version mismatch on load; the value shown instead
  comes from an audit-time retrain on the same 26 features and the same
  evaluation split, with its decision threshold selected by maximizing F1
  on this same split, not the deployed operating threshold. The lookup
  table's near-parity with the full model should be read as evidence of
  rule-ID memorization risk, since rule 31101 is 100\% attack in both
  folds of this split, not as evidence that the full model adds nothing
  (see Figs.~2--3a for the mechanism).}
  \label{fig:1-lookup-vs-model}
\end{figure}
```

### Fig 2 — `fig2_feature_composition`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig2_feature_composition.pdf}
  \caption{Share of XGBoost split gain attributable to a single feature,
  \texttt{is\_web\_attack} (94.99\%, shown as 95.0\%), versus the sum of
  the other 25 features in the 26-feature AIT-ADS pipeline (5.01\%, shown
  as 5.0\%). \texttt{is\_web\_attack} is rule-definition metadata (rule
  groups and description phrases), not an independent observation of the
  event payload, and functions in effect as a rule-type indicator. Of the
  26 features, 3 are RULE-IDENTITY, 21 are RULE-CORRELATED, and 2 are
  BEHAVIORAL (\texttt{time\_since\_last\_high} reclassified from
  BEHAVIORAL to RULE-CORRELATED, since its mechanism is proximity to a
  rule-severity event rather than an independent behavioral signal).
  \texttt{is\_web\_attack} is one of the 21 RULE-CORRELATED features and
  individually accounts for essentially all of that bucket's combined
  gain share; this reclassification does not change the 95.0\%/5.0\%
  split plotted here, which is computed per individual feature rather
  than per bucket.}
  \label{fig:2-feature-composition}
\end{figure}
```

### Fig 3a — `fig3a_ablation_separability`

```latex
\begin{figure*}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig3a_ablation_separability.pdf}
  \caption{Left: recall and false-positive rate (FPR) of the 26-feature
  AIT-ADS pipeline under three ablation variants -- the full feature set,
  the set with the 3 RULE-IDENTITY features removed (\emph{no\_identity}),
  and the 3 nominally behavioral features alone (\emph{behav\_only}). No
  true identity-only ablation exists in the committed results; these
  three variants are exactly what was run, not a clean
  identity-versus-behavior split. \emph{no\_identity} is identical to
  \emph{full} to four decimal places, because the dominant carrier is
  \texttt{is\_web\_attack}, a RULE-CORRELATED feature (Fig.~2), not a
  RULE-IDENTITY one; this ablation should not be read as showing that
  identity features are necessary. \emph{behav\_only} nearly matches
  \emph{full} (recall 0.9886 vs.\ 0.9891, FPR 0.0187 vs.\ 0.0000). Right:
  two unfitted single-feature threshold rules, computed directly from the
  same evaluation split with no additional training, that explain most of
  \emph{behav\_only}'s performance. Both threshold values (the
  \texttt{alert\_rate\_1min} cap of 20 and the
  \texttt{time\_since\_last\_high} floor of 0) were confirmed against the
  feature-engineering source code to be structural, natural boundaries
  rather than values selected by inspecting evaluation performance.
  However, the mechanism behind each threshold's separation differs:
  \texttt{alert\_rate\_1min} is capped by a hard 20-alert rolling buffer,
  and 99.3\% of attack rows saturate this cap versus 32.9\% of benign
  rows -- unlike this project's Linux testbed, where benign traffic never
  approaches attack-level density, AIT-ADS benign traffic does reach the
  same cap in roughly a third of rows, making this a partial, coarse
  tempo signal rather than a clean capture-tempo artifact, and one that
  carries only 0.307\% of the full model's split gain.
  \texttt{time\_since\_last\_high} shows a sharper asymmetry (80.4\% of
  attack rows equal exactly zero versus 1.0\% of benign) and carries most
  of the behavioral bucket's gain (2.815\%), but its mechanism is
  proximity to a rule-severity event (\texttt{rule.level} $\geq$ 10)
  rather than raw alert volume; \texttt{rule\_level} itself is classified
  as rule-identity metadata, so this feature's separation is closer to a
  rule-derived signal than to a genuinely behavioral one. Taken together
  with Fig.~2, all three routes to separability shown across both panels
  -- a rule-type/content flag, rule identity directly, and rule-severity
  proximity -- are rule-definition metadata in different forms; only
  \texttt{alert\_rate\_1min} (0.307\% of gain) is a genuine, if partial,
  behavioral/tempo signal. AIT-ADS is therefore separable almost entirely
  by rule-definition metadata (99.08\% of split gain across the corrected
  RULE-IDENTITY and RULE-CORRELATED buckets combined), not by learned,
  generalizable behavior.}
  \label{fig:3a-ablation-separability}
\end{figure*}
```

### Fig 3b — `fig3b_31101_tier_study`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig3b_31101_tier_study.pdf}
  \caption{Recall and false-positive rate (FPR) of two raw-HTTP feature
  tiers for Wazuh rule 31101, evaluated on the held-out test split
  ($n=3{,}464$ attack / 42 benign), against a trivial ``always predict
  attack'' baseline (dashed line, FPR $=1.00$, F1 $=0.9940$). Tier A
  (identity: the exact User-Agent string) separates perfectly (recall
  1.0000, FPR 0.0000) but is carried entirely by one HTTP header and is
  trivially evadable by an attacker who sets a different User-Agent. Tier
  B (structural: path depth, length, entropy, extension class, and
  related properties) achieves the same recall but a substantially higher
  FPR of 0.6667 (28 of 42 benign alerts misclassified); this result rests
  on a 3-endpoint benign baseline, and the nominal top-ranked feature does
  not survive a causal swap-to-benign-typical test, with the real, small
  effect traced to \texttt{path\_depth} correctly flagging only one of the
  three benign endpoints. Both populations are tool-generated (\texttt{dirb}
  with a spoofed User-Agent for attack traffic; bare \texttt{curl} polling
  3 fixed endpoints for benign traffic), not organic browsing. A third
  tier, aggregate per-entity features such as \texttt{distinct\_url\_count},
  is not shown here as a recall/FPR bar because it was not evaluated as a
  per-alert classifier -- a single alert cannot have a distinct path
  count, which requires aggregating multiple alerts; for reference only,
  that aggregate feature shows a 1{,}519$\times$ median separation between
  attack and benign entities, a magnitude not established to hold in a
  busier benign environment than the one collected.}
  \label{fig:3b-31101-tier-study}
\end{figure}
```

### Fig 4 — `fig4_31101_score_overlap`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig4_31101_score_overlap.pdf}
  \caption{Per-alert OC-SVM anomaly score density for rule 31101, attack
  ($n=20{,}665$) versus benign ($n=209$), with the deployed operating
  threshold ($\theta_{ocsvm}=-0.3350$) shown as a vertical reference
  line. At this threshold the novelty layer flags 4.78\% of benign
  alerts but only 2.25\% of attack alerts -- FPR exceeding recall places
  this operating point at or below the chance diagonal, a stronger
  finding than mere score overlap, though the heavy overlap of both
  classes' score mass in the same narrow band is the underlying cause.
  This is the left panel only of an earlier combined figure; the paired
  right panel there aggregated the same alerts to entity-windows and is
  not reproduced in any form, since that result has since been
  retracted. This figure is a mechanism/undecidability demonstration
  rather than a novel result in its own right. Both populations are
  tool-generated HTTP traffic (\texttt{dirb} with a spoofed User-Agent
  for attack; bare \texttt{curl} polling fixed endpoints for benign),
  not organic browsing.}
  \label{fig:4-31101-score-overlap}
\end{figure}
```

### Fig 5 — `fig5_tempo_asymmetry`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig5_tempo_asymmetry.pdf}
  \caption{Mean alert rate (alerts/s) for the attack round versus the
  benign round of each platform's fresh collection. Linux shows a
  135.2$\times$ attack:benign ratio; Windows shows 1.5$\times$ (note the
  differing y-axis scales between panels, needed to show each platform's
  own within-round contrast). This asymmetry is the mechanism behind
  every retracted Linux rate/volume-shaped feature finding in this study
  and the reason this project's carrier-classification analysis treats
  Linux rate-shaped features as tempo-contaminated while Windows is not.
  It does not, however, apply uniformly to every rate-derived feature on
  this pipeline: a targeted check of the deployed model's own capped
  \texttt{alert\_rate\_1min} feature found Linux benign traffic never
  approaches the cap that Linux attack traffic saturates, meaning this
  particular feature's separation on Linux is not symmetrically erased by
  the asymmetry shown here, unlike the entity-window rate features it
  affected elsewhere. Windows's small residual 1.5$\times$ ratio does not
  by itself explain any finding in this study.}
  \label{fig:5-tempo-asymmetry}
\end{figure}
```

### Fig 6 — `fig6_benign_composition`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig6_benign_composition.pdf}
  \caption{Dominant rule-ID composition of each platform's fresh benign
  collection, each rule labeled with a short description. Linux benign is
  78.3\% rule 31101 (``web 400 error'') alone; Windows benign is
  38.8\% rule 92004 (PowerShell process-spawn) plus 28.9\% rule 60106
  (logon success). Rules 60122/60204 -- the T1110.001 brute-force rule
  family a previously reported, retracted headline result was nominally
  scored against -- have zero representation in the Windows benign
  collection, confirmed directly rather than assumed. This figure
  grounds the population-mismatch defect that recurs throughout this
  study: several rule families in this evaluation have no measurable
  benign-side false-positive rate at all, because their own rule ID is
  simply absent from the benign traffic collected for that platform.
  Read together, rule 31101's share is bare \texttt{curl} polling three
  fixed endpoints, and the Linux file-integrity remainder is a printing
  daemon's own periodic subscription-lease file rewrite, not human file
  activity -- the Linux benign corpus is machine-generated daemon
  traffic almost end to end, not human activity, which is this study's
  benign-realism limitation made concrete. Neither collection is large
  ($n=267$ Linux, $n=201$ Windows); the ``all other rules'' aggregate in
  each panel is what remains after the five named rule IDs and should
  not be read as a stable long-tail estimate.}
  \label{fig:6-benign-composition}
\end{figure}
```

### Fig 7 — `fig7_threshold_sweep_v5defer`

```latex
\begin{figure*}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig7_threshold_sweep_v5defer.pdf}
  \caption{Recall and false-positive rate (FPR) versus threshold for the
  deployed v5+defer production configuration. Panel A sweeps
  $\theta_{xgb}$ (L1) against known attacks (rules 31101/31151) and the
  entire fresh Linux benign collection, with $\theta_{ocsvm}$ held fixed
  at its deployed value; Panel B sweeps $\theta_{ocsvm}$ (L2) against
  novel attacks and the same benign collection, with $\theta_{xgb}$ held
  fixed. Both panels mark the deployed operating threshold as a vertical
  reference line. Panel A's recall is flat by construction (TP=2026,
  FN=20224 across all 400 swept values), since both known-attack rules
  are wholly deferred to L2 regardless of $\theta_{xgb}$; its FPR,
  however, is not flat (ranging from 6.7\% to 17.6\%), because the
  benign side scored is the entire fresh Linux benign collection rather
  than rule-31101 benign alone, and roughly a fifth of that collection
  belongs to rule IDs that are not deferred and whose L1 vote still
  responds to $\theta_{xgb}$. Panel A's flat 9.1\% recall is a
  volume-weighted blend of two markedly different per-rule L2 recalls --
  rule 31101 ($n=20{,}665$, L2 recall 2.25\%) and rule 31151
  ($n=1{,}585$, L2 recall 98.49\%) -- not a fourth, contradicting
  known-attack recall figure; a specific alternative explanation, that
  rule 31151's L1 vote escapes the defer mechanism while rule 31101's
  does not, was checked directly against the production models and found
  false, since both rules are 100\% deferred. Panel B shows a genuine
  recall/FPR trade-off (recall 23.9\%-100\%, FPR 4.5\%-100\%) over a much
  wider raw threshold range than Panel A; the two panels' x-axes are not
  on comparable scales and are not intended to be read against each
  other directly.}
  \label{fig:7-threshold-sweep-v5defer}
\end{figure*}
```

### Fig 8 — `fig8_cap_censoring_cross_dataset`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig8_cap_censoring_cross_dataset.pdf}
  \caption{Benign-side distribution of \texttt{alert\_rate\_1min} for two
  datasets, with the feature's hard cap (20) marked as a vertical
  reference line. The same unfitted rule
  (\texttt{alert\_rate\_1min} $\geq 20$) applied identically to both
  datasets gives opposite verdicts using only the benign distribution:
  AIT-ADS benign reaches the cap in 32.9\% of rows (rule FPR 0.3291),
  indicating a partial, genuine signal rather than a clean artifact;
  the Linux testbed's benign traffic never approaches the cap (maximum
  observed value 10 of 20; rule FPR 0.0000), the signature of a pure
  collection-tempo artifact. This is this study's own methodological
  contribution made visible -- the same control that diagnosed the
  testbed's capture-tempo defect applies unchanged to a second,
  independent dataset and correctly distinguishes signal from artifact
  using the benign side alone. Both datasets' underlying numbers are
  established elsewhere in this study; this figure shows the full
  distributions rather than only their summary statistics.}
  \label{fig:8-cap-censoring-cross-dataset}
\end{figure}
```

### Fig 9 — `fig9_cross_detector_lookup`

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig9_cross_detector_lookup.pdf}
  \caption{F1 of a majority-label-per-signature lookup table, a model, and
  a trivial always-predict-attack baseline, for three detectors on their
  own evaluation splits: Wazuh-native ($n=458{,}517$, 74.7\% attack),
  Suricata (embedded in Wazuh rule 86601, $n=61{,}536$, 1.9\% attack), and
  AMiner ($n=11{,}112$, 84.7\% attack). The trivial baseline is drawn
  per detector, computed on the identical population as that detector's
  other two bars, because base rates differ too sharply for one shared
  reference value. The lookup table exceeds its trivial baseline on every
  detector, but by very different margins and, for Suricata, in a way an
  F1 gap alone overstates: Wazuh-native beats trivial by $+0.141$ F1
  (0.996 vs.\ 0.855); AMiner by $+0.060$ (0.977 vs.\ 0.917; AMiner's
  recall alone, 0.994, is below its trivial baseline's recall of 1.000 by
  construction, which is why F1, not recall, is the metric used
  throughout this figure); Suricata's nominal $+0.016$ gap (0.054 vs.\
  0.038) is better read in raw counts -- the lookup table flags only 33
  of 61,536 eval-split alerts (0.05\%) and is correct on all 33, but this
  covers a negligible share of Suricata's volume (5 of 29 signatures,
  $\sim$0.07\% of alerts dataset-wide), so the honest claim is the
  \emph{absence} of an exploitable identity shortcut for this detector,
  not a marginal F1 win. Wazuh-native's and AMiner's lookup FPRs
  themselves differ by $\sim$435$\times$ (0.0005 vs.\ 0.2212) -- on
  Wazuh-native, signature identity is close to deterministic for the
  label; on AMiner it is a weak prior riding on an already-high base
  rate. The Wazuh-native and Suricata model bars are an audit-time
  26-feature XGBoost retrain that includes rule-identity features; the
  deployed pickle was re-tested and found scoreable (not
  version-mismatched, as earlier work claimed -- a scaling bug in prior
  scoring scripts was the actual cause) but was not separately rescored
  per detector subset for this figure. The AMiner model bar (marked
  \textdagger{}) is not constructed the same way and is not a
  like-for-like comparison to the other two: no Wazuh-style feature
  vector exists for AMiner's native schema, so this bar instead reports a
  deliberately identity-free 5-feature model (log length, log line count,
  and three causal per-source temporal features), excluding every field
  that names or implies which AMiner detector fired. This model
  (F1$=0.991$) exceeds AMiner's own lookup table (F1$=0.977$), with 94.95\%
  of its gain concentrated in a single per-source alert-tempo feature.
  Because this is the same feature-importance shape behind several
  results this project has already retracted, it was tested against
  Control C1 (does benign reach the same feature range as attack, within
  the same split) rather than assumed real: benign \texttt{alert\_rate\_1min}
  reaches the exact value 98.06\% of attack rows occupy (a 20-alert
  rolling-buffer cap) in 8.41\% of benign rows -- C1 \textbf{passes}, but
  more thinly than the analogous AIT-ADS Wazuh feature (32.9\% benign
  overlap, Fig.~8), so separation here is driven mainly by density at the
  shared cap rather than by disjoint ranges, and remains consistent with
  -- not independent evidence against -- AIT-ADS's time-window labelling
  partly encoding proximity to a labelled attack window rather than a
  purely causal per-source behavioral signature. Full control check:
  supplementary material (\texttt{newCol/fig9\_c1\_check.md}).}
  \label{fig:9-cross-detector-lookup}
\end{figure}
```
