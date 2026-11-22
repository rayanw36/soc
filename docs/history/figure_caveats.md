# Full caveats for each figure, moved out of the paper source

Extracted from the manuscript source (not distributed with this repository); the line ranges below refer to that file. There are 9 blocks between `%% ---- FULL CAVEATS FOR THIS FIGURE` and `%% ---- END FULL CAVEATS ----`. Each is copied verbatim below (comment prefix removed, the three boilerplate lines dropped), one section per figure, headed by its label, with the line range in the manuscript source at the time of extraction.

After each block, the caveats are sorted by whether the printed text or caption already says them: **not stated**, **partly stated**, **already stated** (with where). The sorting is a reading of the manuscript, not a string search. Figure 9 has no block.

| figure | block lines | not stated | partly stated | already stated |
|---|---|---:|---:|---:|
| `fig:1-lookup-vs-model` | 1092-1119 | 2 | 1 | 4 |
| `fig:2-feature-composition` | 1127-1151 | 2 | 2 | 1 |
| `fig:3a-ablation-separability` | 1161-1212 | 3 | 5 | 0 |
| `fig:3b-31101-tier-study` | 1342-1374 | 2 | 1 | 3 |
| `fig:4-31101-score-overlap` | 1382-1407 | 3 | 0 | 2 |
| `fig:7-threshold-sweep-v5defer` | 1451-1486 | 2 | 1 | 2 |
| `fig:5-tempo-asymmetry` | 1626-1651 | 2 | 1 | 2 |
| `fig:6-benign-composition` | 1682-1712 | 3 | 1 | 2 |
| `fig:8-cap-censoring-cross-dataset` | 2034-2059 | 1 | 0 | 3 |

## fig:1-lookup-vs-model

Manuscript source, lines 1092-1119.

Full block, verbatim:

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{figures/fig1_lookup_vs_model.pdf}
  \caption{F1 of the full 26-feature XGBoost model versus a
  majority-label-per-rule-ID lookup table, both measured on the same
  AIT-ADS evaluation split (gap $=+0.0003$). Only F1 is shown because it
  is the sole metric committed for both series; precision and recall for
  the lookup-table baseline are not available in any committed artifact
  and were not reconstructed. The XGBoost bar is an audit-time retrain rather than the deployed
   artifact. An earlier report that the deployed pickle produced a
   degenerate F1 of 0.0000 was traced to a scaling-pipeline error
   (raw features passed to a model trained on scaled ones), not to a
   serialization-version mismatch; scored correctly the deployed
   artifact gives F1 = 0.9945, matching the retrain. The value shown" the value shown instead
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

**Not stated in the printed text or caption:**

- Only F1 is shown because it is the only metric committed for both series; precision and recall for the lookup table are not available in any committed artifact and were not reconstructed.
- An earlier report that the deployed pickle gave a degenerate F1 of 0.0000 was traced to a scaling-pipeline error (raw features passed to a model trained on scaled ones), not to a serialization-version mismatch. No sentence in the manuscript mentions the 0.0000 report or its cause. Decide whether this history belongs in print or only in the artifact's notes.

**Partly stated:**

- Rule 31101 is 100% attack in both folds of the evaluation split; the lookup table's near-parity is therefore memorization risk, not evidence that the full model adds nothing. Sec. "The Benchmark Is separable by rule identity alone" says rule 31101 is "almost entirely attack-labelled in both temporal folds", which is the chronological repeat, not the primary stratified-random split the figure uses. The "100% in both folds of this split" statement and the "not evidence that the model adds nothing" reading are not in print.

**Already stated in print:**

- The XGBoost bar is an audit-time retrain, not the deployed artifact. Sec. Methods ("Two XGBoost configurations appear throughout this paper") and Table of XGBoost configuration; Limitations ("the audit-time results reported here use a model retrained"). Not repeated at the figure or in its caption.
- The shown value uses a threshold chosen by maximising F1 on the same split, not the deployed operating threshold. Sec. "The Benchmark Is separable by rule identity alone" ("its threshold was selected by maximising F1 directly on the same evaluation split"); Methods; Limitations.
- Scored correctly, the deployed artifact gives F1 = 0.9945, matching the retrain. Limitations ("We verified that the deployed artifact itself reproduces the same F1 to four decimal places").
- Gap = +0.0003. Sec. "The Benchmark Is separable by rule identity alone" ("a gap of 0.0003").

**Editorial notes on the block:**

- The block's caption has a duplicated fragment: `The value shown" the value shown instead comes from an audit-time retrain`. Fix before any of it is moved to a caption.

## fig:2-feature-composition

Manuscript source, lines 1127-1151.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- Exact shares are 94.99% and 5.01% (the plot shows 95.0% and 5.0%). Text and plot use the rounded values only.
- `is_web_attack` alone accounts for essentially all of the RULE-CORRELATED bucket's gain, and the reclassification of `time_since_last_high` does not change the 95.0%/5.0% split because that split is per feature, not per bucket.

**Partly stated:**

- `is_web_attack` is rule-definition metadata specifically in the form of rule groups and description phrases. Sec. "The Benchmark Is separable by rule identity alone" says it is "a rule-type indicator derived from the rule definition"; the groups/description-phrase detail is not given.
- Bucket sizes: 3 RULE-IDENTITY, 21 RULE-CORRELATED, 2 BEHAVIORAL. "Three rule-identity features" and "2 of 26 features behavioral" are in the text; the 21 rule-correlated count is not.

**Already stated in print:**

- `time_since_last_high` was reclassified from behavioral to rule-correlated because its mechanism is proximity to a rule-severity event. Sec. "The Benchmark Is separable by rule identity alone" ("Investigating the mechanism produced a taxonomy correction").

## fig:3a-ablation-separability

Manuscript source, lines 1161-1212.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- No true identity-only ablation exists in the committed results; the three variants are exactly what was run, not a clean identity-versus-behavior split.
- `alert_rate_1min` carries only 0.307% of the full model's split gain; `time_since_last_high` carries most of the behavioral bucket's gain (2.815%).
- 99.08% of split gain lies in the corrected RULE-IDENTITY and RULE-CORRELATED buckets combined.

**Partly stated:**

- `no_identity` equal to `full` must not be read as showing that identity features are unnecessary. Sec. "The Benchmark Is separable by rule identity alone" explains that the carrier is `is_web_attack`, rule-correlated rather than rule-identity; it does not say in so many words that the ablation does not show identity features are unnecessary.
- The `alert_rate_1min` cap of 20 and the `time_since_last_high` floor of 0 were confirmed against the feature-engineering source to be structural boundaries, not values chosen by looking at evaluation performance. Text states that neither threshold was fitted and gives the reason (history buffer `maxlen=20`; floor of 0). The confirmation against the source code is not stated.
- 99.3% of attack rows saturate the `alert_rate_1min` cap versus 32.9% of benign rows; AIT-ADS benign reaches the cap in about a third of rows, unlike the Linux testbed, so this is a partial, coarse tempo signal and not a clean capture-tempo artifact. The 0.9925 recall and 0.3291 FPR are stated here and the "partial genuine signal" reading is stated in Sec. "The Controls Transfer to the Public Benchmark". Not stated at this figure: that this is a coarse partial tempo signal, and the contrast with the testbed.
- `time_since_last_high` is zero for 80.4% of attack rows versus 1.0% of benign; its mechanism is proximity to a `rule.level` >= 10 event, and `rule_level` is itself rule-identity metadata, so the separation is closer to a rule-derived signal than a behavioral one. Recall 0.8036 / FPR 0.0103 and the reclassification are in the text; the link through `rule_level` is in the taxonomy paragraph. The 2.815% gain share is not.
- Only `alert_rate_1min` is a genuine, if partial, behavioral/tempo signal; all three other routes to separability are rule-definition metadata. TENSION: the printed text ends the paragraph with "Nothing behavioral separates this benchmark", while this caveat (and the cross-dataset section) treats `alert_rate_1min` as partial genuine signal. Reconcile the wording before one is quoted against the other.

**Editorial notes on the block:**

- The block describes "Left" and "Right" panels; the printed figure is now two sub-figures (a) and (b) (`fig3a_ablation.pdf`, `fig3a_thresholds.pdf`), so the wording needs updating if the caveats are moved to a caption.

## fig:3b-31101-tier-study

Manuscript source, lines 1342-1374.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- A third tier, aggregate per-entity features such as `distinct_url_count`, is not drawn as a bar because it was not evaluated as a per-alert classifier (one alert cannot have a distinct path count).
- `distinct_url_count` shows a 1,519x median separation between attack and benign entities, a magnitude not established to hold in a busier benign environment. Check against the entity-window retractions (Sec. "The Entity-Window Redesign: Retraction Sequence", R1 global-window result) before quoting this number: it comes from the same global-window block.

**Partly stated:**

- Tier B's nominally top-ranked feature does not survive a causal swap-to-benign-typical test; the real, small effect is `path_depth` flagging correctly only one of the three benign endpoints. The `path_depth` / one-of-three-endpoints effect is stated (Sec. "Per-Alert Insufficiency for Rule 31101"). The swap test is not mentioned anywhere in the text.

**Already stated in print:**

- Both populations are tool-generated (dirb with a spoofed User-Agent; bare curl polling three fixed endpoints). End of Sec. "Per-Alert Insufficiency for Rule 31101" and Limitations.
- Tier A: recall 1.0000, FPR 0.0000, carried by one header and evadable. Same section.
- Tier B: FPR 0.6667 (28 of 42); trivial always-attack baseline FPR 1.00, F1 0.9940; n = 3,464 / 42. Same section, with Wilson intervals added.

## fig:4-31101-score-overlap

Manuscript source, lines 1382-1407.

Full block, verbatim:

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
  retracted. This figure is a mechanism/insufficiency demonstration
  rather than a novel result in its own right. Both populations are
  tool-generated HTTP traffic (\texttt{dirb} with a spoofed User-Agent
  for attack; bare \texttt{curl} polling fixed endpoints for benign),
  not organic browsing.}
  \label{fig:4-31101-score-overlap}
\end{figure}
```

**Not stated in the printed text or caption:**

- FPR exceeding recall places the operating point at or below the chance diagonal, "a stronger finding than mere score overlap". Do not restore as written. The printed text says "on the chance diagonal" and, after the episode analysis, "We therefore do not claim the novelty layer prefers benign alerts"; the block's stronger wording is superseded.
- This is the left panel only of an earlier combined figure; the paired right panel (entity-window aggregation of the same alerts) is not reproduced because that result was retracted. The entity-window retractions are reported in their own section, but not tied to this figure.
- The figure is a mechanism/insufficiency demonstration, not a novel result in its own right.

**Already stated in print:**

- Counts, threshold and the 2.25% / 4.78% rates. Sec. "Per-Alert Insufficiency" and the caption.
- Both populations are tool-generated. Same section and Limitations.

## fig:7-threshold-sweep-v5defer

Manuscript source, lines 1451-1486.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- Panel A sweeps theta_xgb with theta_ocsvm held at its deployed value; Panel B sweeps theta_ocsvm with theta_xgb held fixed; both mark the deployed threshold with a vertical line.
- Panel B ranges: recall 23.9%-100%, FPR 4.5%-100%, over a much wider raw threshold range than Panel A; the two x-axes are not on comparable scales and should not be read against each other.

**Partly stated:**

- Panel A's FPR varies (6.7% to 17.6%) because the benign side is the whole fresh collection, roughly a fifth of which is non-deferred rule IDs. "From 18 to 47 of 267" and "because some benign alerts fire non-deferred rules" are stated; the "roughly a fifth" share is not (it follows from 31101 being 78.3%, stated in the benign-composition section).

**Already stated in print:**

- Flat recall (TP = 2026, FN = 20224 at all 400 points) because both known rules are 100% deferred. Sec. "Deferral Behaviour and the Inert Threshold".
- The 9.1% blended recall is volume-weighted over rule 31101 (2.25%) and rule 31151 (98.49%), not a contradicting measurement; the alternative that 31151 escapes deferral was checked and is false. Same section ("It decomposes exactly"; "We verified directly against the production models").

## fig:5-tempo-asymmetry

Manuscript source, lines 1626-1651.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- The two panels use different y-axis scales (to show each platform's own within-round contrast).
- Windows' residual 1.5x ratio does not by itself explain any finding in this study. Text says only that the Windows collections show "no comparable asymmetry".

**Partly stated:**

- The asymmetry does not apply uniformly: a check of the capped `alert_rate_1min` found Linux benign never approaches the cap that Linux attack saturates, so that feature's separation on Linux is not symmetrically erased by the asymmetry. Sec. "Capture-Tempo Asymmetry" says the cap makes the asymmetry "only partly visible" to the deployed model; the benign maximum of 10 against the cap of 20 is in the cross-dataset section. The contrast with the entity-window rate features is not drawn at this figure.

**Already stated in print:**

- The asymmetry is the mechanism behind every retracted Linux rate/volume-shaped finding. Sec. "Capture-Tempo Asymmetry" ("the unifying explanation for the retracted results").
- 135.2x mean rate; Windows 1.5x. Same section.

**From later analyses in this repository (not in the block):**

- The 135.2x (and Windows 1.5x) uses every row of the attack-round files, including the 312 Linux and 65 Windows alerts that are not attack-labelled. With attack-labelled rows only the Linux ratio is 227.5x and the Windows ratio 1.7x. Control C4 as implemented in `controls/run_all.py` uses attack-labelled rows and prints 227.5x / 684.0x, not 135.2x / 820.8x. See `results/nonattack_alerts_attack_rounds.md`. The direction of the asymmetry is the same either way; which population to quote is a choice for the authors, and the caption or text should say which one the figure uses.

## fig:6-benign-composition

Manuscript source, lines 1682-1712.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- Windows benign is 38.8% rule 92004 (PowerShell process-spawn) plus 28.9% rule 60106 (logon success). The text gives only the Linux composition (78.3% rule 31101). The new horizontal figure prints the Windows counts (78 and 58 of 201) on the bars.
- Rules 60122/60204, the T1110.001 brute-force family a retracted headline result was scored against, have zero representation in the Windows benign collection (checked directly).
- The "all other rules" aggregate is what remains after the five named rules and is not a stable long-tail estimate. The sample sizes are in the caption (n = 267, 201); this caution is not.

**Partly stated:**

- Several rule families have no measurable benign-side FPR because their rule ID is absent from the benign traffic. Limitations ("Several rule families have no benign representation") and Sec. "Decomposition of the Novel-Attack Result"; not tied to this figure for Windows.

**Already stated in print:**

- Linux benign is bare curl polling three endpoints plus a printing daemon's lease-file rewrite: machine-generated daemon traffic. Sec. "Benign Corpus Composition".
- Neither collection is large (n = 267 Linux, n = 201 Windows). Caption and Limitations.

**Editorial notes on the block:**

- The block describes the original vertical-bar figure; the printed figure is now `fig6_benign_composition_h.pdf` with counts and percentages and an id: description label on each bar. The caveat text itself still applies.

**From later analyses in this repository (not in the block):**

- In the horizontal figure the "all other rules" bars are 9 alerts (Linux) and 24 (Windows). The 19 Linux and 3 Windows alerts labelled benign inside the attack rounds are not part of this figure; it is built from the benign-only collections.

## fig:8-cap-censoring-cross-dataset

Manuscript source, lines 2034-2059.

Full block, verbatim:

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

**Not stated in the printed text or caption:**

- The figure shows the full benign distributions, not only the summary statistics, which are established elsewhere in the study.

**Already stated in print:**

- AIT-ADS benign reaches the cap in 32.9% of rows (FPR 0.3291): a partial genuine signal, not a clean artifact. Sec. "The Controls Transfer to the Public Benchmark". See the wording note below.
- Linux testbed benign never approaches the cap (maximum 10 of 20; FPR 0.0000): the signature of a collection-tempo artifact. Same section.
- The same unfitted rule applied identically to both datasets gives opposite verdicts from the benign distribution alone; the control that diagnosed the testbed transfers unchanged to a second dataset. Same section.

**Editorial notes on the block:**

- The printed caption says "genuine AIT-ADS signal"; the block and the text say "partial" genuine signal. Consider "partial" in the caption.

