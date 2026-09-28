# XDET Results — Tasks 1–3 + Addition A (rule 86601 natural experiment)

Continues `newCol/xdet_task0_composition.md` (Task 0, accepted). Standing
rules unchanged: no fabrication, no new collection, no retraining of any
deployed model, no threshold tuning. All numbers below are computed from
files already in `data/ait_ads/`; scripts are `newCol/xdet_recover_wazuh_split.py`,
`newCol/xdet_build_aminer.py`, `newCol/xdet_task1_lookup.py`,
`newCol/xdet_task2_task3.py`. Raw outputs: `newCol/xdet_task1_results.json`,
`newCol/xdet_task2_task3_results.json`.

## Methodology recap (Additions B and C applied)

- **Labels**: re-derived for Suricata and AMiner using the *same*
  `labels.csv` time-window / `merge_asof` method already used for Wazuh
  (`phase1_xgboost.py:load_ait_ads`) — **not** `AIT_alerts.csv`'s own
  `label` column, which uses a different event-label-preferred convention
  (Addition B). This keeps all three detectors comparable under one
  labelling discipline.
- **Split discipline**: for Wazuh, the *exact* deployed train/test
  partition was recovered (not re-derived approximately) — verified
  byte-identical to `models_v2/ait_split.npz`'s `y_train`/`y_test`
  (`xdet_recover_wazuh_split.py`). For AMiner, which was never part of
  any deployed split, a freshly-constructed 80/20 stratified split (same
  `test_size`/`SEED` convention) is used and disclosed as such, not
  presented as a recovery.
- **NMI convention** (stated once, used everywhere below): sklearn
  `normalized_mutual_info_score` with its default `average_method=
  'arithmetic'` — the same call already used in
  `results/rule_memorization_audit/exp3_lookup_table.py`.
- **Citation**: `landauer_introducing_2024` (Landauer, Skopik,
  Wurzenberger, CSET '24) independently retrieved and read in full (not
  taken on faith) — see the Task 0 update. It confirms every count in
  this section to the alert and confirms the Suricata-via-Wazuh
  collection mechanism from the dataset authors' own description.

## ADDITION A — Rule 86601 as a natural experiment

Rule 86601 (Wazuh's wrapper for Suricata alerts it collects, per
`landauer_introducing_2024` Sect. 3.1.2) fired for 306,635 alerts
(11.8% of the Wazuh stream) and was trained/scored by the deployed
pipeline with its true 29-signature identity already collapsed to one
value (`rule_id_encoded = 86601.0` for all of them). This is an
identity-ablation that already happened on real, already-scored data.

### A(a). Performance contrast: identity-preserved vs. identity-collapsed

**The deployed `models_v2/xgb_model.pkl` could not be used as-is.**
Verified directly: `predict_proba` on `ait_split.npz`'s `X_test` produces
scores topping out at 0.059 (mean 0.0041), entirely below
`theta_xgb=0.0754` — TP=0 on every possible subset, not a real result.
This is the same xgboost version-mismatch degeneracy already diagnosed by
prior work (`newCol/figures_ms/fig1_lookup_vs_model.py`'s docstring and
`exp4_ablation.py`'s docstring: *"fresh retrain; used as baseline since
pkl has version mismatch"*). Following that established precedent, this
task uses an **audit-time retrain** that exactly reproduces
`exp4_ablation.py`'s "full" (26-feature) variant — same hyperparameters,
same raw features, same eval-split-calibrated threshold — then breaks
the *same* eval split out by rule 86601 vs. Wazuh-native. This is **not**
a retrain of the deployed model (that model is simply unusable here);
its threshold (0.3798, chosen by max-F1 on the eval split) is an
audit-only calibration, **not** `theta_xgb`. "At the deployed threshold"
literally could not be honored and this substitution is stated plainly
rather than silently presented as the deployed result.

| eval subset | n | Precision | Recall | F1 | FPR |
|---|--:|--:|--:|--:|--:|
| Wazuh-native (rule.id != 86601) | 458,517 | 1.0000 | **0.9924** | 0.9962 | 0.00004 |
| Suricata-via-Wazuh (rule.id == 86601) | 61,536 | 0.9808 | **0.0429** | 0.0821 | 0.00002 |

Recall collapses from **99.2% to 4.3%** exactly where detector identity
was destroyed by the encoding, at matched near-zero FPR on both sides
(so this isn't a precision/recall trade-off artifact — the model simply
almost never fires on the identity-collapsed population). **This is
causal, not correlational**: the same model, same features (minus a
usable identity value), same eval split, same attack activity — the
only thing that changed is that 29 real signatures got mapped to one
shared number. This is stronger evidence for the manuscript's
memorization thesis than the correlational lookup-table argument alone,
because it is a controlled contrast within one scored run rather than
two different measurement setups.

### A(b). Suricata lookup table within the 86601 population (= Task 1 Suricata row, presented once)

Built on train, scored on eval, keyed on the true `rule.description`
(29 signatures), restricted to the 86601 subset — i.e., using the
identity that the deployed encoding discarded:

| | value |
|---|--:|
| n | 306,635 |
| distinct signatures | 29 |
| attack rate | 1.96% |
| top attack-contributing signature | `SURICATA TLS invalid record/traffic` (39.6% of attack alerts) |
| train / eval | 245,099 / 61,536 |
| **Precision / Recall / F1 / FPR** | 1.0000 / **0.0277** / 0.0540 / 0.0000 |
| NMI(signature, label) | train=0.0056, eval=0.0048, full=0.0054 |

The lookup table performs *even worse* than the full-feature audit
retrain (2.8% vs. 4.3% recall) — recovering true signature identity
alone is not enough to detect attacks well here; see A(c) below for why.
**This directly answers Task 1's model-comparison requirement for
Suricata**: no deployed model exists for Suricata as such, but the
26-feature audit retrain *does* provide a legitimate comparison on this
population (both scored on the same alerts), and both are weak — this is
a property of the population, not an artifact of the lookup table
specifically.

### A(c). Is the 86601 population a random subset, or confounded?

Not random by scenario (concentrated in `wheeler`/`harrison`/`wilson`,
the three "extensive scanning" scenarios per `landauer_introducing_2024`
Sect. 3.2.2 — 22.4%/22.0%/21.2% of the 86601 population respectively vs.
3.0% for the shortest scenario, `russellmitchell`), which tracks overall
alert-volume differences across scenarios and is not itself alarming.

More importantly: **is the weak recall explained by pure label noise**
(background Suricata traffic that happens to fall inside a wall-clock
attack window, per the false-positive-by-construction mechanism
documented in Task 0d) **rather than a genuine identity-collapse
effect?** Checked directly — the 6,018 attack-labeled 86601 alerts,
broken out by which attack category's time window they fall in:

| attack category | n | share |
|---|--:|--:|
| dnsteal | 2,285 | 38.0% |
| cracking | 1,621 | 26.9% |
| dirb | 778 | 12.9% |
| network_scans | 658 | 10.9% |
| service_scans | 542 | 9.0% |
| wpscan | 56 | 0.9% |
| webshell | 38 | 0.6% |
| reverse_shell | 24 | 0.4% |
| privilege_escalation | 14 | 0.2% |
| service_stop | 2 | 0.03% |

These concentrate in categories where a network IDS *should* plausibly
fire — `dnsteal` (DNS exfiltration; matches `landauer_introducing_2024`'s
own account of Suricata detecting the DNS-exfiltration case via
`S-Dns-Qry3` in some scenarios) and `network_scans`/`service_scans`
(scanning) together are 58.8% of the attack-labeled population — not a
random scatter across categories, and not concentrated in a category
where Suricata firing would be coincidental. **This weighs against "pure
label noise" as the explanation and is consistent with genuine, if
weak, network-layer signal that the collapsed encoding and the lookup
table both fail to exploit.** Stated as a directional read, not proof:
we did not verify alert-by-alert causal linkage to the attack traffic,
only that the timing pattern is attack-category-coherent rather than
diffuse background noise.

## TASK 1 — Per-detector lookup-table audit (full results, all three detectors)

| detector | n alerts | distinct sigs | attack rate | top attack sig | its share of attacks | train / eval |
|---|--:|--:|--:|---|--:|---|
| Wazuh-native | 2,293,628 | 30 | 74.62% | `31101` | 91.8% | 1,835,111* / 458,517* (native subset of the recovered exact split) |
| Suricata (86601) | 306,635 | 29 | 1.96% | `SURICATA TLS invalid record/traffic` | 39.6% | 245,099 / 61,536 |
| AMiner | 55,558 | 34 | 84.70% | `AMiner: New request method in Apache Access log.` | 57.9% | 44,446 / 11,112 (fresh 80/20 split) |

\* Wazuh-native train/eval counts are the native-only rows within the
exact recovered split (2,080,210/520,053 total incl. the 86601 rows).

### Lookup-table performance (majority-label-per-signature, train→eval)

| detector | Precision | Recall | F1 | FPR | unseen-in-eval | NMI(sig,label) train/eval |
|---|--:|--:|--:|--:|--:|--:|
| Wazuh-native | 0.9998 | **0.9922** | 0.9960 | 0.0005 | 0 (0.00%) | 0.6800 / 0.6788 |
| Suricata (86601) | 1.0000 | **0.0277** | 0.0540 | 0.0000 | 0 (0.00%) | 0.0056 / 0.0048 |
| AMiner | 0.9614 | **0.9937** | 0.9773 | 0.2212 | 0 (0.00%) | 0.2865 / 0.2870 |

No unseen signatures in any eval split (every signature seen in eval was
also seen in train, for all three detectors) — so none of these results
are inflated or deflated by an out-of-vocabulary effect.

### Model-vs-lookup gap, per Task 1d's instruction

- **Wazuh**: full-feature model recall 99.24% vs. lookup-table recall
  99.22% on the native subset — the model and the pure-identity lookup
  table are nearly indistinguishable on native Wazuh alerts. This is
  consistent with (not new evidence beyond) the manuscript's existing
  Wazuh-only finding.
- **Suricata**: both the model (4.3% recall, Addition A(a)) and the
  lookup table (2.8% recall) are weak here. Reported as required by Task
  1d: "the lookup table's absolute performance, model comparison is
  [available and weak on both sides for this population]" — not because
  no model exists, but because the model that does exist performs almost
  as poorly as the lookup table, for the reasons discussed in A(c).
- **AMiner**: per Task 1d's instruction, **no comparable trained model
  exists for AMiner in this project** (it was never part of any deployed
  pipeline), and none was built to force a comparison. AMiner's lookup
  table achieves F1=0.9773, recall=99.4% **on its own, with zero
  engineered features, using nothing but "which of 34 signature names
  fired."**

## TASK 2 — Unfitted rate thresholds (schema-independent, timestamps only)

**Rate definition** (stated once, structural, not tuned): for each
alert, the count of alerts from the *same detector-subset and same
scenario* in the trailing 60 seconds (inclusive of itself) — a simple
per-scenario sliding count from timestamps alone. This is deliberately
**not** the existing `alert_rate_1min` feature (which is per-agent and
capped at a 20-alert buffer) — that feature is Wazuh-specific and not
computable in a comparable way for Suricata's collapsed identity or
AMiner's different host-identification scheme. **Threshold**: the 99th
percentile of the benign-class rate distribution — a structural
percentile rule computed once per detector, not selected by looking at
attack recall.

| detector | benign mean/median/p99 | attack mean/median/p99 | threshold (benign p99) | recall | FPR |
|---|---|---|--:|--:|--:|
| Wazuh-native | 33.0 / 23 / 183 | 19,979 / 21,124 / 27,203 | 183 | **0.9925** | 0.0099 |
| Suricata (86601) | 30.9 / 15 / 209 | 30.6 / 19 / 160 | 209 | **0.0000** | 0.0099 |
| AMiner (all data) | 10.4 / 4 / 51 | 1,482 / 662 / 6,237 | 51 | **0.9821** | 0.0088 |
| AMiner (excl. first-12h) | 10.7 / 4 / 49 | 1,482 / 662 / 6,237 | 49 | 0.9826 | 0.0081 |

Wazuh-native and AMiner show the same qualitative pattern already
documented for Wazuh in `newCol/figures_ms/tempo_ait_check.md`: attack
alert rates are roughly 2–3 orders of magnitude above benign, driven by
scripted/bursty attack activity, giving near-total separability from
timestamps alone with essentially no threshold fitting. **Suricata is
qualitatively different: benign and attack rate distributions are
statistically indistinguishable** (means 30.9 vs 30.6, medians 15 vs 19)
— **zero** attack alerts in the 86601 population exceed the benign p99
threshold. This independently corroborates `landauer_introducing_2024`
Table 2/Sect. 4.1, which separately flags Suricata detectors like
`S-Tls-Hnd` (part of rule 86601) as contributing little to detection
because they *"involve similar alert rates for phases of attack and
normal behavior"* — the dataset authors reached the same conclusion by a
different method.

### Task 2c — AMiner training-phase false-positive caveat

Per `landauer_introducing_2024` Sect. 3.2.1: *"almost all AMiner
detectors report multiple false positives in the first half of the
first day of each scenario, which is the result of training the
models... that are still incomplete."* Checked directly whether this
period is in our data: **yes** — 4,076 AMiner alerts (7.34% of the
55,558 total) fall in the first 12 hours of their scenario's timeline,
and **all 4,076 are benign-labeled** (0 attack-labeled), consistent with
attacks starting later in each scenario's timeline. Reported both ways
per instruction (see table above): recall changes from 98.21% to 98.26%
and FPR from 0.88% to 0.81% when this window is excluded — a small,
expected shift, not a confound that changes the qualitative result.

## TASK 3 — Labelling-artefact / signature-exclusivity check

For each detector: signatures partitioned into those that fire
**exclusively** during labeled attack windows, **exclusively** outside
them (benign-only), or in **both** (mixed), with alert volume per
bucket.

| detector | attack-only sigs | attack-only alerts (% of detector) | benign-only sigs | benign-only alerts (%) | mixed sigs | mixed alerts (%) |
|---|--:|--:|--:|--:|--:|--:|
| Wazuh-native | 8 | 127,146 (5.54%) | 4 | 238 (0.01%) | 18 | 2,166,244 (94.45%) |
| Suricata (86601) | 5 | 201 (0.07%) | 17 | 337 (0.11%) | 7 | 306,097 (99.82%) |
| AMiner | **0** | **0 (0.00%)** | 7 | 350 (0.63%) | 27 | 55,208 (99.37%) |

Wazuh-native attack-only signatures: `5706, 30305, 31151, 30306, 31516,
31104, 5304, 31510` (all low-volume; the dominant `31101` is *mixed*,
not attack-only).

### The mechanism question, answered directly

**"Signature fires only in attack windows by construction of
time-window labelling" is a minor contributor to volume everywhere —
under 6% of alerts for every one of the three detectors, and literally
0% for AMiner.** This is an important correction to the mechanism Task
3b anticipated: the manuscript's memorization effect is **not**
primarily explained by trivially-exclusive signatures. What actually
drives lookup-table success (where it succeeds) is **within-signature
label skew on *mixed* signatures** — e.g., rule 31101 (Wazuh) is mixed
(fires in both classes) yet is 91.8% of all Wazuh-native attack alerts,
so a majority-vote lookup table still captures it correctly. AMiner's
strong lookup-table performance (99.4% recall, F1=0.9773) is achieved
with **zero** attack-exclusive signatures at all — its effectiveness
comes entirely from genuine within-signature skew in an anomaly
detector's real behavior, not from a labelling artefact.

**This is evidence *against* the "exclusivity-by-labelling-construction"
version of the confound, and evidence *for* a different, more
interesting claim**: detector-identity substitutes for detection
whenever a detector's *typical firing pattern* is skewed toward attack
periods for real behavioral reasons (dense scripted attack traffic for
Wazuh/AMiner) — a property of the platform's behavior under this
dataset's attacks, not an artefact of how the labels were drawn. Where
that skew doesn't exist behaviorally (Suricata/86601, attack rate 1.96%
with near-identical timing to benign), the lookup table fails
regardless of exclusivity bookkeeping.

### Task 3c verdict input

**The pattern (strong identity-substitutes-for-detection effect) holds
for Wazuh-native AND AMiner — one signature-based, one anomaly-based,
both host-based — but NOT for Suricata (network-based).** This is not
the boundary Task 3c anticipated ("holds for all three" vs. "Wazuh
only"); it is a third shape: **replicates across paradigm (rules vs.
anomaly) but not across placement (host vs. network)**. See Task 4 for
the full verdict.

## Threats-to-validity items (Addition D — recorded regardless of Task 4's outcome)

1. **The deployed feature pipeline encoded away the detector identity of
   ~11.8% of its AIT-ADS training data** (rule 86601 collapses 29
   distinct Suricata signatures to one `rule_id_encoded` value). Found
   only by this audit; not previously documented anywhere in the
   project.
2. **The split loader (`phase1_xgboost.py:load_ait_ads`, Task 0) reads
   only `*_wazuh.json`**, structurally excluding AMiner (2.1% of the
   dataset's alerts) from every AIT-ADS number in the manuscript,
   including Fig 8.
3. **The deployed `models_v2/xgb_model.pkl` is non-functional in the
   current environment** (xgboost version-mismatch degeneracy, proba
   max=0.059 vs. threshold 0.0754) — this was already known from prior
   work (`fig1_lookup_vs_model.py`) but is re-confirmed here and is a
   standing risk for any figure/number in the manuscript that implicitly
   assumes this file is usable.

All three are defects/limitations in this project's own pipeline,
independent of whatever Task 4 concludes about generalization.

---

# PRE-VERDICT CHECKS B1–B3 (supersede/sharpen Task 3's framing above)

Scripts: `newCol/xdet_preverdict_b1b2b3.py`. Output:
`newCol/xdet_b1b2b3_results.json`. These checks were requested because
Task 3 and Addition A, as written above, drew two conclusions more
strongly than the evidence supported. Both are corrected below; **Task
3's exclusivity table and B2/B1's numbers are not deleted, they are
sharpened.**

## B1 — Suricata: "no shortcut exists" vs. "the shortcut points at benign"

Per-signature majority-label distribution across all 29 signatures in the
86601 population:

| | signatures | volume | volume % |
|---|--:|--:|--:|
| majority-attack | 5 | 201 | 0.07% |
| majority-benign | 24 | 306,434 | **99.93%** |

The 5 majority-attack signatures are all *strictly* attack-exclusive but
tiny (`ET SCAN Possible Nmap User-Agent Observed`=138, `SURICATA SMTP
invalid reply`=18, `SURICATA SMTP no server welcome message`=18,
`SURICATA TLS invalid SSLv2 header`=18, `SURICATA TLS invalid record
type`=9 — 201 alerts total). The other 24 signatures — including the two
highest-volume ones, `SURICATA TLS invalid handshake message` (2,356
attack / 102,660 benign, ratio 0.023) and `SURICATA TLS invalid
record/traffic` (2,383 attack / 102,660 benign, ratio 0.023) — are
majority-benign by roughly 43:1, carrying 99.9% of the population's
volume between them and the other 22 majority-benign signatures.

**This settles B1c: the second situation holds.** A majority-vote lookup
table over these 29 signatures predicts "benign" for the population
almost everywhere, *because that is what the population actually looks
like* — Suricata fires on background/protocol noise (TLS handshake
oddities, DNS queries to generic TLDs) far more than on attack traffic,
not because the mechanism failed to find a shortcut that exists. The
**corrected statement, replacing the report's earlier framing**:
*signature identity does not provide an attack-side shortcut for this
detector, and the population is not more decidable by other means either
— the audit-time model reaches only 4.3% recall on the same alerts
(Addition A(a))*. This is not "the effect does not appear here" (which
implies Suricata is simply a clean, well-separated population the
mechanism fails to exploit) — it is "this population is hard on its own
terms, independent of the identity-collapse question." Both facts belong
in Task 4; they are different claims.

## B2 — Is the 86601 population a filtered slice of Suricata?

**The premise needed correcting before it could be tested as posed.**
There is no standalone raw Suricata file anywhere in our holdings to
compare against (confirmed in Task 0: no `*_suricata.json` in
`data/ait_ads/raw/` or the zip) — and, per `landauer_introducing_2024`
Sect. 3.1.2 itself (*"The authors of the AIT-LDSv2 already deployed
Suricata on the servers in the network. Accordingly, Suricata alerts are
already available in the data set and can be conveniently collected by
Wazuh"*), **Wazuh-mediated ingestion was the only Suricata collection
mechanism the dataset's own authors used** — there is no unfiltered
Suricata channel to compare against even in principle, in this dataset.

The strongest available check instead: compare our reconstructed 86601
signature set against the dataset authors' own published complete list
(Table 1 of `landauer_introducing_2024`, transcribed directly from the
retrieved PDF — 29 distinct alert-description texts under the Suricata
column).

| check | result |
|---|---|
| Our 86601 population: distinct signatures | 29 |
| Paper's documented Suricata signatures | 29 |
| Paper signatures missing from our population | **0** |
| Signatures in our population not in the paper's list | **0** |
| Our total 86601 volume | 306,635 |
| Paper's published total Suricata alert count | 306,635 |
| Volume match | **exact** |

**Perfect match, on both signature identity and total volume.** Per
B2c: the 86601 population is representative of Suricata as documented by
the dataset's own creators — not a decoder-filtered subset — so every
Suricata claim in this report (B1, Task 1, Task 2, A(a)-(c)) can be made
at full detector scope, with the caveat (stated once, applies throughout)
that "Suricata" in this dataset was, by the dataset's own design, always
collected via Wazuh's ingestion pipeline — there is no "Suricata
collected independently of Wazuh" condition to compare against, in this
dataset or in our holdings.

## B3 — Exclusivity was too strict a test for Task 3's conclusion

Full per-signature attack:benign ratio distribution, all three
detectors (volume share at each band, not cumulative-exclusive-only):

| detector | ≥1000:1 | ≥100:1 | ≥10:1 | ≥2:1 | strictly exclusive (Task 3's number) |
|---|---|---|---|---|---|
| Wazuh-native | 9 sigs, 1,698,459 (**74.05%**) | same | same | 11 sigs, 74.06% | 8 sigs, 5.54% |
| Suricata (86601) | 5 sigs, 201 (0.07%) | same | same | same | 5 sigs, 0.07% (unchanged) |
| AMiner | 0 sigs, 0 (0.00%) | 1 sig, 27,342 (**49.21%**) | 3 sigs, 40,928 (73.67%) | 4 sigs, 48,588 (87.45%) | 0 sigs, 0.00% |

**This changes the report's earlier conclusion materially.** Task 3
above reported "exclusivity is a minor contributor to volume everywhere
(<6%)" and used AMiner's 0% exclusive-signature count as evidence *for*
genuine behavioral skew over labelling-construction. B3 shows that
framing was too narrow a test:

- **Wazuh-native**: 74.05% of all Wazuh-native volume sits at ≥1000:1,
  driven almost entirely by **rule 31101 itself** (1,571,057 attack /
  256 benign = **ratio 6,137:1**, the single largest signature by volume
  in the whole detector). 31101 is technically "mixed" (not strictly
  exclusive, per Task 3), but at 6,137:1 it is a near-perfect statistical
  proxy in every practical sense. **The labelling-construction
  explanation is not ruled out for Wazuh** — it is highly plausible for
  the majority of Wazuh-native volume, concentrated in one rule.
- **AMiner**: 49.21% of volume sits at ≥100:1, entirely attributable to
  one signature, `AMiner: New request method in Apache Access log.`
  (27,269 attack / 73 benign, ratio 373.5). This also was not visible in
  the strict-exclusivity count (0%). **AMiner's strong lookup-table
  result is therefore only partly explained by "genuine skew across many
  signatures with zero exclusive artefacts"** as the report previously
  argued — nearly half its volume rides on a single near-perfect,
  non-exclusive proxy, structurally the same shape as rule 31101.
- **Suricata**: unchanged at every threshold (0.07%) — the one detector
  where near-perfect proxies, exclusive or not, are genuinely absent at
  any meaningful volume.

**Task 3c's actual, defensible claim (per B3c), replacing the earlier
"exclusivity is minor everywhere" framing:** signature identity is a
legitimate near-perfect statistical predictor for *specific* rules within
Wazuh and AMiner (concentrated in one or a handful of high-ratio
signatures each), worthless for the rest, and for Suricata worthless
almost everywhere — **an aggregate F1/recall number conceals this
per-signature split.** For rule 31101 specifically, this project has
*already* established (not re-derived here — see
`newCol/fr_31101_report.md`, an existing prior audit) that this
statistical dominance is **not genuine attack detection**: *"URL/UA
information does not recover generalizable per-alert separability on
rule 31101. It recovers one kind of separability — exact User-Agent
identity — which is the same disease as rule-ID memorization at finer
grain, not detection, and which a real attacker defeats by setting one
HTTP header."* Rule 31101 is a real, previously-verified instance of "high
statistical ratio, worthless as a detector." Whether AMiner's dominant
signature (`New request method in Apache Access log.`) is the same kind
of case (tempo/volume artifact) or genuine anomaly signal has **not**
been separately verified in this audit — flagged as open, not claimed
either way, since no equivalent feature-recovery check has been run for
it.

---
**CHECKPOINT — B1–B3 complete, STOP before Task 4.**

---

# TASK 4 — Verdict and Fig 9

## 4a. Verdict: Partially generalizes — led by AMiner, bounded by one untested axis

**Headline result, stated first as instructed: an anomaly-based detector
with no rule database in Wazuh's sense reproduces the effect this paper
is built on.** AMiner's majority-label-per-signature lookup table —
34 signature names, zero engineered features, zero training in the
machine-learning sense — reaches **F1=0.977, recall=99.4%** on held-out
AMiner alerts (Task 1). This is not a Wazuh rule-engine artefact: AMiner
has no rules, no `rule.id`, no expert signatures at all — it has
statistical models that flag deviations from learned baselines, and
knowing only *which* deviation-type fired is almost enough to know
whether the alert is an attack. **This is the answer to the paper's
central anticipated objection** ("the findings may be an artefact of one
platform's rule engine"): the mechanism is not about rule engines,
because it appears in a detector with no rules.

Wazuh-native replicates too (recall 99.2%, F1 0.9960), consistent with
the manuscript's existing Wazuh-only findings and now independently
corroborated by a second, structurally different detector.

**Suricata, the one network-based detector available, does not show an
attack-side identity shortcut** — neither the lookup table (2.8% recall)
nor a full-feature audit-time retrain of the model on the same alerts
(4.3% recall, Addition A(a)) detects this population well. B1 established
this is a property of the alerts themselves (24 of 29 signatures are
majority-benign by ~43:1, carrying 99.9% of the population's volume), not
a broken test.

**On the shape of this boundary — stated as a hypothesis, not a
conclusion, per instruction:** we have exactly one network-based detector
in this audit. Framing the boundary as "host-based vs. network-based" —
as an earlier draft of this report did — asserts a placement effect from
a sample size of one, which is the same kind of over-generalization this
paper's central argument warns against when applied to Wazuh alone. The
defensible claim is narrower: **the identity-substitutes-for-detection
effect replicates across detection *paradigm* — one signature-based
detector (Wazuh) and one anomaly-based detector (AMiner), both
host-based — and the one network-based detector tested (Suricata) did
not show it.** Whether that is because Suricata specifically has a noisy
signature set in this dataset (B1: predominantly benign background
protocol chatter — TLS handshake/record oddities, generic DNS queries —
rather than attack-correlated events) or because network placement
generally produces this pattern is **not decidable from this audit**.
**The test that would settle it: repeat Tasks 1–3 on an additional
network-based detector** (e.g., a second network IDS/NIDS on the same or
comparable traffic) — which we do not have and, per the no-new-collection
rule, cannot add here.

**The strongest single number in this audit — the 99.2%→4.3% recall
contrast (Addition A(a)) — must be qualified at the point it is used,
not only in a threats-to-validity appendix:** it is measured on an
audit-time retrain of the model, not the deployed
`models_v2/xgb_model.pkl`, because that pickle is non-functional in this
environment (predict_proba capped at 0.059, entirely below the deployed
threshold 0.0754 — a version-mismatch artefact already diagnosed by
prior work, not newly discovered here). The retrain uses the same 26
features and the same eval split as the deployed model was meant to use,
and its own threshold is chosen by maximizing F1 on that same split
(0.3798), not the deployed `theta_xgb`. Any use of this contrast in the
paper (abstract, discussion, Fig 9) should carry this qualification
inline, e.g. "an equivalent audit-time retrain of the deployed model."

**B3's revision also belongs in the verdict, not just the mechanism
section**: within Wazuh, the 99.2% recall is substantially carried by
one rule (31101, ratio 6,137:1, 68.5% of Wazuh-native volume) that this
project has *already independently verified* is not genuine attack
detection but a memorization/tempo artefact defeated by a single HTTP
header (`newCol/fr_31101_report.md`). Within AMiner, 49.2% of volume
similarly rides on one dominant near-perfect signature (`New request
method in Apache Access log.`, ratio 373.5) whose status (genuine anomaly
signal vs. tempo/volume artefact, AMiner's own analogue of 31101) **has
not been separately verified** in this audit. **The verdict "AMiner
replicates the effect" should not be read as "AMiner's alerts are
therefore high-quality detections"** — it means AMiner's alert stream has
the same statistical shape (identity substitutes for detection, aggregate
metrics conceal per-signature heterogeneity) that this project has
already shown, for Wazuh specifically, to be at least partly a
memorization artefact rather than real capability. Whether AMiner's case
is the same kind of artefact is an open question this audit surfaces but
does not close.

**Verdict: Partially generalizes.** The identity-substitutes-for-detection
effect, and the more specific finding that aggregate lookup-table metrics
conceal a small number of dominant near-perfect proxy signatures riding
on otherwise weak per-signature signal, replicate across a signature-based
and an anomaly-based host detector. It does not replicate on the one
network-based detector tested, for reasons not yet isolated from this
detector's specific noise profile in this dataset. This is a paradigm
finding with an open placement question, not a closed platform finding
and not a closed paradigm-vs-placement finding either.

## 4b. Fig 9

Built: `newCol/figures_ms/fig9_cross_detector_lookup.{py,pdf,png}`.
Grouped bars, one group per detector (Wazuh-native, Suricata, AMiner),
lookup-table recall vs. model recall (audit-time retrain; explicitly
`n/a` for AMiner, not built per Task 1d). Source data read directly from
`newCol/xdet_task1_results.json` at plot time (no hardcoded values).
Added to `captions.md` and `sources.md` (see those files' new Fig 9
sections) following the existing short-printed-caption /
externalized-caveats / LaTeX-block convention used for Figs 1–8.

## 4c. Claim impact list

- **Fig 8's "cross-dataset" framing (AIT-ADS vs. Linux testbed) —
  DOES NOT SURVIVE as written.** Task 0 established both sides of that
  comparison are Wazuh-only (`ait_split.npz` is 100% Wazuh by
  construction; the Linux testbed collection is also Wazuh). Fig 8 must
  be restated as **cross-collection-within-Wazuh**, not cross-platform or
  cross-dataset. This XDET audit's Fig 9 is the paper's actual
  cross-detector evidence and should be positioned as the figure that
  does what Fig 8's caption previously implied.
- **The abstract's and title's unqualified use of "SIEM alert triage" —
  PARTIALLY STRENGTHENED, PARTIALLY NARROWED.** Strengthened: the central
  memorization/identity-substitution mechanism is no longer a
  single-vendor (Wazuh) claim — it independently replicates on AMiner, an
  anomaly-based detector with a completely different architecture,
  which is meaningfully broader support for a general "alert triage"
  claim than one rule-engine's output. Narrowed: the paper cannot yet
  claim the finding holds for network-based detection in general, or for
  signature-based network IDS specifically (Suricata, the one example
  tested, did not replicate it, for reasons not yet isolated) — any
  language claiming generality across "SIEM alert triage" without
  qualification should be scoped to *host-based* alert triage, or
  explicitly flagged as untested for network-based detection.
- **The transferability claim for the control set — NARROWED.** Any
  claim built on the deployed `xgb_model.pkl` transferring across
  populations should be re-examined: that artifact is non-functional in
  this environment (Addition A(a), also independently found by prior
  work in `fig1_lookup_vs_model.py`). Numbers attributed to "the deployed
  model" anywhere in the manuscript should be traced to confirm they
  were not silently computed from this broken pickle.
- **Threats-to-validity (Addition D, restated here since Task 4 is where
  claims get finalized):**
  1. The deployed feature pipeline encoded away the detector identity of
     ~11.8% of its AIT-ADS training data (rule 86601 collapses 29
     Suricata signatures to one `rule_id_encoded` value).
  2. The split loader (`phase1_xgboost.py:load_ait_ads`) reads only
     `*_wazuh.json`, structurally excluding AMiner from every AIT-ADS
     number in the manuscript prior to this audit.
  3. `models_v2/xgb_model.pkl` is non-functional in the current
     environment; every figure/number that assumes it is usable should
     be audited for this.
- **New, this audit:** the manuscript should add that within-detector
  heterogeneity (a small number of dominant, near-perfect proxy
  signatures carrying most of a detector's apparent performance,
  alongside many weak/uninformative ones) is itself a generalizable
  finding across Wazuh and AMiner (B3) — a more precise and more
  defensible claim than "detector identity predicts labels," which an
  aggregate F1/recall number conceals.

---
**CHECKPOINT — Task 4 complete. Verdict: Partially generalizes (AMiner
replicates strongly, Suricata does not, boundary not yet isolated to
paradigm vs. placement). STOP.**

---

# XDET-V CORRECTIONS — AMiner signature verification + 86601 numbers labelled

Two claims above were promoted or used before they were fully earned.
Both are now checked directly. **Neither reverses the Partially-generalizes
verdict, but both change how its supporting evidence must be described.**
Full detail: `newCol/xdet_aminer_signature_check.md`,
`newCol/xdet_86601_numbers.md`. This section corrects, does not delete,
Addition A and Task 4a above.

## Correction 1 — AMiner's dominant signature: fragile fingerprint, not memorization

Verified directly (`xdet_aminer_signature_check.md`): the 373:1 AMiner
signature (`AMiner: New request method in Apache Access log.`, 27,269
attack / 73 benign) **is distinguishable** on non-identity features — not
an unmeasurable or per-alert-indistinguishable case. But the separation
is carried entirely by **one exact User-Agent string**: every one of the
27,269 attack alerts is `WPScan v3.8.20 (...)` — a penetration-testing
tool announcing its own name in its default banner — with **zero**
User-Agent overlap against the 73 benign alerts (which are also
mostly, 82%, AMiner's own documented training-phase noise, not
steady-state traffic).

**This is the same mechanism this project already found for Wazuh rule
31101's Tier A** (`fr_31101_report.md`: *"the same disease as rule-ID
memorization at finer grain, not detection... trivially evadable by
setting one HTTP header"*) — narrow, exact-string identity matching, not
generalizable behavioral detection.

**Correction to Task 4a's wording, effective now**: replace *"whether
AMiner's dominant signature is genuine signal or an artefact... has not
been separately verified"* with the verified finding: **it is neither
cleanly a labelling artefact nor genuine generalizable detection — it is
a fragile, single-string tool-fingerprint match, the AMiner-schema
analogue of 31101 Tier A.** Correspondingly, **replace "memorization
replicates on an anomaly-based detector" with "the same narrow,
identity-driven, trivially-evadable separability pattern already found
for Wazuh replicates on an anomaly-based detector"** wherever the former
phrasing is used (Task 4a, Fig 9 caption — both updated). This is a
**more precise and, if anything, more interesting finding**: it shows
the *fragility pattern* generalizes across paradigms, which is a
different and better-supported claim than "detector identity predicts
labels" alone.

## Correction 2 — the 86601 contrast is suggestive, not a clean ablation

`xdet_86601_numbers.md` labels every number in the 99.2%→4.3% contrast
precisely (exact configuration, split, threshold source for each) and
identifies a confound Addition A did not flag clearly enough: **Wazuh-native
and Suricata-via-Wazuh are not the same alerts with identity added or
removed — they are two different populations from two different
detectors**, and only one of them (Suricata-via-Wazuh) has both (a)
collapsed identity and (b) B1's already-established weak intrinsic
signal (24/29 signatures majority-benign by ~43:1). **The
identity-preserving lookup table on this same population (Measurement 1,
`xdet_86601_numbers.md`) only reaches 2.8% recall — restoring identity
does not close the gap to Wazuh-native's 99.2%.** This is the key new
evidence: it points to population content (B1's weak-signal finding), not
identity collapse per se, as the larger contributor to the recall gap.

**Correction to Addition A's framing, effective now**: the
"causal, not correlational" language in Addition A(a) overstated what a
between-population comparison with an uncontrolled confound can show.
**Corrected claim**: identity collapse is real, verified, and measurable
(Task 0/B2), and recall is far lower on the affected population (both
measurements in `xdet_86601_numbers.md`) — but the identity-preserving
lookup table's own weak performance on the same population (2.8%) shows
identity collapse is a **compounding, secondary** defect, not the
**primary** explanation for the recall gap, which is better attributed to
this population's intrinsically weak signal (B1). Any manuscript use of
this contrast must state which configuration produced each number
(`xdet_86601_numbers.md` §a) and must not claim clean causal ablation
evidence.

## Net effect on Task 4's verdict

**The verdict itself is unchanged: Partially generalizes.** What changes
is the *character* of the supporting evidence: it is no longer "a clean
causal ablation (86601) plus an unverified-but-promising AMiner
replication" — it is now **two independently-verified instances of the
same narrow, fragile, identity/fingerprint-driven separability
mechanism (Wazuh 31101 Tier A and AMiner's WPScan signature), plus one
suggestive-but-confounded observational contrast (86601)**. This is a
less dramatic story than "identity collapse causes detection failure,
and memorization independently replicates on an anomaly detector" — but
it is the more defensible one, and it still fully supports the paper's
core generalization claim (the mechanism recurs across a signature-based
and an anomaly-based detector) without overclaiming causal proof the
data does not clean-ly provide.

---
**CHECKPOINT — XDET-V complete. STOP.**
