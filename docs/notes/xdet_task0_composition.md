# XDET Task 0 — Detector composition of our actual AIT-ADS holdings

All counts below were derived directly from the files on disk (raw JSON
line counts via `wc -l`, exact field parsing via `jq`, and cross-checks
against `AIT_alerts.csv`). No counts are assumed or carried over from
prior documentation. Commands are reproducible from `data/ait_ads/`.

## 0a. What detectors are actually present, at each stage

### Raw holdings: `data/ait_ads/raw/*.json` (and the identical `downloads/ait_ads.zip`)

16 files, 8 scenarios × 2 files/scenario:

| file pattern | present? | total alerts (sum of 8 scenarios) |
|---|---|---:|
| `*_wazuh.json` | yes | 2,600,263 |
| `*_aminer.json` | yes | 55,558 |
| `*_suricata.json` (standalone) | **no — does not exist** | 0 |

Per-scenario line counts (`wc -l`):

| scenario | wazuh | aminer |
|---|---:|---:|
| fox | 462,523 | 10,581 |
| harrison | 583,754 | 10,194 |
| russellmitchell | 41,488 | 4,056 |
| santos | 126,513 | 4,266 |
| shaw | 68,539 | 2,243 |
| wardbeck | 88,204 | 3,053 |
| wheeler | 603,939 | 12,222 |
| wilson | 625,303 | 8,943 |
| **total** | **2,600,263** | **55,558** |

There is no standalone Suricata export anywhere in our holdings (not in
`raw/`, not in the zip). However — important nuance found below — genuine
Suricata detections are *not entirely absent*; a large slice of them is
embedded inside the Wazuh JSON stream (§0b).

### `models_v2/ait_split.npz` (the file every downstream phase/model/figure uses)

```
X_train (2,080,210, 26)   y_train (2,080,210,)
X_test  (520,053, 26)     y_test  (520,053,)
```

Total rows: **2,600,263** — attack rate 66.05% (1,717,524 attack / 882,739 benign).

This total is **exactly equal** to the raw Wazuh line count above
(2,600,263) and has **zero** overlap with the AMiner total. Traced to
source: `phase1_xgboost.py:load_ait_ads()` (called at `phase1_xgboost.py:151`,
which is the only code path that produces `ait_split.npz`, written at
`phase1_xgboost.py:201-206`):

```python
files = sorted(glob.glob(os.path.join(raw_dir, "*_wazuh.json")))   # line 93
```

The loader's file glob is **hardcoded to `*_wazuh.json`**. It never opens
an `*_aminer.json` file. This is not a downstream filter, a null-mapping,
or a label-based exclusion — the AMiner files are simply never read by
the function that builds the split. The row-count identity above (raw
Wazuh lines == `ait_split.npz` rows, to the alert) confirms every single
line that was read made it into the split with no additional loss.

**Composition of `ait_split.npz`: 100.00% Wazuh-sourced JSON, 0% AMiner,
0% Suricata (standalone).**

## 0b. Explaining "93 documented signatures" vs "31 rule IDs" — with a mechanism, not a guess

Re-derived independently (not trusting `ait_ads_seen_all.txt` at face
value) with `jq '.rule.id'` streamed over all 8 `*_wazuh.json` files:
**31 distinct rule IDs**, identical to the set already in
`ait_ads_seen_all.txt`. So that file is current and accurate for what it
measures — Wazuh's own `rule.id` namespace.

Pulling `(rule.id, rule.description)` pairs for all 31 IDs surfaced the
mechanism directly:

| rule.id | description | alert count |
|---|---|---:|
| 2501–80730 (30 IDs) | genuine Wazuh host-based rules (auth, sudo, PAM, Apache 4xx/5xx, Dovecot, ClamAV, SELinux, CMS brute force, etc.) | 2,293,628 |
| **86601** | **`Suricata: Alert - <varies>`** | **306,635** |

Rule 86601 is Wazuh's generic ingestion wrapper for Suricata's `eve.json`
output (Wazuh forwards Suricata alerts through its own pipeline and
re-emits them under one rule ID). Pulling `rule.description` specifically
for `rule.id==86601` gives **29 distinct strings** — e.g. `SURICATA TLS
invalid handshake message`, `ET SCAN Possible Nmap User-Agent Observed`,
`ET POLICY GNU/Linux APT User-Agent Outbound...`, `ET INFO Suspicious
Domain (*.ga) in TLS SNI` — which is the actual Suricata signature
identity. **These 29 strings are an exact match to the "29 Suricata"
figure in the dataset documentation cited in the task brief.**

Cross-check against `data/ait_ads/AIT_alerts/AIT_alerts.csv` (a
separately-held, pre-extracted, already-labeled artifact covering the
same 8 scenarios — see provenance note below) confirms this reading
exactly:

| detector (AIT_alerts.csv `name` prefix) | rows | distinct `name` values |
|---|---:|---:|
| Wazuh | 2,293,628 | 30 |
| Suricata | 306,635 | 29 |
| AMiner | 55,558 | 34 |
| **total** | **2,655,821** | **93** |

Every one of these numbers reconciles exactly with independently-derived
counts from our raw files:
- `2,293,628` = raw Wazuh lines minus rule-86601 lines (2,600,263 − 306,635)
- `306,635` = raw Wazuh lines with `rule.id == 86601`
- `55,558` = raw AMiner line count (`wc -l data/ait_ads/raw/*_aminer.json`)
- `34` = distinct `AnalysisComponent.AnalysisComponentName` values, independently
  re-derived via `jq` over the raw AMiner files (not taken from AIT_alerts.csv)
- Per-scenario row totals in AIT_alerts.csv equal raw-wazuh + raw-aminer
  for that scenario, exactly, in all 8 scenarios (e.g. wilson: 625,303 +
  8,943 = 634,246 = AIT_alerts.csv wilson row count)

So **93 = 30 + 29 + 34 is the correct, fully verifiable signature count
for the data we hold** — we were never missing Suricata's underlying
signal, only failing to read/parse it as distinct signatures.

**Candidate explanations, evaluated against these numbers:**

1. *"the split was filtered to Wazuh alerts only"* — **CONFIRMED**, and
   sharper than "filtered": AMiner was never opened at all (glob excludes
   it categorically, not via a post-hoc filter). Suricata was never held
   as a standalone export at all.
2. *"non-Wazuh alerts present but signature field maps to null/default,
   collapsing them"* — **PARTIALLY TRUE, but only for the Suricata slice
   that is embedded inside the Wazuh stream itself.** `rule_id_encoded`
   (`shared_features.py:_rule_id_encoded`, `float(rule.id)`) maps all 29
   distinct Suricata signatures under rule 86601 to the single numeric
   value `86601.0` — a real collapse, but it happens *within* what we are
   calling "Wazuh" alerts, not as a mechanism that lets true AMiner rows
   in under a null value. AMiner rows are not collapsed; they are absent.
3. *"Wazuh dominates by volume"* — not the operative explanation; Wazuh
   isn't dominant, it's exclusive in `ait_split.npz`. (Within the Wazuh
   stream, rule 31101 alone is 1,571,313 / 2,600,263 = 60.4% of all rows —
   the pre-existing 31101 volume/memorization finding from prior audits —
   but that is orthogonal to the detector-composition question.)

So the true count of **31** in `ait_ads_seen_all.txt` decomposes as
**30 genuine Wazuh signatures + 1 ID (86601) that is actually a
29-signature-wide Suricata bucket collapsed to one value.** The 93 vs 31
gap is not a data availability problem — the AMiner and Suricata signal
we need is present in files we already hold — it is a scope/encoding
limitation of the pipeline that built `ait_split.npz` and the
`rule_id_encoded` feature.

## 0c. Data-handling defect — stated plainly

**Yes, this is a defect in our own pipeline, not a property of the
dataset, and it must be reported in the paper regardless of what Tasks
1–3 find.**

`phase1_xgboost.py:93` (`load_ait_ads`, the sole builder of
`ait_split.npz`) reads only `*_wazuh.json`. Every AIT-ADS number in the
manuscript — training, evaluation, and specifically the Fig 8
"cross-dataset" comparison — is built on a feature pipeline that:

- never reads the 55,558 AMiner (anomaly-detector) alerts that are
  sitting in `data/ait_ads/raw/*_aminer.json` on disk;
- never separates the 306,635 Suricata-origin alerts (29 signatures)
  that are present but folded into a single Wazuh rule ID via
  `rule_id_encoded = float(rule.id)`.

This was not caught earlier because `ait_ads_seen_all.txt` /
`ait_ads_seen_rules.txt` (used throughout prior audits, e.g.
`check_rule.py`, `newCol/f1_phaseB_win.py`, `newCol/verify_labels_lnx.py`)
is explicitly documented as a "Wazuh rule ID" vocabulary — correct for
what it claims to be — but nothing upstream of it flagged that this
vocabulary was the *entire* AIT-ADS training signal, rather than one of
three detector streams.

## 0d. Label field and labelling method

**Our own pipeline** (`phase1_xgboost.py:load_ait_ads`, lines 130–145)
labels purely by time window: it loads `data/ait_ads/labels.csv`
(columns `scenario, attack, start, end` — 78 labeled windows across the
8 scenarios, confirmed by direct read) and assigns `label=1` to any alert
whose epoch timestamp falls inside the nearest preceding window's
`[start, end]` via `pd.merge_asof(..., direction="backward")`. This
matches the task brief's understanding: **our working label is purely
time-window derived, with no per-event ground truth used.**

**On quoting the dataset authors directly:** we searched `Sources/*.pdf`
(no AIT-LDS/AIT-ADS/Landauer/Skopik hits in any bundled PDF) and the
`data/ait_ads/` tree (no README, no paper, no docs bundled with the
raw/zip download — confirmed via `find`). **We do not hold the original
AIT-ADS/AIT-LDS paper or documentation text locally, so no verbatim
quote can be produced without fabricating one.** This is stated plainly
per the no-fabrication rule rather than inventing a citation.

What we *can* do is demonstrate the phenomenon the task brief describes
(delays, false positives, overlaps as a consequence of time-window
labelling) empirically, using the dual-labelled `AIT_alerts.csv` artifact
already in our holdings, which independently assigns each alert both an
`event_label` (fine-grained, presumably derived from AIT-LDSv2's
per-line ground truth, used when available) and a `time_label` (pure
window membership, used as fallback):

| `label_source` | rows |
|---|---:|
| `event_label` (preferred) | 1,817,250 |
| `time_label` (fallback) | 838,571 |

`time_label` alone assigns 891,240 alerts the tag `false_positive` even
though `time_label` is purely a function of falling inside a labeled
attack scenario's overall span — i.e., under pure time-window logic a
large fraction of alerts occurring during an attack scenario's wall-clock
duration are still not attributable to the attack and must be tagged
false-positive by the window method itself. Comparably, `time_label`
counts `dirb`=1,691,090 vs `event_label` `dirb`=1,688,945 — a 2,145-alert
delta consistent with event/window misalignment (delay/overlap) at the
boundaries of the same nominal category. This is exactly the kind of
window-vs-event slippage the task brief anticipated, demonstrated from
data we hold, in lieu of a textual citation we don't have.

**Caveat for later tasks:** `AIT_alerts.csv`'s labelling convention
(event_label-preferred, time_label-fallback) is *not the same
methodology* as our own pipeline's pure time-window labels.csv approach.
If Tasks 1–3 use `AIT_alerts.csv` as the source for Suricata/AMiner rows
(the only route to those detectors without new collection), the fairest
comparison is to **re-derive all three detectors' labels ourselves from
`labels.csv` via the same merge_asof time-window method already used for
Wazuh**, rather than importing `AIT_alerts.csv`'s own label column. This
keeps "same temporal split discipline used elsewhere" honest across
detectors and avoids silently mixing two label conventions in one
comparison table. Recommend building Suricata rows from the rule-86601
subset of `*_wazuh.json` (keyed on `rule.description`, 29 signatures) and
AMiner rows from `*_aminer.json` (keyed on
`AnalysisComponent.AnalysisComponentName`, 34 signatures), both re-labeled
via `labels.csv` exactly like the existing Wazuh loader — not by
consuming `AIT_alerts.csv`'s `label` column directly.

## Summary table

| | Wazuh | Suricata | AMiner |
|---|---:|---:|---:|
| Documented signature count | 30 | 29 | 34 |
| Present in raw holdings? | yes (`*_wazuh.json`) | yes, embedded (`rule.id==86601` subset of `*_wazuh.json`) | yes (`*_aminer.json`) |
| Signal collapsed in current pipeline? | no | **yes — 29→1 via `rule_id_encoded`** | n/a — never read |
| Alerts available (this session, verified) | 2,293,628 | 306,635 | 55,558 |
| Rows in `models_v2/ait_split.npz` | 2,600,263 (incl. the 306,635 Suricata-via-Wazuh rows, undifferentiated) | 0 (as distinct signal) | 0 |

**Bottom line for Task 0:** the manuscript's AIT-ADS results, and by
extension Fig 8's "cross-dataset" framing, are Wazuh-only not because
Suricata/AMiner signal is unavailable to us, but because the feature
pipeline that produced `ait_split.npz` only reads `*_wazuh.json` and
further collapses the one Suricata slice that leaks through into a
single undifferentiated rule ID. All three detectors' underlying alert
records are present in files we already hold (no new collection
required) and can be reconstructed with the same time-window labelling
discipline used elsewhere. This is the basis for Tasks 1–3.

---
**CHECKPOINT — STOP.** Awaiting go-ahead before building the
per-detector lookup tables (Task 1), rate thresholds (Task 2), and
labelling-artefact check (Task 3), which require materializing the
Suricata (rule-86601 subset) and AMiner alert streams as described above.

---

## UPDATE (post-checkpoint, supersedes §0d's "no documentation found" claim)

Go-ahead received to proceed to Tasks 1–3, along with the citation
`landauer_introducing_2024` (Landauer, Skopik, Wurzenberger, "Introducing
a New Alert Data Set for Multi-Step Attack Analysis," CSET '24). Rather
than take the citation on faith, it was independently retrieved and read
in full (arXiv:2308.12627, verified real via `WebSearch` — DOI
`10.1145/3675741.3675748` — and fetched directly). **This is the AIT-ADS
dataset paper Task 0d said we did not hold.** It is now added as
`NET_SEC.bib:landauer_introducing_2024` (no `.bib` file existed anywhere
in the project before this — confirmed by a full filesystem search; the
brief's assumption of a pre-existing `landauer_dealing_2022` entry in
`NET_SEC.bib` could not be verified and is explicitly not relied upon —
see the note at the top of `NET_SEC.bib`).

Reading the actual paper text resolves §0d's citation gap and
independently corroborates essentially every number in this report:

- **"Table 1 summarizes all 93 unique detector signatures (34 from
  AMiner, 29 from Suricata, and 30 from Wazuh)."** — exact match to the
  30+29+34 breakdown this report derived from raw files, computed before
  this citation was found.
- **"Across all scenarios, the total number of alerts is 2,655,821, where
  2,293,628 (86.4%) origin from Wazuh, 306,635 (11.5%) from Suricata, and
  55,558 (2.1%) from AMiner."** — exact match, to the alert, with this
  report's independently-derived counts (§0a/§0b).
- **The Suricata-via-Wazuh mechanism this report reverse-engineered from
  rule 86601 is independently confirmed by the paper's own description of
  data collection**: *"Suricata... The authors of the AIT-LDSv2 already
  deployed Suricata on the servers in the network. Accordingly, Suricata
  alerts are already available in the data set and can be conveniently
  collected by Wazuh."* (Sect. 3.1.2). This is not our pipeline's
  invention — it is how the dataset's own authors collected Suricata
  alerts in the first place, which is exactly why Suricata detections
  appear inside our `*_wazuh.json` files under rule 86601.
- **Labelling method, quoted directly (replaces the empirical-only
  argument in the original §0d):** *"Since the alerts are generated from
  a synthetic and labeled log data set, we are also able to provide
  labels for attack phases based on alert occurrences"* (Sect. 6); and,
  more precisely on the limitation: *"we emphasize that counting is only
  based on the alert timestamp, i.e., the counts for a detector represent
  how many alerts it produces in the respective time interval **without
  validating that the alert is actually a direct consequence of an
  attack**"* (Sect. 4.1, emphasis added). The paper also states plainly
  that this produces exactly the false-positive-by-construction effect
  Task 0d anticipated: *"several detectors report a high number of false
  positives, i.e., alerts occurring outside of the attack time windows.
  We point out that referring to these alerts as false positives may be
  misleading; the detectors correctly report these events as expected, it
  is just the case that the events themselves do not correspond to any
  activities related to the attacks in the context of these scenarios."*
  (Sect. 3.2.1).
- **Correction to the brief's characterization:** the brief described the
  paper as "listing delays, false positives, and overlaps" as labelling
  problems. Having now read the full text, **"false positives"** is
  extensively and explicitly documented (quoted above) and **"delays"**
  is consistent with the timestamp-only-counting limitation quoted above,
  but the literal word **"overlaps"** does not appear describing a
  labelling defect in this paper — the closest related passage is in
  future-work discussion (Sect. 6), proposing that *later* data sets
  should add *more* overlapping attack phases for extra difficulty, which
  is the opposite point (this dataset has relatively little attack-phase
  overlap, not a documented problem with overlap-induced mislabelling).
  Stated plainly rather than silently importing the brief's framing.
- **The AMiner training-phase false-positive caveat used in Task 2c below
  is independently confirmed verbatim**: *"almost all AMiner detectors
  report multiple false positives in the first half of the first day of
  each scenario, which is the result of training the models... that are
  still incomplete and not representative for the system behavior at this
  point"* (Sect. 3.2.1).
- **Independent external validation of this audit's Task 2 finding for
  Suricata** (see `xdet_results.md`): the paper's own per-detector
  robustness/detection scoring (Table 2, Sect. 4.1) flags Suricata
  detectors like `S-Tls-Hnd` (= our `SURICATA TLS invalid handshake
  message`, part of rule 86601) as contributing little to detection
  because they *"involve similar alert rates for phases of attack and
  normal behavior"* — independently reaching the same conclusion this
  audit reaches from raw timestamps in Task 2.
