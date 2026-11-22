# LBL — AIT-ADS Label Provenance

Inspection only: no fabrication, no new collection, no retraining. Nothing
in `models_v2/`, `thresholds_*.json`, or any existing artifact was
modified. Scripts: `newCol/lbl_signature_exclusivity.py` (Task 2c; raw
output `newCol/lbl_signature_exclusivity.log`). All other numbers below
are read directly from `data/ait_ads/labels.csv` and from the already-built
label sources `newCol/xdet_wazuh_recovered_split.npz` /
`newCol/xdet_aminer_split.npz`, whose own provenance is traced in full in
Task 1e — nothing is taken on the strength of a prior report's summary
alone.

## Task 1 (gate)

### a. Location, size, columns, example rows

`data/ait_ads/labels.csv` — 3,703 bytes, **78 data rows** (79 lines
including header). Full column list (there are only four; nothing else in
the file):

```
scenario,attack,start,end
```

Representative rows (first 10, verbatim):

```
scenario,attack,start,end
russellmitchell,network_scans,1642993260.0,1642996606.0
russellmitchell,service_scans,1642996606.0,1642996645.0
russellmitchell,dirb,1642996645.0,1642996668.0
russellmitchell,wpscan,1642996668.0,1642996699.0
russellmitchell,webshell,1642996699.0,1642996762.0
russellmitchell,cracking,1642996762.0,1642999016.0
russellmitchell,reverse_shell,1642999016.0,1642999059.0
russellmitchell,privilege_escalation,1642999059.0,1642999093.0
russellmitchell,service_stop,1643032238.0,1643032240.0
```

`start`/`end` are Unix epoch floats. Rows per scenario: 10 each for
fox/harrison/russellmitchell/santos/shaw/wardbeck/wilson, 9 for wheeler
(78 total) — one interval per named attack phase within each of the 8
scenarios.

### b. Detector scope

**No detector field exists in the file at all** — the four columns above
are the complete schema. So detector scope cannot be read off a column;
it has to be established by whether the file's time windows actually join
to alerts from more than one detector, which was tested directly rather
than assumed:

| detector | alerts | attack (labelled via `labels.csv` join) | benign | attack rate |
|---|--:|--:|--:|--:|
| Wazuh-native (`rule.id != 86601`) | 2,293,628 | 1,711,506 | 582,122 | 74.62%\* |
| Suricata (`rule.id == 86601`, keyed by `rule.description`) | 306,635 | 6,018 | 300,617 | 1.96% |
| AMiner (keyed by `AnalysisComponentName`) | 55,558 | 47,062 | 8,496 | 84.70% |

\*Wazuh-native's 74.62% figure above is computed directly from this
task's own rerun of the exclusivity script (`n_alerts=2,293,628,
attack_rate=0.7462`, exact counts summed from its per-signature output);
it differs from the 66.05% headline figure elsewhere in this response
because that headline figure is for **all** Wazuh rows including rule
86601, while this row isolates Wazuh-native only.

**All three detectors get non-degenerate, non-trivial attack/benign
splits from the identical `labels.csv` time-window join** (§e traces the
exact code path for each). This directly answers (b): `labels.csv` is not
restricted to Wazuh by content or by construction — it is a
scenario-and-time index that applies to whichever detector's alert stream
happens to share that scenario's timeline, which is all three. The
apparent "Wazuh-only" impression in earlier work came from `phase1_xgboost.py`'s loader hardcoding its file glob to `*_wazuh.json`
(documented in the prior XDET audit, `newCol/xdet_task0_composition.md`
§0a) — a restriction in **our pipeline's use** of the file, not a
restriction **in the file**.

### c. Labelling mechanism

**Time-window intervals, joined to alerts by timestamp — the second
option in the task brief, not per-alert.** Quoting the schema again since
it is the whole answer: `scenario, attack, start, end`, where `start`/
`end` are Unix-epoch bounds of a named attack phase (e.g.
`russellmitchell, network_scans, 1642993260.0, 1642996606.0`). There is
**no join key to an individual alert or log line** anywhere in the file —
no alert ID, no line number, no hash, no per-event field of any kind. An
alert is labelled attack (1) iff its own timestamp falls inside `[start,
end]` for some row sharing its scenario; every alert in that window gets
the same label regardless of whether it is actually related to the named
attack, and every alert outside all windows for its scenario is benign by
default. This is coarse by construction, not by an implementation
shortcut — there is nothing finer to recover from this file.

### d. What the dataset paper says, from local holdings only

**We hold no local copy of the AIT-ADS dataset paper (Landauer, Skopik,
Wurzenberger, "Introducing a New Alert Data Set for Multi-Step Attack
Analysis," CSET '24, DOI 10.1145/3675741.3675748).** Checked directly for
this task, not inferred from memory: every PDF in `Sources/` was opened
and its first-page text extracted — the set is `IEEE Xplore Full-Text
PDF-.pdf` / `getPDF.jsp.pdf` (both DeepCASE), `main.pdf`/`main 1-5.pdf`
(AlertPro, CyberShapley, and three other unrelated Computers & Security /
Elsevier papers), `ndss2019_...UlHassan_paper.pdf` (NoDoze), `sec22-
alahmadi.pdf`, `soups2025-kramer.pdf` — none is the AIT-ADS paper. No
other PDF or text copy of it exists anywhere else in this project
directory (`data/ait_ads/` holds only `labels.csv`, the raw JSON, and
`AIT_alerts.csv` — no paper, no README). Per the task's instruction to
say so rather than infer, that is the full answer for this task.

(Context, not a substitute for the above: a prior session's report,
`newCol/xdet_task0_composition.md`, states it retrieved and read this
paper via a live web fetch — not a local copy — and quotes it describing
labelling as "based on alert occurrences" with an explicit "counting is
only based on the alert timestamp... without validating that the alert is
actually a direct consequence of an attack" caveat. That is consistent
with what §c finds independently from the raw file's own schema, but this
task was asked specifically about local holdings, so it is reported here
as an unverified secondary reference, not re-fetched or re-relied-upon.)

### e. How our pipeline actually obtained every label in use

Traced to the exact script and field for each of the four label sources
named in the task brief — this is the part that matters most, so each is
shown with its concrete join code, not just named:

| source | script | mechanism | from `labels.csv`? |
|---|---|---|---|
| `models_v2/ait_split.npz` (L1 training split) | `phase1_xgboost.py:load_ait_ads`, lines 130–145 | `pd.merge_asof(sub, windows, on="epoch", direction="backward")` per scenario, `label=1` iff `epoch <= end` | **Yes** — directly |
| XDET Wazuh-native subset | `newCol/xdet_recover_wazuh_split.py`, lines 71–85 | identical `merge_asof` block, same file, applied to the full recovered Wazuh stream (native + rule 86601) | **Yes** — directly, byte-identical join logic to the loader above (this script's own internal assertion additionally confirms its recovered `y_train`/`y_test` match `ait_split.npz` exactly) |
| XDET Suricata subset (rule 86601) | same `newCol/xdet_recover_wazuh_split.py` output, filtered to `rid_all==86601` in `newCol/xdet_task1_lookup.py` | same `y_all` array as the row above — Suricata rows are a subset of the same Wazuh JSON stream, so they receive the identical `merge_asof` label as every other row in that stream, no separate join | **Yes** — via the row above, same mechanism |
| XDET AMiner subset | `newCol/xdet_build_aminer.py`, lines 74–88 | independently re-implements the identical `merge_asof` block against `data/ait_ads/labels.csv`, applied to `*_aminer.json`'s own epoch field (`LogData.DetectionTimestamp`, script lines 27–35) | **Yes** — directly, same file, own timestamp field |

**No label used anywhere in this response's Wazuh, Suricata, or AMiner
results comes from `AIT_alerts.csv`'s own `label`/`event_label` column, or
from any source other than `data/ait_ads/labels.csv`.** (`AIT_alerts.csv`
exists in our holdings and carries its own, differently-derived labels —
flagged as a *not-used* alternative in prior work — but it was not the
source for any of the four splits above; confirmed by reading each
script's actual load path, not assumed from the filename.)

### Gate check

- Condition 1 ("`labels.csv` covers only Wazuh alerts"): **false** — §b
  shows non-degenerate joins to all three detectors from the one file.
- Condition 2 ("XDET Suricata/AMiner labels came from a source other than
  `labels.csv`, or their source cannot be determined"): **false** — §e
  traces both to the identical `labels.csv` merge_asof join, in code,
  for every one of the four sources named in the brief.

**Neither gate condition holds. Proceeding to Task 2.**

---

## Task 2

### a. Labelling mechanism, for the manuscript's methodology section

AIT-ADS ground-truth labels originate from `data/ait_ads/labels.csv`, a
78-row table of `(scenario, attack, start, end)` intervals giving the
Unix-epoch start and end time of each named attack phase within each of
the dataset's 8 independent testbed scenarios. Every alert — regardless
of which of the dataset's three underlying detectors (Wazuh, Suricata, or
AMiner) produced it — is labelled attack (1) if its own event timestamp
falls within `[start, end]` of any interval sharing its scenario, and
benign (0) otherwise; the join is performed per scenario via a
backward-direction as-of merge on epoch time (`pandas.merge_asof(...,
direction="backward")`), with no per-alert or per-log-line ground truth
involved at any stage.

### b. Is the manuscript's current claim accurate?

**Accurate, not merely "partly."** The manuscript's related-work claim —
that AIT-ADS labels are time-window derived from a known attack schedule,
with the attendant risk of delays, false positives, and label overlaps at
window boundaries — is exactly what Task 1c/1e establish from the file
itself and from every script that consumes it: there is no per-alert or
per-log-line join key anywhere in `labels.csv`, and all four traced label
sources (L1 training split, XDET Wazuh-native, Suricata, and AMiner) use
the identical coarse time-window join. **The related-work argument built
on this — that a detection identifier firing only inside attack windows
becomes a label proxy by construction of the labelling — is correct as
stated and does not need to be revised.** If anything, this task
strengthens that argument rather than weakening it: it was previously
resting on a secondary source's characterization of the labelling method;
it now rests on this project's own direct inspection of the file and of
every consuming script, confirmed independently rather than inherited.
Recommend updating the citation from "reportedly time-window labelled" to
a direct methods-section statement citing `labels.csv`'s own schema
(quoted in Task 1a/1c above), since that is now the stronger source.

### c. Per-detector signature exclusivity — the measurement that decides whether the label-proxy argument survives

Computed fresh for this task (`newCol/lbl_signature_exclusivity.py`),
using the same three label sources traced in Task 1e, at the signature
granularity each detector actually operates on (`rule.id` for
Wazuh-native, `rule.description` for the 29 Suricata signatures embedded
under rule 86601, `AnalysisComponentName` for AMiner):

| detector | n signatures | attack-only sigs | alerts covered | benign-only sigs | alerts covered | mixed sigs | alerts covered |
|---|--:|--:|--:|--:|--:|--:|--:|
| Wazuh-native | 30 | 8 | 127,146 (5.54%) | 4 | 238 (0.01%) | 18 | 2,166,244 (94.45%) |
| Suricata | 29 | 5 | 201 (0.07%) | 17 | 337 (0.11%) | 7 | 306,097 (99.82%) |
| AMiner | 34 | 0 | 0 (0.00%) | 7 | 350 (0.63%) | 27 | 55,208 (99.37%) |

**The label-proxy argument survives, but only for a small, identifiable
minority of signatures in each detector — the manuscript should state it
at this precision, not as a blanket claim.** Reading this table straight:

- **Wazuh-native** has the strongest proxy effect of the three: 8
  signatures (led by rule 31101, 121,794 attack alerts, and rule 31151 —
  the pre-existing memorization-audit finding) are attack-only, covering
  5.54% of Wazuh-native volume outright. But **94.45% of Wazuh-native
  alert volume sits on signatures that fire on both classes** — rule
  31101 by itself (1,571,057 attack / 256 benign, in the *mixed* table
  because 256 benign alerts exist) dominates the mixed bucket, meaning
  the dominant memorization signal is not "this rule is attack-only," it
  is "this rule is overwhelmingly one-sided but not perfectly so" — a
  distinction the manuscript should preserve, since a perfectly
  attack-only rule is a different (stronger, more mechanical) claim than
  a 99.98%-one-sided rule.
- **Suricata** is the weakest case for the proxy argument: only 5 of 29
  signatures are attack-only, covering a trivial 201 alerts (0.07% of
  Suricata volume); 99.82% of Suricata alerts fire on signatures seen in
  both classes, and the two highest-volume Suricata signatures (TLS
  invalid record/handshake, ~105k alerts each) are only ~2.2–2.3%
  attack — the opposite of a label proxy, closer to noise uncorrelated
  with the label.
- **AMiner has zero attack-only signatures.** Every one of its 34
  signatures fires on at least one benign alert; 99.37% of AMiner volume
  is on mixed signatures, and the remaining 0.63% is **benign-only**, not
  attack-only — the opposite direction from a label-proxy risk. This is
  the detector where the manuscript's proxy argument, if applied
  uncritically to "AIT-ADS" as a whole, would be most clearly overstated.

**Net effect on the manuscript's claim:** the mechanism (time-window
labelling creates identifier-as-proxy risk) is confirmed and should stay.
But the magnitude is detector-specific and concentrated in a handful of
Wazuh rules (chiefly 31101, already the subject of this response's Task 1
memorization analysis, and 31151, 30305, 31516, 31104), not a
dataset-wide property — Suricata and AMiner, which make up 13.6% of
AIT-ADS's total alert volume, show little to no exploitable proxy signal
by this same measurement. The manuscript should scope the "detection
identifiers as label proxies" claim to the specific Wazuh rule set it
demonstrably applies to, rather than to AIT-ADS as a whole, since this
task's own numbers show it does not generalize evenly across the
dataset's three detectors.

---

**Artifacts:** `newCol/lbl_signature_exclusivity.py` (script, read-only),
`newCol/lbl_signature_exclusivity.log` (full per-signature tables for all
three detectors, referenced but not fully reproduced above for length).

**CHECKPOINT — STOP.**

---

## SUPERSEDING NOTE (PURITY-V Task 1 — §2c's binary partition replaced, nothing above deleted)

§2c's exclusive/mixed partition used **purity == 1.0** (zero exceptions)
as its only threshold for "exclusive." That criterion is too strict: rule
31101 (1,571,057 attack / 256 benign, 99.98% attack, 68.5% of
Wazuh-native volume) fell into "mixed" solely because 256 benign alerts
exist, which is why §2c reported "94.45% of Wazuh-native volume sits on
mixed signatures" — true under that definition, but it buried the single
most one-sided rule in the corpus.

**Replaced with a volume-weighted purity distribution** (per-signature
purity = max(attack-share, benign-share); full bands, top-5 tables, and
the replacement manuscript paragraph: `newCol/purity_verify.md` Task 1).
**Headline correction — the label-proxy exposure figure (purity ≥ 0.99
share of volume) that should be cited going forward:**

| detector | §2c's figure (attack-only, purity==1.0) | corrected figure (purity ≥ 0.99) |
|---|--:|--:|
| Wazuh-native | 5.54% | **74.09%** |
| AMiner | 0.00% | **53.05%** |
| Suricata | 0.07% | 0.18% (essentially unchanged) |

**§2c's qualitative recommendation — "scope the label-proxy claim to a
handful of Wazuh rules" — is confirmed and sharpened, not weakened:**
under purity, Wazuh-native's exposure is carried by essentially two rules
(31101 + 31151, 99.6% of the exposed volume) and AMiner's by essentially
one (`AMiner: New request method in Apache Access log`, 92.8% of its
exposed volume) — even more concentrated than "a handful" implied. What
was wrong was the **magnitude**, understated by more than an order of
magnitude for two of the three detectors, not the scoping logic itself.
Any manuscript text citing the old 5.54%/0%/0.07% figures must be updated
to the purity-based numbers above; the underlying recommendation to name
specific carrying rules rather than describe AIT-ADS/Suricata/AMiner as
uniformly exposed stands as originally written.

Full derivation, per-band volume tables, top-5-by-volume tables for all
three detectors, and the drafted replacement wording for the
manuscript's `%% PURITY %%` paragraph: `newCol/purity_verify.md` Task 1.
Script: `newCol/purity_task1.py` (read-only over
`newCol/xdet_wazuh_recovered_split.npz` and
`newCol/xdet_aminer_split.npz` — the same already-verified label sources
§1e traced; no new collection, no retraining).

**CHECKPOINT — STOP.**
