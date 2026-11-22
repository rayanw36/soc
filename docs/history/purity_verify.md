# PURITY-V — Purity Restatement + Final Verification

Standing rules observed: no fabrication, no new collection, no retraining
of deployed models. `models_v2/*` untouched. Script:
`newCol/purity_task1.py` (Task 1; output `newCol/purity_task1_results.json`).
Tasks 2–5 are verification/inspection only, against artifacts already on
disk — no new computation beyond direct recomputation from committed CSVs
(`labeled_win.csv`, `labeled_lnx.csv`), used to independently confirm
figures rather than take a prior summary's word for them.

---

## Task 1 — Volume-weighted purity restatement

Full per-detector bands, exposure figures, and top-5 tables:
`newCol/purity_task1_results.json`. A superseding note (not an in-place
edit) has been appended to `newCol/lbl_provenance.md` — see that file's
new final section.

### a. Purity-band volume distribution, per detector

| band | Wazuh-native (n=2,293,628) | Suricata (n=306,635) | AMiner (n=55,558) |
|---|--:|--:|--:|
| = 1.0 (exclusive) | 5.55% (12 sigs) | 0.18% (22 sigs) | 0.63% (7 sigs) |
| [0.99, 1.0) | 68.54% (2 sigs) | 0.00% (0 sigs) | 52.42% (2 sigs) |
| [0.95, 0.99) | 25.85% (9 sigs) | 99.82% (6 sigs) | 28.31% (10 sigs) |
| [0.90, 0.95) | 0.02% (1 sig) | 0.00% (0 sigs) | 3.74% (4 sigs) |
| [0.75, 0.90) | 0.04% (4 sigs) | 0.00% (1 sig, 12 alerts) | 14.51% (7 sigs) |
| < 0.75 | 0.00% (2 sigs, 80 alerts) | 0.00% (0 sigs) | 0.39% (4 sigs) |

### b. Label-proxy exposure (purity ≥ 0.99)

| detector | exposure (purity ≥ 0.99) |
|---|--:|
| **Wazuh-native** | **74.09%** (1,699,375 / 2,293,628) |
| **AMiner** | **53.05%** (29,473 / 55,558) |
| **Suricata** | **0.18%** (538 / 306,635) |

This is the figure the manuscript should cite in place of the old binary
exclusivity partition's 5.54%/0%/0.07% (attack-only-exposure) numbers —
those undercounted by construction, since they excluded every signature
with even one alert of the minority class, however small.

### c. Top 5 signatures by volume, per detector

**Wazuh-native:**

| rank | signature | n | purity | direction |
|--:|---|--:|--:|---|
| 1 | 31101 | 1,571,313 | 0.9998 | attack-leaning |
| 2 | 20101 | 295,032 | 0.9805 | benign-leaning |
| 3 | 9701 | 276,855 | 0.9749 | benign-leaning |
| 4 | 31151 | 121,794 | 1.0000 | attack-leaning |
| 5 | 52507 | 8,407 | 0.9831 | benign-leaning |

**Suricata:**

| rank | signature | n | purity | direction |
|--:|---|--:|--:|---|
| 1 | SURICATA TLS invalid record/traffic | 105,043 | 0.9773 | benign-leaning |
| 2 | SURICATA TLS invalid handshake message | 105,016 | 0.9776 | benign-leaning |
| 3 | ET INFO Observed DNS Query to .biz TLD | 91,761 | 0.9889 | benign-leaning |
| 4 | ET POLICY GNU/Linux APT User-Agent Outbound | 3,422 | 0.9892 | benign-leaning |
| 5 | ET INFO Observed DNS Query to .cloud TLD | 464 | 0.9763 | benign-leaning |

**AMiner:**

| rank | signature | n | purity | direction |
|--:|---|--:|--:|---|
| 1 | New request method in Apache Access log | 27,342 | 0.9973 | attack-leaning |
| 2 | New characters in Apache Access request | 10,366 | 0.9696 | attack-leaning |
| 3 | New event type | 7,660 | 0.8206 | attack-leaning |
| 4 | New status code in Apache Access log | 3,220 | 0.9717 | attack-leaning |
| 5 | High entropy in DNS domain | 1,781 | 0.9966 | benign-leaning |

### d. Replacement wording for the `%% PURITY %%` paragraph

**The ordering Wazuh-native > AMiner > Suricata holds under purity — the
ranking does not change — but the magnitudes are dramatically larger for
Wazuh-native and AMiner than the binary-exclusivity framing showed
(74.09% vs. 5.54%; 53.05% vs. 0%), while Suricata's near-zero exposure is
essentially unchanged (0.18% vs. 0.07%).** Draft replacement:

> This ordering follows the distribution of label association across
> each detector's signatures: 74.1% of Wazuh-native's alert volume, 53.1%
> of AMiner's, and 0.2% of Suricata's sits on signatures whose class
> purity — the maximum of attack-share and benign-share within that
> signature — is 0.99 or higher. On Wazuh-native, this exposure is
> concentrated in essentially two signatures (rule 31101, 68.5% of
> volume at 99.98% attack purity, and rule 31151, 5.3% of volume at
> 100.0% attack purity), which together account for 99.6% of the
> exposed volume; two further high-volume signatures (rules 20101 and
> 9701, together 24.9% of volume) sit just below the 0.99 threshold at
> ~97.5–98.1% purity, benign-leaning. On AMiner, exposure is concentrated
> almost entirely in a single signature (`AMiner: New request method in
> Apache Access log`, 49.2% of volume at 99.73% purity, attack-leaning).
> On Suricata, no signature's volume-weighted contribution to the ≥0.99
> band exceeds a fraction of a percent; even the detector's highest-volume
> signatures (the two TLS-validation alerts and the DNS-query alert,
> together 98% of Suricata's total volume) sit at 97.6–98.9% purity,
> benign-leaning — high, but not high enough to cross the exposure
> threshold, and in the direction that provides no attack-detection
> shortcut.

### e. Consequence for `lbl_provenance.md` §2c's recommendation

**Too narrow, and specifically too narrow about magnitude, not about
which rules carry it.** §2c's qualitative scoping — "concentrate on a
handful of Wazuh rules, not the dataset as a whole" — is *confirmed*,
sharper if anything: under purity, Wazuh-native's exposure is carried by
essentially **two** rules (31101 + 31151 = 73.8% of Wazuh-native volume,
99.6% of its exposed volume), and AMiner's by essentially **one**
(49.2% of AMiner's volume, 92.8% of its exposed volume) — even more
concentrated than "a handful" suggested. But §2c's stated *magnitude* was
wrong by more than an order of magnitude for two of three detectors: it
reported 5.54% attack-only exposure for Wazuh-native (actual: 74.09% at
purity ≥ 0.99) and 0% for AMiner (actual: 53.05%). The manuscript should
keep the "concentrated in a small number of specific rules" framing —
that is correct and now sharper — but must replace the exposure
percentages themselves; citing the old binary-exclusivity numbers going
forward would understate the finding, not merely round it differently.

---

## Task 2 — Population-labelled attack rates

| figure | population | one-line statement |
|---|---|---|
| **66.05%** | all Wazuh rows (native + rule 86601), whole corpus, `models_v2/ait_split.npz` | "AIT-ADS's L1 training corpus — all 2,600,263 Wazuh-sourced alerts (native rules plus the Suricata-via-rule-86601 subset) — is 66.05% attack." |
| **74.62%** | Wazuh-native only (rule.id ≠ 86601), whole corpus | "Restricted to Wazuh-native alerts only (excluding the 306,635 Suricata-via-86601 alerts), the whole-corpus attack rate is 74.62% (1,711,506 / 2,293,628)." |
| **74.66%** | Wazuh-native only, evaluation split (n=458,517) | "On the Wazuh-native evaluation split specifically (n=458,517, the eval fold of the exact recovered `ait_split.npz` partition), the attack rate is 74.66% (342,315 / 458,517)." |

**Artifacts citing one of these figures without naming its population,**
checked directly against the committed files listed in this response's
own history (not from memory):
- `newCol/xdet_results.md` line 154: the 74.62% figure sits in a table
  whose "n alerts" column (2,293,628) ties it to the whole-corpus
  Wazuh-native population by table structure, but no adjoining prose
  states "whole corpus" in words — borderline; the table is
  self-consistent but would misread if the row were quoted in isolation.
- `newCol/figures_ms/captions.md` line 521 and `sources.md` line 212:
  both state "74.7% Wazuh-native" (the eval-split figure, rounded) in a
  sentence that does not itself carry the population/n; the population
  (`n=458,517`, eval split) is given nearby (2–14 lines later, in the
  same paragraph or the caption's opening sentence) but not at the point
  of citation itself. Low-severity — same paragraph, not a different
  section — but flagged per the task's instruction to list every site.
- No other site checked (`newCol/rev_task1_split.md`,
  `newCol/rev_dataset_table.tex`, `newCol/xdet_task0_composition.md`,
  `newCol/lbl_provenance.md`, `newCol/fig9_metric_fix.md`) cites any of
  the three figures without its population named in the same sentence or
  table row/column header.

---

## Task 3 — Numbers not in `eval_set_definition.md`

| claim | value | artifact | quoted/computed value | verdict |
|---|---|---|---|---|
| Windows provenance-verified labels | 0% → 55.7% | `newCol/label_win_provenance.py` (mechanism) + `newCol/labeled_win.csv` (recomputed directly, not from a log) | Linux: 0/22,769 HIGH-process (0.0%, structural — no process tree used at all, by design). Windows: 187/336 HIGH-process = **55.65% ≈ 55.7%**. | **MATCH** |
| Alerts misattributed under raw Wazuh timestamp | 74.1% | `newCol/label_lnx_timeonly.py` docstring, lines 22–24 | "Measured impact of getting this wrong: **74.1%** of alerts would be attributed to a DIFFERENT technique and 25.3% would fall outside every window." | **MATCH** (quoted verbatim from the producing script's own docstring; not independently re-derived within this task's scope — the counterfactual computation itself was not rerun) |
| v8 attack-side evaluation on rules with zero benign representation | 95.2% | `newCol/ew_carrier_classification.md` §A6 | "160/168 (**95.2%**) is T1110.001 — the Windows brute-force rules (60122/60204)... has no benign counterpart of its own rule family at all." | **MATCH** |
| v8 recalibrated Windows F1 and FPR | 0.80 at 14.9–16.4% | `results_v2/windows_recalibration_v8.md`, Task 2 table | C2: F1=**0.8000** @ **14.9%** FPR. C3: F1=0.7927 @ 14.9% FPR. C1: F1=0.7818 @ **16.4%** FPR. | **PARTIAL MATCH — the individual numbers are all real, but not paired the way the manuscript implies.** F1=0.80 occurs only at 14.9% FPR (candidate C2); 16.4% FPR belongs to a *different* candidate (C1) with F1=0.7818, not 0.80. Stating "F1=0.80 at 14.9–16.4%" reads as one result spanning that FPR range; it is actually three candidates at three F1s, only one of which is 0.80. Correct as: "F1=0.80 at 14.9% FPR (best candidate, C2); the full candidate range spans 14.9–16.4% FPR at F1=0.78–0.80." |
| Windows L1 recall, two pipelines | 6.04% and 57.74% | `newCol/f1_final_summary.md` (table, line 137/140), `newCol/ew_report_edit_impact_list_E1_E8.md` (line 110/111) | un-normalized pipeline L1 recall = **6.04%**; normalized (cross-platform) pipeline L1 recall = **57.74%**. | **MATCH** |
| Windows original novelty-layer FPR | 75–100% | `newCol/f1_final_summary.md` (line 138–142), `results_v2/windows_recalibration_v8.md` (Table 7.5 baseline rows) | un-normalized combined FPR = 75.12% (**~75%**); normalized combined FPR = **100.00%**. Consistent across both artifacts. | **MATCH** |
| Linux attack alerts / benign alerts | 23,081 / 267 | `newCol/labeled_lnx.csv` (recomputed directly) + `newCol/lbl_provenance.md`/Fig 6 caption (267 figure) | **23,081 = total row count** of `labeled_lnx.csv` (attack + benign + uncertain), **not** attack-labeled rows specifically — actual attack-labeled = 22,769 (99.8% LOW-time). **267 is a different, separate artifact** (`collection_benign_lnx_alerts.csv`, a dedicated fresh benign-only session), not the complement of the 23,081-row file (whose own internal "benign" tier is only 19 rows). | **MISMATCH (population conflation).** Both numbers are individually real and traceable, but pairing them as "attack alerts / benign alerts" implies one population split into two classes; they are actually the total size of one collection (attack round, mostly-but-not-purely attack-labeled) and the total size of a *different* collection (a separate dedicated benign round). Corrected framing: "23,081 total alerts in the Linux attack-round collection (22,769 attack-labeled, 19 benign, 293 uncertain) and a separate 267-alert dedicated Linux benign-only collection used for FPR evaluation." |
| Windows benign alerts | 201 | `results_v2/windows_recalibration_v8.md` line 12 | "evaluated on the fresh, matched, held-out Windows benign (**n=201**, WIN-CL1, 2026-07-12)." | **MATCH** (same population-conflation caveat as Linux applies here too, symmetrically: `labeled_win.csv`'s own "benign" tier is only 3 rows — 201 is the separate dedicated benign-only collection, `collection_benign_win_alerts.json`, not the complement of the 401-row attack-round file.) |
| Entity-window extractor output | 23,950 rows, 57 features, 252 windows | `newCol/ew_features/ew_augmented_per_alert.csv` (recomputed directly: 23,950 rows × 99 columns) and `newCol/ew_features/ew_window_level.csv` (recomputed directly: **244 rows × 29 columns**) | 23,950 matches the per-alert file's row count exactly. Neither file has 57 columns/features (99 for the per-alert file, 29 for the window-level file) or 252 rows/windows (244 for the window-level file). | **MISMATCH — "57 features" and "252 windows" could not be located in any committed artifact.** Only the 23,950 row count is confirmed, and it belongs to the *per-alert* augmented file (99 columns), not a 57-feature window-level output. Per this task's own instruction: this is a control-6 failure and the manuscript must not state "57 features, 252 windows" as written — either the true window-level shape (244 windows × 29 columns) should be cited instead, or, if 57/252 refer to some other filtered/derived artifact, that artifact was not found in this project's holdings and must be produced or the claim dropped. |

---

## Task 4 (important) — What actually labels the Linux attack alerts?

Determined from code, not from prior summaries: `newCol/label_lnx_timeonly.py`
(Linux) and `newCol/label_win_provenance.py` (Windows), both read in full
for this task, plus direct recomputation from their output CSVs
(`newCol/labeled_lnx.csv`, `newCol/labeled_win.csv`) rather than trusting
either script's own docstring numbers unverified.

### a–b. Mechanism and anchored fraction, per category

| | mechanism | script | fraction anchored |
|---|---|---|---|
| **(i) Linux attack** (n=22,769) | **Time-window join on a corrected event time — zero process-tree component.** The script's own docstring states this is a deliberate, explicit decision: *"Per explicit user decision (2026-07-08), the raw process tree is NOT used: `audit_lnxdmz.log` only covers 20:42:43Z–21:32:09Z... 21.1% of the collection"* — the log needed to build a process tree was lost to rotation for 79% of the collection window. Every attack label comes from `classify()`: `hits = [(s,e,k,r) for ... if s<=t<=e]`, a pure timestamp-in-window test. The refinement over naive time-window labeling is the **event-time source**, not the join logic: `event_time()` tries, in order, `full_log`'s embedded syslog/nginx-CLF timestamp, an embedded `audit(<epoch>)` value, or `syscheck.mtime_after` (bounded to a physically plausible 15–120s ingestion lag) before falling back to the raw, lagged `alert.timestamp`. | `label_lnx_timeonly.py` | **0% process-tree-anchored** (structural — `n_high=0`, hardcoded, "no process tree → no HIGH tier"). Of the time-window-derived labels: **99.8% (22,732/22,769) use a corrected/recovered event time** (`LOW-time` tier); **0.2% (37/22,769) fall back to the raw alert timestamp** (`VLOW-time`, ±18–80s uncertainty). |
| **(ii) Linux benign** | **Two distinct populations, neither process-tree-based.** (a) `labeled_lnx.csv`'s own sparse "BENIGN-baseline" tier: time-window join (falls in a 90s post-teardown baseline window, not any technique window, and does not name a collection artifact) — n=19 (18 `BENIGN-baseline` + 1 `-weak`), explicitly disclaimed by the script itself: *"none of which is background traffic: every one is a side effect of the attack script's own sudo/PAM activity."* (b) The population actually used for FPR evaluation throughout this project, `collection_benign_lnx_alerts.csv` (n=267): **benign by construction of the collection window**, not per-alert classified at all — extracted via `extract_agent.sh <agent> <START> <END> <tag>` from a **dedicated benign-only session**, run on a separate day with "nothing attack-shaped run[ning] before, during, or [after]" (`benign_fim_collection_runbook.md`). | `label_lnx_timeonly.py` (tier a); `benign_fim_collection_runbook.md`/`extract_agent.sh` (tier b — no labeling script, session-level construction) | 0% process-tree for either population. |
| **(iii) Windows attack** (n=336) | **Mixed: genuine process-tree anchoring for a majority, time-window fallback for the rest.** `in_tree = guid in tree`, where `tree` is built by `load_tree()` walking Sysmon `EID1` parent/child `ProcessGuid` edges from a named `ROOT_GUID` — a real PID/GUID-tree join, unlike Linux. When `in_tree` is true, label="attack" at `HIGH-process` confidence regardless of time window. When not, the script falls back to the identical time-window test used on Linux (`elif one: label,technique,conf = "attack",one[2],"LOW-time"`). | `label_win_provenance.py` | **55.7% (187/336) HIGH-process** (genuinely GUID-tree-anchored to `ROOT_GUID`). **44.3% (149/336) LOW-time** (time-window fallback, no process anchor — same mechanism as Linux, just used less often here because the Sysmon capture is more complete). |
| **(iv) Windows benign** | Same two-population structure as Linux: (a) `labeled_win.csv`'s own "BENIGN-baseline" tier, time-window-based, n=3 only; (b) the population actually used for evaluation, `collection_benign_win_alerts.json` (n=201), a separate dedicated benign-only session (same construction logic as the Linux fresh benign collection, `results_v2/windows_recalibration_v8.md` line 12/60). | `label_win_provenance.py` (tier a); dedicated session (tier b) | 0% process-tree for either population (Sysmon tree construction in `label_win_provenance.py` is only ever run against the attack-round collection's alerts). |

### c. What the 175/175 result verifies, and against what

**It verifies time-window-derived `technique` sub-labels against an
independent, path-based ground truth — for a 175-alert subset of Linux
FIM-related attack alerts only. It does not involve, and cannot be read
as verifying, any process-tree mechanism, because Linux's pipeline has
none.** Specifically (confirmed via `newCol/eval_set_definition.md`,
already-verified in this response's prior turn, re-checked here against
`label_lnx_timeonly.py`'s own logic): for alerts whose `rule_id` is in
the discriminative FIM set (`{550, 553, 554, 5710, 5712, 5901, 5902,
5903, 31101, 31104, 31151, 31516}`), the `technique` value that
`label_lnx_timeonly.py` assigned by **time-window membership** was
checked against a second, independent signal — the file path each
alert's `syscheck.path` field names, mapped to a technique via a
hand-built, verbatim-from-collection-commands lookup
(`ARTIFACT_TECHNIQUE` in the same script: e.g. `/etc/cron.d/col_cron` →
`T1053.003`). The two agreed on all 175 alerts checked (6+6+151+6+6),
zero contradictions. This 175-alert set is **0.77% of the 22,769
attack-labeled Linux alerts** — a targeted spot-check on the subset where
an independent path-based signal happens to exist (FIM alerts only;
`dirb`/web-scan/brute-force alerts, which make up the overwhelming
majority of the corpus, have no `syscheck.path` field and were not part
of this check).

### Verdict and corrected wording

**The manuscript's description is accurate for Windows (as a majority
mechanism, not a universal one) and is inaccurate — not merely too broad
— for Linux, and must be rewritten there, not just narrowed.** "Narrowed"
would imply Linux uses process-tree anchoring some of the time; it uses
it **none** of the time, by an explicit, documented decision, for a
concretely stated reason (79% audit-log coverage loss to rotation). The
175/175 result is real and worth keeping, but it verifies a **time-window**
label, not a process-tree one, and only for a narrow FIM subset — citing
it as validation of "process-tree anchored labeling... on Linux" is a
category error, not an approximation.

**Corrected wording:**

> **Abstract / Section III-A** (currently "provenance-labeled"): keep
> "provenance-labeled" only if the term is defined broadly enough to
> cover timestamp-based provenance recovered from forensic artifacts
> embedded in each alert (syslog/CLF timestamps, `audit(epoch)` values,
> file-modification times) — which is what both platforms actually rest
> on for the majority of their labels. If "provenance" is meant to imply
> process-tree/causal-chain anchoring specifically, it should read:
> *"alerts were labeled via a combination of process-tree anchoring
> (Windows, where Sysmon process-ancestry data was fully captured) and
> corrected-event-time window matching (both platforms, and the sole
> mechanism for Linux, where process-tree data was incomplete)."*
>
> **Section III-C** (currently: *"Standard timestamp-window labeling
> proved invalid due to background noise. We replaced it with
> process-tree anchored labeling, joining alerts to attack processes via
> root PIDs/GUIDs… and passed verification on Linux (175/175 with zero
> contradictions against `syscheck.path`)."*): replace with —
> *"For Windows, where Sysmon captured a complete process-ancestry tree,
> alerts were labeled by resolving each alert's `ProcessGuid` against a
> tree rooted at the attack script's launch process — 55.7% of Windows
> attack-labeled alerts (187/336) are anchored this way; the remainder
> fall back to time-window matching, described next. For Linux, audit-log
> rotation left only 21.1% of the collection window's process-tree data
> recoverable, so process-tree anchoring was not used at all; Linux
> labels instead rest on time-window matching against a corrected event
> time recovered from each alert's own embedded timestamp fields (syslog/
> CLF text, embedded `audit()` epoch, or bounded syscheck modification
> time), rather than Wazuh's raw ingestion timestamp — using the raw
> timestamp instead would misattribute 74.1% of alerts to the wrong
> technique window and place 25.3% outside every window entirely. As an
> independent check on a 175-alert subset of Linux file-integrity-monitoring
> alerts, where each alert's own recorded file path names a specific
> attack artifact, the time-window-assigned technique agreed with the
> path-derived ground truth on all 175 (0 contradictions) — this validates
> the time-window mechanism for that subset, not a process-tree
> mechanism, which Linux's pipeline does not use."*

This is a genuine finding, not a wording nuance: as originally stated,
the manuscript describes Linux's labeling with a mechanism (process-tree/
PID anchoring) that the codebase explicitly and deliberately does not
use for that platform, and cites a verification result (175/175) as
supporting that mechanism when it in fact supports a different one
(time-window matching) on a small, non-representative subset of the
corpus. Caught during revision, as requested — this is exactly the kind
of gap better found now than in review.

---

## Task 5 — T1110.001 carrier status, confirmed from the final appended state

**Confirmed: T1110.001's carrier remains UNTRACED — not later attributed
— in `ew_carrier_classification.md`'s final state.** The file is
append/supersede throughout (matching this project's own convention);
its last substantive correction (§ "PRE-MS FIX 1," lines ~466–503, the
final content section before two small closing fixes about an unrelated
number and an unrelated recall claim) explicitly re-affirms this rather
than silently carrying it forward. Quoted directly, from the file's own
final state (lines 497–503):

> "**T1110.001's 'untraced' carrier-type label is also now kept separate
> from its unmeasurability**: A4 was right that 5710/5712 can never be
> FPR-checked with the collected data, but that is independent of, and
> should not have been read as resolving, the still-open question of
> what feature carries its attack-side recall — **that remains genuinely
> untraced, not 'unmeasurable'** (unmeasurable describes the benign side
> only)."

The file's final cross-tab (line 486) places all 119 T1110.001 alerts
(38.9% of the 306-alert discriminative-rule cross-tab) in the
**untraced** row, explicitly with **0** in the "measurable" column and
119 in "not measurable" — consistent with `eval_set_definition.md`'s
frozen cross-tab, and with Table VI's own text description in Section
IV-D per the task brief. **If Table VI's summary row literally states
"Untraced 0.0%," that contradicts this file's own final, most-recent
determination (Untraced = 119/306 = 38.9%, not 0.0%) and the
accompanying Section IV-D text, and must be corrected to match the text
— not the other way around**, since the text's "untraced" claim is the
one independently re-confirmed here, against the source artifact's final
state, not merely repeated from an earlier draft.

---
**CHECKPOINT — STOP.**
