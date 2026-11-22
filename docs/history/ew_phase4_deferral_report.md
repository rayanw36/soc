# Phase 4 — restructured around the deferral result

Scope note up front: this replaces the original Phase 4 spec's broad
4-arm/full-technique-table structure with a narrower, deferral-centered
question, per instruction. `models_v2/rule_confound_fixes_v5.json` routes
4 rule families away from L1's own verdict on Linux and relies on L2
(OC-SVM) alone: `{31101, 31151, 5710, 5501}`. **The question this phase
answers: for each deferred rule, can EW features do better than "trust L2
alone" — and where the data can't answer that, say so plainly rather than
force a number.** The provenance arm, the full per-technique three-tier
metrics table, and window-level/augmented/baseline arm comparisons across
the entire eval set are explicitly NOT run here — descoped by the
restructuring, not forgotten; see "What this supersedes" at the end.

Scripts: `newCol/ew_phase4_deferral_study.py`. Data:
`newCol/ew_phase4_deferral_baseline.csv`.

## Why each rule is deferred (baseline, reproduced from the live pipeline)

| rule | n_attack | n_benign | L1 recall | L2 recall | L1 FPR | L2 FPR |
|---|--:|--:|--:|--:|--:|--:|
| 31101 | 20,665 | 209 | 99.96% | 2.25% | 99.52% | 4.78% |
| 31151 | 1,585 | **0** | 100.00% | 98.49% | N/A | N/A |
| 5710 | 113 | **0** | 100.00% | 76.11% | N/A | N/A |
| 5501 | 43 | 22 | 30.23% | 83.72% | 22.73% | 4.55% |

Two very different reasons hide under one mechanism name:
- **31101 is deferred because L1 is broken** (99.96% recall / 99.52% FPR —
  it fires on nearly everything, the rule-identity shortcut this whole
  project exists to escape) and L2 barely helps (2.25% recall). This is
  the "genuinely per-alert undecidable" case Phase 3 studied.
- **31151 and 5710 are deferred even though L1's recall is already 100%**
  and L2's is 98.49%/76.11% — reasonable numbers on their face. They were
  presumably added to the defer set because of FPR concerns documented
  elsewhere in the project (`f1_final_summary.md`'s v6 recall-collapse
  finding), not because they're undecidable the way 31101 is.
- **5501 already benefits from the defer mechanism working as designed**:
  L1 (30.23% recall / 22.73% FPR) is worse than L2 (83.72% / 4.55%) on
  every axis — deferring to L2 was already the right call before any EW
  feature is added.

## Hard scope limitation: 31151 and 5710 are not evaluable with current data

**Zero benign alerts of rule 31151 or 5710 exist in the fresh benign
collection.** Any EW-vs-L2 comparison needs both classes; there is no FPR
side to compare against for these two rules, at all. This is not the same
finding as Phase 2's "zero auth-failures" result (which was about the
5710/60122 *auth-failure* rule family specifically) — this is that the
*rule itself* never fires during the benign capture. Reported plainly, not
substituted with anything synthetic, and carried to Phase 6 as a genuine
collection gap: a benign round that can trigger 31151 (multiple 400s from
one source) and 5710 (invalid-user SSH attempts) is needed before this
rule pair can be assessed at all.

## 31101 — see Phase 3

Already studied in full (`ew_phase3_31101_case_study.md`): per-alert
undecidable (L2 2.25% recall / 4.78% FPR, worse than chance in the relevant
direction), entity-window separation is real and large, but the minimal
window-level classifier is fragile at n=10 windows and the separation
itself is downstream of the same testbed-pacing confound described below.
Not repeated here.

## 5501 — new finding, and a more important one than it first looks

An EW classifier restricted to **user-block features only** (GLOBAL block
excluded — see below) was trained on a temporal split (train n=45: 30
attack/15 benign; test n=20: 13 attack/7 benign) and scored a perfect
**100% recall / 0% FPR** on the test split, against the L2-alone baseline
of 83.72% recall / 4.55% FPR. Feature importance was concentrated
entirely on one feature: `ew_user_trail60m_max_rate_10s` (importance=1.0).

**This was investigated rather than reported as a win, and it doesn't hold
up as attacker-specific signal:**

1. **The GLOBAL block was excluded specifically to escape the host-wide
   testbed-density confound** (`ew_global_trail60m_alert_count`: attack
   median 10,973 vs. benign median 146 for 5501 alerts — the *same* ~75×
   gap as 31101's, confirming the confound is host-wide, not specific to
   the web-scan rule). The USER block (`lnx-dmz`'s own trailing history)
   was chosen because `lnx-dmz` is the actor on both the attack and
   benign side (no rule-composition confound the way 5710's distinct
   `baduserN` accounts had), and 31101 alerts never carry a user field —
   so `lnx-dmz`'s own history should, in principle, be untouched by the
   web-scan volume.
2. **It wasn't.** `ew_user_trail60m_max_rate_10s` for attack-5501 has
   **zero variance** — every one of the 43 alerts shows exactly the same
   value (10.0, std=0.00). Benign-5501 shows real variance (0–2, std=0.50).
   Real attacker behavior does not produce an identical rate reading on
   43 separate alerts; a collection round with a repeating scripted
   pattern (e.g. a setup/health-check step that logs in as `lnx-dmz`
   several times in quick succession, run repeatedly through the session)
   does.
3. **Cross-checked against an unrelated rule.** Rule 5402 (`sudo` to root
   — different mechanism, same actor) shows the identical *direction*:
   attack median max-rate 4.0 vs. benign median 2.0. Weaker gap than 5501,
   but the same shape.
4. **The whole-collection tempo gap is 135×** (lnx_attack: 8.944
   alerts/s over its 43-minute span; lnx_benign: 0.066 alerts/s over its
   67-minute span) — the two collection rounds were captured at
   categorically different paces, for reasons that have nothing to do
   with attacker vs. legitimate behavior (most plausibly: the attack round
   was driven by a fast automated attack-simulation script end-to-end,
   the benign round by a slower/organic capture methodology).

**Verdict: the 5501 "100%/0%" number is not reported as a validated
result.** It is the same testbed-pacing confound as 31101's, now shown to
survive switching pivots from GLOBAL to USER — meaning the confound is not
specific to the host-wide aggregate, it's baked into how the two
collection rounds were captured, and it can surface through more than one
feature depending on which rule/pivot is examined.

## Restructured headline

**The central threat to validity in this experiment is not "per-alert vs.
entity-window" as an architecture question — it is that the attack and
benign collection rounds were captured at categorically different tempos
(135× apart), and every rate/volume-shaped EW feature tested so far
(GLOBAL alert_count for 31101, USER max_rate_10s for 5501) is at least
partly reading that tempo difference rather than a property of the
attacker.** This is a stronger and more specific claim than "benign never
bursts" (Phase 2's 2e, which was already true for Linux) — it says the
confound survives the specific mitigation (switching to a pivot that
excludes the dominant volume rule) that was designed to escape it.
Nothing tested under the deferral restructuring has produced a result that
is both real (features genuinely separate the classes) and traced to
attacker behavior specifically rather than collection tempo. The one
rule with a complete recall/FPR baseline where L1 already fails and L2
already underperforms (31101) is exactly the rule Phase 3 already showed
requires this caveat; 5501 now shows the same problem where L2 was
already doing fine, meaning EW added a confound without an established
need. 31151/5710 remain simply untested.

## What this supersedes / leaves untouched (per the reporting checklist expected in Phase 5)

- Supersedes: the original Phase 4 spec's plan to report a full 4-arm
  comparison (v5+defer baseline / +EW retrained / window-level /
  provenance) across the entire eval set with per-technique three-tier
  metrics. Not run. The restructuring narrowed scope to the 4 defer-rule
  families specifically.
- Leaves untouched: Phase 4c's provenance-feature arm (needs the archived
  auditd/Sysmon data, independent of this restructuring — still blocked on
  the same coverage gap Phase 0a found: no raw logs for either benign
  window).
- Amends: Phase 2's tentative "Windows brute-force features" and "Linux
  user-pivot min_interarrival_s" findings are further reinforced as
  testbed-artifact-driven by this phase's tempo-gap measurement (135×),
  which gives the earlier qualitative "zero-failures"/"rule-composition"
  findings a quantitative anchor.
