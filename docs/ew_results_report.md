# Entity-Window Re-Architecture Experiment — Results Report

No further data collection is possible within this project's timeline. Every
gap named below is a **permanent limitation of these results**, not a
pending action item, unless explicitly framed as a recommendation to future
researchers. All numbers are reproduced from existing artifacts or computed
directly from the collected data; nothing is simulated or fabricated. Every
table caption below names the carrier of the number it reports, or marks it
untraced — no exception.

---

## 1. What was proposed, and why

The production pipeline's headline known-attack numbers were shown, prior to
this experiment, to be substantially rule-identity memorization: 88.5% of
the 26-feature space encodes rule identity or a rule-correlated proxy, and a
lookup table on `rule_id` alone matches the trained model to within 0.0003
F1. Rule 31101 (web scan, ~97% of alert volume in both AIT-ADS and the fresh
collections) was shown to be **provably undecidable per-alert**: attack and
benign 31101 alerts are statistically indistinguishable on every
non-rule-identity feature. The thesis this experiment tests: **per-alert
classification is the wrong abstraction; the correct unit of triage is the
(entity, time-window) pair**, and the behavioral aggregates that appeared to
carry genuine detections in prior work (`alert_rate_1min`,
`failed_login_5min`) are exactly what an entity-window redesign should
systematize. Phases 0–4 built the extractor, audited it, and tested it. This
report is the outcome.

---

## 2. The retraction sequence

This is the spine of the document. Four positive findings were produced by
this experiment and then retracted by a control run against them —
including two of this experiment's own Phase 2 headline results, and one
retraction (#4) that defeated a pivot chosen specifically to escape the
mechanism that caused retraction #1.

### Retraction 1 — Linux GLOBAL-block volume/rate features

**Finding as produced (Phase 2):** GLOBAL-block EW features
(`alert_count`, `distinct_url_count`, `mean_interarrival_s`, syscheck
path-class counts) showed mutual information against the attack/benign
label up to 0.0665 — modestly above a same-method rule-identity reference
(0.0563). The 31101 case study (Phase 3) showed 82–1,519× separation between
attack and benign entity-windows on these same features.

**Control that falsified it (Phase 2e, testbed-artifact check):** the
benign collection's busiest 10-second window contains 5 alerts of mixed,
unrelated types; the attack round's peak is 4,104 alerts in the same
10-second span. Benign reaches **0.1%** of the attack round's peak rate.
Quantified precisely in Task 1c: the two rounds' **mean alert rate differs
135.2×** (536.6 vs. 3.97 alerts/min), peak rate differs 820.8×.

**Mechanism:** the GLOBAL block is host-wide, not rule-specific. Any alert
occurring during the dense attack-round capture inherits an inflated
GLOBAL rate reading regardless of what triggered it, because the two
rounds were captured at categorically different tempos — most plausibly
because the attack round was driven by a fast, scripted, end-to-end attack
simulation and the benign round by a slower or differently-instrumented
capture methodology. **Carrier: `ew_global_trail60m_alert_count` /
`ew_global_trail5m_alert_count` and related rate features — rate-shaped,
confirmed tempo-contaminated.**

**Implication for anyone repeating this experiment:** a rate or volume
feature computed on a two-round testbed (one attack round, one benign
round) cannot be trusted until the two rounds' capture tempo is measured
and shown comparable. MI screening alone will not catch this — MI only
asks whether a feature separates the classes, not why.

### Retraction 2 — Windows brute-force EW features

**Finding as produced (Phase 2):** Windows EW features
(`auth_failure_count`, `auth_success_after_failure_flag`,
`min_interarrival_s`) showed MI up to 0.6330, roughly 2× a same-method
rule-identity reference (0.3101) — the strongest EW result the experiment
produced anywhere, and initially reported as "genuinely promising, passed
the one check that could have falsified it" (the burst-rate check, which
passed because a genuine login/session-start burst exists in Windows
benign, 22 alerts/10s exceeding the attack round's own peak of 11/10s).

**Control that falsified it (zero-failures check, requested explicitly
before Phase 3 could proceed):** the Windows benign collection contains
**zero** alerts of rule 60122 or 60204 (logon failure / multiple logon
failures) — the entire auth-failure rule family. **The burst-rate check
that passed answered a different question than the one that mattered for
this specific feature family**: it tested whether benign traffic can ever
be busy (yes), not whether benign traffic ever contains a failed login
(no).

**Mechanism:** `auth_failure_count > 0` is not a behavioral threshold when
the class it's supposed to separate from (benign) structurally cannot
produce a nonzero value for this feature. This is a class-presence defect,
not a rate/tempo defect, and it survived the tempo-style check precisely
because it is a different mechanism. **Carrier: `auth_failure_count`,
`auth_success_after_failure_flag` — rate/count-shaped by construction, and
additionally a label proxy because the benign class cannot contain the
counted event type at all.**

**Implication:** MI screening (Phase 2b) did not catch this either — MI
was high precisely because the feature perfectly encodes label via class
absence. **Only an explicit class-presence check catches it**, and it must
be run per feature family, not assumed satisfied by a general burst-rate
check.

### Retraction 3 — Cross-platform user-scoped `min_interarrival_s`

**Finding as produced (Phase 2):** `ew_user_trail60m_min_interarrival_s`,
restricted to alerts where the user pivot applies, was the strongest single
user-block feature on *both* platforms (MI 0.29 Linux, 0.55 Windows) —
reported as "a consistent, non-trivial signal on both platforms," the one
finding presented as surviving Phase 2 cleanly.

**Control that falsified it (user-pivot-composition check, requested
explicitly before Phase 3):** in the 242-row Linux user-present subset, the
attack side is 55.1% rule 5710 (ssh brute force — itself zero-occurrence in
benign per retraction 2's mechanism) and the benign side is 70.3% rule 5501
(routine PAM login). Windows showed a partial version of the same problem:
no single-rule split, but the auth-failure rules within that subset are
present only on the attack side.

**Mechanism:** the "user-present" subset was not a random sample of
user-attributed behavior — it was implicitly a rule-composition split, with
different rule types populating the attack and benign sides. A feature that
looks like "this user's typical inter-event timing" was actually "which
rule type populates this row," reintroducing the rule-identity confound the
whole EW redesign exists to escape, smuggled in through pivot-population
imbalance rather than through the `rule_id_encoded` feature directly.

**Implication:** restricting a feature to a pivot's "present" subset can
silently reintroduce a rule-composition confound even after the raw
rule-identity feature has been removed. This must be checked explicitly
per pivot, not assumed clean because the feature itself contains no rule ID.

### Retraction 4 — 5501 user-block classifier (100%/0%)

**Finding as produced (Phase 4, restructured around the deferral result):**
an EW classifier restricted to USER-block features only — GLOBAL block
deliberately excluded, specifically to escape retraction 1's host-wide
confound — scored a perfect 100% recall / 0% FPR on a held-out test split
for rule 5501, against an L2-alone baseline of 83.72%/4.55%. Feature
importance was concentrated entirely on `ew_user_trail60m_max_rate_10s`.

**Control that falsified it:** the driving feature has **zero variance
across all 43 attack-side alerts** (constant value 10.0, std=0.00) — real
attacker behavior does not produce an identical rate reading on 43 separate
occasions; a repeating scripted collection step does. The same directional
pattern (not identical magnitude) was confirmed in an unrelated rule (5402,
sudo-to-root) on the same actor. The whole-collection tempo gap (135×,
Task 1c) supplies the mechanism: the entire attack-round session, not just
the web-scan rule, was captured at a different pace.

**Mechanism, and why this retraction is the most important of the four:**
the USER pivot was chosen specifically because 31101 (the volume driver
behind retraction 1) never carries a user field, so a user-scoped feature
should, in principle, be insulated from the GLOBAL block's host-wide
density confound. **It wasn't.** The tempo-asymmetry confound does not live
in one feature or one pivot — it is a property of how the two collection
rounds were captured, and it can resurface through a different feature
(rate) on a different pivot (user) for a different rule (5501) than the one
it first appeared on (31101, GLOBAL, volume). Escaping the confound requires
escaping the collection asymmetry itself, not switching which column reads
it.

**Implication:** a mitigation designed around a specific instance of a
confound (here: "switch pivots to avoid the volume-driving rule") does not
generalize to the confound's actual cause (capture-tempo asymmetry) unless
that cause is checked directly, every time, on the specific feature and
rule in question.

---

## 3. What survived

- **Per-alert undecidability for rule 31101, sharpened.** Reproduced
  exactly from the frozen v5 OC-SVM pipeline (`f1_phaseA_diag_l2.py`
  methodology): attack-31101 median score −2.2929 (recall 2.25%),
  benign-31101 median score −2.1589 (FPR 4.78%). **Benign FPR exceeds
  attack recall** — per-alert, this feature set is not merely undecidable
  for 31101, it is worse than the chance diagonal in the direction that
  matters.
- **31101's deferral to L2 is justified, not merely diagnostic.** L1
  (XGBoost) achieves 99.96% recall on 31101 at **99.52% FPR** — a
  near-constant "attack" output regardless of input, on live data. Deferring
  this rule away from L1's own verdict is the correct engineering decision
  independent of anything the EW experiment found.
- **5501's deferral is justified independently of EW.** L2 (83.72%
  recall / 4.55% FPR) beats L1 (30.23% recall / 22.73% FPR) on both axes
  before any EW feature is considered — the defer mechanism was already
  the right call here.
- **31151 and 5710 are stated as unevaluable, not estimated.** Zero benign
  alerts of either rule exist in the fresh collection; no FPR-side claim
  can be made for either, and none is made here.

---

## 4. The six control mechanisms — the methodological contribution

| # | control | what it catches | cost to run | finding it caught in this study |
|---|---|---|---|---|
| 1 | **Missing benign behavioral class — burst** | a rate/volume feature that trivially separates classes because the benign collection never reaches comparable activity density | one pass computing max/median rate per collection, compared across rounds | Retraction 1 (Linux GLOBAL rate features) |
| 2 | **Missing benign behavioral class — event-type presence** | a count/flag feature that trivially separates classes because the benign collection contains zero instances of the counted event type at all, regardless of overall activity level | one pass checking, per rule/event family, whether the benign collection contains any alert of that type | Retraction 2 (Windows auth-failure features) — the burst check (control 1) explicitly did **not** catch this; a distinct, narrower check was required |
| 3 | **Rule-composition confounding within a pivot subset** | a feature that appears entity-scoped but is actually rule-scoped, because the subset of alerts where the pivot applies is dominated by different rule types on each side of the label | a groupby of (label, rule_id) within the pivot-restricted subset, checked for a dominant-rule split | Retraction 3 (cross-platform `min_interarrival_s`) |
| 4 | **Small-n hyperparameter determinism** | a classifier result that is actually a property of default regularization interacting with a tiny training set, not of the features | fit the same features under a deliberately different regularization setting and check whether the verdict changes | the n=7 31101 window-level classifier: default XGBoost produced a degenerate constant-output model (zero feature importance, misclassified the one held-out attack window); the same features under regularization suited to n=7 recovered perfect separation on one feature. Neither run alone is evidence — running both is what makes the finding legible |
| 5 | **Capture-tempo asymmetry between rounds** | any rate-shaped feature, on any pivot, for any rule, that is actually reading which collection round an alert came from | mean/peak alert rate per collection round, compared as an explicit ratio | Retraction 4 (5501 user-block classifier) — caught the confound resurfacing through a *different* feature and pivot than the one it was first found on |
| 6 | **Claim provenance** | a characterization of a finding that propagates through project documentation without ever having a named artifact that produced it | for any claim about *why* a result holds, require a named script/output before it is repeated | the "endogenous auth aggregates" characterization of T1110.001's carrier (see Task 1's carrier classification) — no ablation or swap trace for this technique exists anywhere in the repository, yet the characterization appeared in the project record, in the prompts driving this experiment, and in manuscript framing before being checked here |

**The general principle controls 1–2 establish:** when a benign collection
lacks a behavioral class entirely — not "has less of it," but zero
instances — any feature keyed on that class becomes a label proxy with a
plausible-sounding behavioral name, and MI screening will not catch it,
because MI only measures whether a feature separates the classes, not
whether it could have failed to. Only an explicit class-presence check
catches this, and it must be run per feature family (auth-failure,
burst-rate, event-type) rather than once, generally.

**The general principle control 6 establishes:** this project already built
`newCol/eval_set_definition.md` because *predicates* — which config, which
threshold, which rule set — drifted from what was actually run, and had to
be frozen and version-controlled to stop re-deriving them from scratch each
session. Task 1 of this phase found the identical failure running one layer
up: not a predicate drifting, but a *claim about a finding* (T1110.001's
carrier) propagating without any artifact behind it. The fix is the same
shape as the fix for predicate drift: every claim needs a named artifact
that produced it, not just every label needs provenance.

---

## 5. Threats to validity — permanent, not pending

No further data collection is possible; every item below is a limitation of
these results as reported, not a gap awaiting future work on this dataset.

- **Benign collections are small and narrow.** 267 Linux alerts / 201
  Windows alerts, single session each, idle-host housekeeping activity —
  not a representative sample of legitimate production traffic.
- **Zero benign auth-failure alerts, both platforms.** Linux rules
  5710/5712: 0/267. Windows rules 60122/60204: 0/201. Any claim resting on
  an auth-failure feature's benign-side behavior is unmeasurable, not
  merely uncertain, on this data — this includes the E8 T1110.001 recall
  claim (Task 1e) and 95.2% of the attack-side evaluation set behind the
  v8 Windows headline (Task 1, Amendment A6).
- **No benign burst exists on Linux.** Busiest 10-second window: 5 alerts,
  vs. the attack round's 4,104. Windows does have a genuine benign burst
  (22/10s, exceeding the attack round's 11/10s) — this asymmetry between
  platforms is itself notable and unexplained.
- **Capture-tempo asymmetry, quantified.** Linux mean alert rate differs
  135.2× between attack and benign rounds (peak rate: 820.8×). Windows
  shows no comparable asymmetry (1.5× mean, benign peak exceeds attack
  peak) — the tempo confound is Linux-specific in this dataset, but nothing
  guarantees it would not appear on Windows under different collection
  conditions.
- **Zero source-IP / host diversity.** Every alert in every Linux
  collection (attack and benign) carries the identical `srcip` value
  (127.0.0.1) and the identical single agent. Windows is single-agent
  throughout as well. An entity-disjoint split is categorically impossible
  on this data — not underpowered, structurally absent.
- **No raw process/auth logs archived for either benign capture window.**
  The provenance-feature arm (Phase 4c of the original plan) is
  unevaluable for the same reason 31151/5710's FPR is unevaluable: the
  data needed does not exist in the collected archive.
- **n=7 training rows / n=3 held-out windows for the 31101 window-level
  study.** Both classifier runs (default and re-regularized) are reported
  because neither is individually meaningful at this n — the figure in
  `ew_fig_31101_before_after.png` is a schematic illustration of the
  mechanism under test, not a validated generalization result.
- **The 0.8702 headline's contamination scope (Task 1).** 55.2% of its
  novel-technique alert volume is confirmed rate-shaped and tempo-
  contaminated; 38.9% is structurally unmeasurable (composite frequency
  rule 5712, zero benign base-rate for 5710); 3.9% is untraced; only 2.0%
  is a confirmed (if coarse, identity-adjacent) non-tempo signal. The
  benign side of the F1 computation is, by direct inspection of
  `f1_final_summary.md`'s own table (`FP=29`/`TN=238` identical across the
  known/novel/blended rows), measured against a population that is 78.3%
  rule 31101 — a known-technique rule, not a member of the novel set at
  all. This is a structural incoherence in what the F1 combines, not a
  correctable estimation issue.

---

## 6. Verified-not-assumed note

Two specific verification steps are recorded here because they are evidence
the rate/timing features underlying this entire study were checked, not
taken on faith:

- **The microsecond-resolution interarrival bug.** This pandas environment
  stores alert timestamps at microsecond resolution
  (`datetime64[us, UTC]`). A naive `int64` conversion of a microsecond-
  resolution array silently produces values 1000× too small when
  interpreted as nanoseconds-since-epoch. This was caught by
  cross-validating an optimized feature-computation path against the
  original reference implementation on real data (not synthetic test
  cases) — 700 real slice comparisons, 0 mismatches after the fix. Every
  interarrival/rate feature in this report post-dates that fix.
- **The mtime UTC-vs-local check, re-verified.** The historical bug class
  (`syscheck.mtime_after` being naive-ISO but actually UTC, not local time)
  was checked again at the start of this experiment (Phase 0c) rather than
  assumed still fixed. It remains correctly handled in
  `newCol/label_lnx_timeonly.py`, with the original justification (the
  cron/`col_cron` timing cross-check) intact.

Both checks are cited because a rate-shaped feature that has not been
timezone- and resolution-verified cannot be trusted regardless of whether
it passes every control in Section 4 — this is a precondition for those
controls to mean anything, not a substitute for them.
