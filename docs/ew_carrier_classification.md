# Carrier classification and tempo-contamination check

Analysis only — nothing retrained, no model or threshold changed. All ablation
numbers below are reproduced by re-running existing scripts
(`newCol/v5_temporal_task2.py`, `newCol/v9_pretask_t1136.py`) that were already
in the repository; no new ablation methodology was invented. Where a script
existed but its full output wasn't persisted to disk (the per-rule breakdown
inside `v9_pretask_t1136.py`), it was re-run to capture that already-computed
output — not to compute anything new.

## 1a/1b. Carrier trace and classification, per surviving technique family

**Bucket definitions** (stated before classifying, per instruction):
- **rate-shaped** — value depends on event timing, counts per unit time,
  interarrival, or volume within a window. Contaminated by the tempo
  asymmetry documented in 1c.
- **content-shaped** — value depends on the content/semantics of the alert
  itself (severity rating, auth outcome, path class). Unaffected by tempo.
- **structural/identity** — rule identity or a coarse proxy for it (already
  established as memorization-carrying elsewhere in this project).
- **untraced** — no swap or ablation test isolating the specific carrier
  exists in this repository. Reported as untraced, not guessed.

| family | rule(s) | n | ablation result | carrier | bucket |
|---|---|--:|---|---|---|
| T1053.003 (cron) | 554 (path subset) | 6 | 0/6 under benign-typical | AgentHistory temporal block (`scan_preceded`/`brute_preceded`/`failed_login_5min` etc.) | **rate-shaped** |
| T1543.002 (systemd) | 554 (path subset) | 6 | 0/6 under benign-typical | same temporal block | **rate-shaped** |
| T1546.004 (shell-rc) | 554 (path subset) | 6 | 0/6 under benign-typical (5/6 pre-ablation) | same temporal block | **rate-shaped** |
| T1098.004 (ssh-key) | 550 (path subset) | 6 | 6/6, unaffected by benign-typical | `rule_level` (traced by direct feature swap: 550→554's level 7→5 collapsed it to 0/6; swapping `rule_id_encoded` alone changed nothing) | **content-shaped / structural** — coarse severity rating, not a rate feature, but still rule-identity-adjacent |
| T1136.001 incidental | 550 (90) + 553 (20) + 554 (41) | 151 | 0/151 under benign-typical | same temporal block | **rate-shaped** |
| T1136.001 account-mgmt | 5901 (6) + 5902 (6) | 12 | 12/12, unaffected by benign-typical (survived the identical temporal-zeroing that killed the 151 above) | **untraced** (no feature-swap test isolating which specific non-temporal feature carries it) — but the rate-shaped hypothesis is **ruled out by the existing ablation itself**: the temporal/behavioral block was already replaced with benign-typical values in this exact test and detection did not change | **untraced, but confirmed NOT rate-shaped** |
| T1110.001 (ssh brute) | 5710 (113) + 5712 (6) | 119 | **no ablation or swap trace exists in this repository** | **untraced** | **untraced — unresolved** |
| — (5903, "group/user deleted") | 5903 | 7 (all label='uncertain', not 'attack') | not evaluated anywhere; does not enter the current F1=0.8702 recall computation (filters to `label=='attack'`) | untraced | untraced, and currently inert to the headline number regardless |

**On T1110.001 specifically**, because this determines a large share of the
verdict below: prior framing (carried over from before this task) described
its carrier as "endogenous auth aggregates." A dedicated search of
`results_v2/`, `newCol/`, and `results/rule_memorization_audit/` found **no
script that ran a benign-typical ablation or feature-swap test on T1110.001**
— unlike every FIM technique and T1136.001, which all have one. `failed_login_5min`
is a plausible candidate carrier (T1110.001 is definitionally about repeated
auth failures, and this is the one feature that counts exactly that), but
`rule_level` is an equally live candidate given the ssh-key precedent (a
coarse per-rule severity number turned out to carry ssh-key's survival, not
anything temporal). **This is reported as untraced, not as "endogenous,"
because no artifact in this repository verifies which one it is.** The
earlier "endogenous auth aggregates" characterization should be treated as
an unverified prior description, not a finding this task confirms.

## 1c. Tempo asymmetry, quantified

| collection | n | span | mean alerts/min | median 10s-window (nonzero) | peak 10s-window |
|---|--:|--:|--:|--:|--:|
| lnx_attack | 23,081 | 43.0 min | 536.6 | 7 | 4,104 |
| lnx_benign | 267 | 67.3 min | 4.0 | 2 | 5 |
| win_attack | 401 | 107.0 min | 3.7 | 2 | 11 |
| win_benign | 201 | 80.9 min | 2.5 | 1 | 22 |

**Attack:benign ratios:**

| platform | mean-rate ratio | peak-10s ratio |
|---|--:|--:|
| Linux | **135.2×** | 820.8× |
| Windows | 1.5× | 0.5× (benign peak exceeds attack peak) |

**The "135×" figure cited elsewhere in this study is the Linux mean-rate
ratio** (536.6 vs. 3.97 alerts/min). The Linux peak-rate ratio is even more
extreme (820.8×); Windows shows no comparable asymmetry in either direction,
consistent with Phase 2/4's findings that the Windows benign round contains
a genuine burst.

## 1d. Verdict on the 0.8702 headline

**[Superseded by the "Amendments" section at the end of this file — an
arithmetic error in the denominator (282/288 instead of the correct 306) and
three additional findings (A2–A4) revise the numbers below. Kept here, not
deleted, per project convention: read the Amendments section for the current
figures.]**

The "novel" F1=0.8702 figure (`f1_final_summary.md`, PRODUCTION v5-defer,
combined layer, n=267 benign) is computed over `NOVEL_RULES =
{5710, 5712, 550, 553, 554, 5901, 5902, 5903}`. Breaking that alert volume
down by the classification above:

| status | rules | n (attack side) | share of novel n |
|---|---|--:|--:|
| **confirmed rate-shaped (contaminated)** | 550/553/554, T1136-incidental portion | 151 | 53.5% |
| **confirmed content-shaped (clean of this confound)** | 550, ssh-key portion | 6 | 2.1% |
| **confirmed NOT rate-shaped (untraced carrier, but confound ruled out)** | 5901/5902 | 12 | 4.3% |
| **untraced — unresolved** | 5710/5712 (T1110.001) | 119 | 42.1%* |
| inert (label='uncertain', not counted) | 5903 | 0 of 7 | — |

\* against the 282 total across the four evaluated rows.

**Verdict: mixed, and not resolvable to a clean answer with existing
artifacts.** Just over half the novel-technique alert volume (53.5%,
the T1136-incidental population) is **confirmed** to carry a rate-shaped
signal and therefore **does inherit the same tempo-asymmetry confound**
that retracted every EW positive result. A further 42.1% (T1110.001) is
**unresolved** — it has never been tested, and given `failed_login_5min`'s
direct relevance to a brute-force technique, contamination cannot be ruled
out the way it was for 5901/5902. Only a small remainder (6.4%: ssh-key's
content-shaped carrier plus the account-management rules' confirmed-not-rate
survival) is clean of this specific confound — though ssh-key's `rule_level`
carrier is still coarse and rule-identity-adjacent, just not tempo-driven.

**The overall F1=0.8702 figure cannot be reported as a single clean number.**
It must be decomposed per rule/technique with the contaminated and
unresolved rows flagged, not cited as one aggregate. One additional finding
sharpens this further: **78.3% of the entire 267-alert benign collection is
rule 31101** (209/267) — meaning the FPR side of the combined 10.86% figure
is overwhelmingly a measurement of how 31101 alerts are classified, not a
balanced measurement across the novel-technique rule set. The FPR component
of this headline is not evenly informative about the techniques it's
nominally being computed over.

**No corrected F1 is produced here**, per instruction — re-scoring would
require a benign side for 5710/5712 and 550/553/554-incidental that doesn't
exist. This is a contamination-scope report, not a replacement number.

## 1e. E8 amendment input

Benign alert count for rules 5710/5712 in the fresh collection: **0 and 0**
(confirmed directly from `ew_augmented_per_alert.csv`; also 0 for 5901,
5902, 5903 — every NOVEL_RULES member except 550/553/554 has zero benign
representation in the current collection).

E8 currently states L1 generalizes on ssh-brute (T1110.001) at 96.6% recall
(`newCol/eval_summary.md`, n=119, the same rule set as the untraced-carrier
row above). Recommended wording:

> L1 achieves 96.6% recall (115/119) on T1110.001 (SSH brute force, rules
> 5710/5712) — a technique whose rule IDs are absent from L1's training
> vocabulary, so this recall figure reflects genuine generalization rather
> than rule-ID memorization. **No false-positive rate can be reported
> alongside this number**: the fresh benign collection contains zero alerts
> of either rule (n=0/267), and no ablation or feature-swap test has been
> run to identify which feature(s) carry this detection. Given that the
> project's other rate/count-derived (`AgentHistory`) features have been
> shown, on other techniques in this same study, to sometimes carry
> nothing but capture-session identity (the Linux attack and benign rounds
> were captured at a measured 135× difference in mean alert rate), this
> recall figure should be read as an upper bound on real-world performance,
> not a deployable detection rate, until both a benign-side measurement and
> a carrier trace exist for this specific technique.

---

## Amendments (post-review corrections — supersede in place, nothing above deleted)

### A1 — Denominator was wrong; corrected from 282/288 to 306

The original 1d table dropped three rows of the classification table (the
separate T1053.003/T1543.002/T1546.004 FIM rows, 6 alerts each = 18) when
summing the denominator, and then added a further arithmetic slip on top
(151+119+12=282, then the ssh-key row's own 6 was divided by that same
282 instead of a denominator that includes it). Verified directly against
`labeled_lnx.csv`:

| rule(s) | n (attack-labeled) | technique |
|---|--:|---|
| 550 | 96 = 90 + 6 | T1136.001 (90) + T1098.004/ssh-key (6), **disjoint by path** |
| 553 | 20 | T1136.001 |
| 554 | 59 = 6+6+6+41 | T1053.003 (6) + T1543.002 (6) + T1546.004 (6) + T1136.001 (41) |
| 5710 | 113 | T1110.001 |
| 5712 | 6 | T1110.001 |
| 5901 | 6 | T1136.001 (account-mgmt) |
| 5902 | 6 | T1136.001 (account-mgmt) |
| **total** | **306** | |

**No contradiction exists between "0/151 collapse under benign-typical" and
"6/6 ssh-key survive"**: these are confirmed disjoint alert populations by
path (`/root/.ssh/authorized_keys` for the 6 ssh-key alerts vs.
`/etc/passwd-`/`/etc/shadow.lock`/`/etc/group-` etc. for the 90 T1136-incidental
ones, both under rule 550) — the two claims are about different alerts, not
contradictory claims about the same ones. The actual defect was a missed
denominator term (the three separate 6-alert FIM rows) plus a subsequent
addition error, not a population overlap.

**Corrected shares (denominator = 306, all four buckets disjoint, verified
to sum exactly):**

| bucket | n | share |
|---|--:|--:|
| rate-shaped (T1053.003 + T1543.002 + T1546.004 + T1136.001-incidental) | 6+6+6+151 = 169 | **55.2%** |
| structural/identity (ssh-key, `rule_level` — see A2) | 6 | **2.0%** |
| untraced, confirmed not rate-shaped (account-mgmt, 5901/5902) | 12 | **3.9%** |
| structurally unmeasurable (T1110.001 — see A4) | 119 | **38.9%** |

### A2 — `rule_level` reclassified: structural/identity, not content-shaped

Accepted. `rule_level` is set in each rule's static XML definition — a
deterministic, many-to-one function of `rule_id`, not a property that varies
with what an alert's payload actually contains. It is a **coarsened rule
identity**, correctly uncontaminated by tempo, but not behavioral. The
ssh-key row is reclassified from "content-shaped / structural" to
**structural/identity**, and its 2.0% share is memorization-adjacent, not a
behavioral detection.

**Consequence, stated plainly: nothing in the 306 novel-technique alerts
behind F1=0.8702 survives as verified behavioral detection.** Every bucket
is one of: tempo-contaminated (55.2%), an identity proxy (2.0%), untraced
against an absent benign side (38.9%), or untraced-but-ruled-out-as-rate
without a confirmed alternative (3.9%). Zero percent is a confirmed,
content-driven, non-tempo, non-identity behavioral signal.

### A3 — Primary reason restated: population mismatch, not tempo, is the lead defect

**Verified directly against `f1_final_summary.md`'s own table**: for the
PRODUCTION (v5-defer) pipeline, `FP=29` and `TN=238` are **identical across
the known, novel, and blended rows**. This means the benign-side confusion
matrix (all 267 fresh benign alerts, of which 78.3% are rule 31101 — a
KNOWN rule, not a member of `NOVEL_RULES` at all) is computed **once** and
reused unchanged regardless of which attack subset it's paired with. The
"novel" F1=0.8702's precision term is not measuring false positives on
novel-rule-like benign traffic — of the 267 benign alerts, only **9 (3.4%)**
belong to any rule in `NOVEL_RULES` (550: 6, 553: 1, 554: 2; zero for
5710/5712/5901/5902/5903). The other 96.6% of the benign side is either
rule 31101 (a *known*-technique rule, evaluated on its own KNOWN line) or
unrelated Linux housekeeping (5501/5502/5402/etc.).

**This is restated as the primary reason the 0.8702 figure cannot be
reported as a single number, ahead of the tempo confound**: it is a
structural incoherence in what is being combined (a recall measured on one
rule population, a precision measured against a near-disjoint one),
independent of whether any individual feature is rate-shaped. The tempo
confound (1c) compounds this; it is not the root cause.

### A4 — 5710/5712 (T1110.001, 38.9%) restated as structurally unmeasurable

Rule 5712 (`sshd: brute force trying to get access...`) is a Wazuh
**frequency/composite rule**: by Wazuh's own rule-correlation model, a
frequency rule fires only after its base rule (5710, invalid-user attempts)
recurs some threshold number of times within a configured timeframe — the
alert's existence is conditioned on a rate threshold **upstream of the SIEM
correlation engine**, before any feature this project computes is ever
derived. (The exact frequency/timeframe parameters are set in Wazuh's
stock ruleset, which is not present in this repository to cite verbatim —
stated at the level of Wazuh's documented rule-correlation mechanism, not a
verified specific threshold value.) Because the fresh benign collection has
**zero** alerts of the base rule (5710) as well as zero of 5712, there is no
way to construct a benign population against which this rule family's false
positive behavior could ever be measured with the collected data — not
"not yet traced," but **categorically unmeasurable with what was collected.**
The 119 alerts (5710+5712, 38.9% of the 306) are restated from "untraced —
unresolved" to **structurally unmeasurable**, generalizing E8's specific
finding (1e) from one row to the largest single bucket behind the 0.8702
headline.

### A5 — sixth control mechanism: claim provenance (folded into Task 2 §4)

Noted here and carried into the Task 2 writeup: the "endogenous auth
aggregates" characterization of T1110.001's carrier had **no artifact
behind it anywhere in this repository**, yet it propagated into the project
record, into the prompts driving this experiment, and into manuscript
framing. This project already built `eval_set_definition.md` because
*predicates* (which config, which threshold, which rule set) drifted from
what was actually run. The identical failure mode was running one layer up,
in *claims about findings* rather than in the underlying predicates
themselves. Every claim needs a named artifact that produced it — this
instance is the worked example, cited in full in Task 2.

### A6 — v8 Windows result checked against the same defect

`results_v2/windows_recalibration_v8.md`'s headline (C2, F1=0.8000 @ 14.9%
FPR) is built on an attack set of n=168 (`in_root_tree==True`, technique ∈
{T1110.001, T1136.001}), of which **160/168 (95.2%) is T1110.001** — the
Windows brute-force rules (60122/60204). Checked directly against the fresh
Windows benign collection (`ew_augmented_per_alert.csv`, `win_benign`,
n=201): **zero alerts of rule 60122 or 60204 exist** (confirmed, same check
as Phase 2's zero-failures result, now applied to the v8 artifact
specifically). Windows benign is dominated by rule 92004 (PowerShell
process-spawn, 38.8%) and 60106 (logon success, 28.9%) — structurally
unrelated rule types to the auth-failure family the F1 is nominally scoring.
**This is the identical A3/A4-style defect, on the other platform**: 95.2%
of v8's attack-side evaluation set has no benign counterpart of its own rule
family at all.

**Stated positively, per instruction**: the measured Windows tempo ratio
(Task 1c: 1.5× mean-rate, and the benign round's peak 10s-window count
*exceeds* the attack round's) means v8's F1=0.80 is **not** contaminated by
the tempo-asymmetry confound that affects the Linux EW results and the
Linux 0.8702 headline — that specific mechanism does not apply here.
**But it is not clear of the population-mismatch defect (A3/A4).** v8's FPR
is measured against Windows benign traffic that contains no auth-failure
alerts at all, so — exactly as in E8 (1e) — the 14.9% FPR paired with
T1110.001's recall in that F1 is not a false-positive rate *on this
technique's own rule family*; it is a false-positive rate on unrelated
Windows housekeeping traffic. v8 should not be cited as the one clean,
untouched deployable number without this caveat attached.

---

## Second-round pre-checks (A7–A9) — supersede in place, nothing above deleted

Same rules: analysis only, nothing retrained, no threshold or model changed.
Where an existing artifact fully answers the question, it is cited and not
recomputed; where no artifact existed, a new analysis-only script was
written (both new scripts are committed alongside this file:
`newCol/a9_acctmgmt_carrier_swap.py`; A8's breakdown reuses
`newCol/f1_phaseA_v5defer.py`'s exact scoring path with a per-rule tally
added, written to `newCol/a8_fp_rule_breakdown.csv`).

### A7 — Confirmed: the true figure is 0/169, from two disjoint existing artifacts, not one

The 18 alerts added by A1's denominator correction (T1053.003/T1543.002/
T1546.004, 6 each, rule 554 path-subset) were **not** inside the run that
produced "0/151" (`newCol/v9_pretask_t1136.py`, which filters on
`technique == "T1136.001"` only — these 18 alerts carry different technique
labels and are excluded from that script's n=163 by construction).

They were, however, already inside a **different** existing artifact:
`newCol/v5_temporal_task2.py` / `newCol/v5_temporal_leakage_ablation.csv`,
which independently ran the identical benign-typical-median ablation
method on exactly this 18-alert set and reported 0/6, 0/6, 0/6
(cron/systemd/shell-rc respectively — reproduced above in the "current
status" table verbatim from that file).

These two artifacts' populations are confirmed disjoint (A1: rule 554's
59 alerts split 6+6+6+41 by path, no overlap) and jointly exhaustive of the
corrected 169-alert rate-shaped bucket (151 + 18 = 169, no gap). Both
independently return zero survivors under the same ablation method and the
same production scoring path (`combined_decision_v6.score_alert`,
θ_ocsvm=−0.335). **No re-run was needed or performed** — this is a citation
correction, not a new experiment. Restated claim: **0/169** rate-shaped
alerts survive benign-typical ablation, sourced from
`v9_pretask_t1136_ablation.csv` (151) ∪ `v5_temporal_leakage_ablation.csv` (18).

### A8 — Measured directly: 31101 is 34.5% of the 29 FPs, not "most"

Re-ran `newCol/f1_phaseA_v5defer.py`'s exact production-v5defer scoring path
(reproduced FP=29, TN=238 exactly, matching `f1_final_summary.md`) with a
per-rule tally added. Full breakdown (`newCol/a8_fp_rule_breakdown.csv`):

| rule | n (benign) | FP | FPR | share of the 29 FPs |
|---|--:|--:|--:|--:|
| 31101 | 209 | 10 | 4.8% | **34.5%** |
| 5402 | 10 | 10 | **100.0%** | **34.5%** |
| 550 | 6 | 3 | 50.0% | 10.3% |
| 52002 | 2 | 2 | 100.0% | 6.9% |
| 553 | 1 | 1 | 100.0% | 3.4% |
| 5502 | 11 | 1 | 9.1% | 3.4% |
| 5501 | 22 | 1 | 4.5% | 3.4% |
| 554 | 2 | 1 | 50.0% | 3.4% |
| 40704 / 503 / 81102 | 1/1/2 | 0 | 0.0% | 0.0% |

**Answer, reported as it came out, not as the task's framing anticipated:**
31101 is the single largest contributor (34.5%) but is **not a majority** of
the 29 FPs on its own. The finding this actually produces is more specific
than "precision measures 31101 suppression," and arguably more damning:
**31101's own per-rule FPR is low (4.8%)** despite it being 78.3% of the
entire benign collection — consistent with finding #1's memorization
mechanism (the model has, in effect, memorized that `rule_id==31101` scores
low on the benign side, the mirror image of memorizing it high on the
attack side). The remaining 65.5% of the 29 FPs are spread across **six
different minority rules that each appear only 1–22 times** in the fresh
benign collection, four of which are flagged at 50–100% individually
(5402: 10/10, 52002: 2/2, 553: 1/1, 550: 3/6). **The model's low aggregate
FPR is not evidence of balanced precision across rule types — it is
carried almost entirely by 31101's own (separately memorized) low FPR,
while every other rule type the fresh benign collection contains is
flagged at 50% or worse.** This sharpens A3 rather than replacing it: the
population-mismatch defect (only 3.4% of benign is a `NOVEL_RULES` member)
is compounded by a precision figure whose apparent stability is itself an
artifact of 31101's dominant volume and separately-memorized low FPR, not a
property that would hold if the benign mix were even slightly more
representative of the other rule types present in this project's own data.

### A9 — Carrier identified: the account-management survival (n=12) is identity-carried, not untraced

The 1a/1b table and A1's corrected-shares table both listed 5901/5902
(n=12) as "untraced, confirmed not rate-shaped" — i.e., ruled out as
rate-shaped but with no positive carrier identified. Ran the existing
swap methodology (same technique as the ssh-key trace: single/blocked
feature substitution on top of the production scoring path,
`newCol/a9_acctmgmt_carrier_swap.py`) over the one remaining untested
block — content/keyword features (`desc_len` + 10 `kw_*` flags,
11 features) — while continuing to hold temporal features at
benign-typical (reproducing the existing 12/12-survives baseline exactly
first: confirmed 6/6 + 6/6).

**Content block: ruled out.** Swapping all 11 content features to their
benign-typical medians left detection at 12/12, scores essentially
unchanged (+22.11→+22.12, +27.05→+22.14 vs. θ=−0.335). The content block
carries none of this signal.

**This left only the identity block (`rule_id_encoded`, `rule_level`,
`mitre_tactic_id`, `is_auth_failure`, `is_web_attack`, `agent_criticality`)
— which the task's own framing had assumed was already ruled out. It was
not; that assumption is corrected here rather than carried forward
unchecked.** Testing it directly: holding temporal and content at their
real per-alert values and swapping only identity to benign-typical
(median identity vector, dominated by `rule_id_encoded=31101`) dropped
detection from 12/12 to 7/12 — a partial but large effect. Going the other
way — holding identity at its real (5901/5902) value while temporal *and*
content are both already at benign-typical — left detection at a full
**12/12**, at very large decision-function scores (+22.1 to +27.0,
structurally the same kind of extreme, far-outside-training-support value
documented for Windows L2 saturation in `f1_final_summary.md`, ~160.87).
Ablating all three blocks together collapses every alert to one identical
score (−2.1589, the same constant reported elsewhere for the generic
benign-typical vector) — trivial by construction (all 26 features become
identical across alerts), not new information.

**Carrier: identified as the identity block, specifically `rule_id_encoded`
/ `rule_level` for rules 5901/5902** — rules that are rare (12 alerts total
in the entire attack collection) relative to AIT-ADS's training
vocabulary, pushing the OC-SVM decision function to extreme values in the
same way an out-of-vocabulary Windows rule ID does. **Bucket: reclassified
from "untraced, confirmed not rate-shaped" to structural/identity** — the
same bucket as ssh-key (A2), for the same underlying reason (a rule-rarity
signal, not a content-aware detection of account-management activity).
Per instruction: **n=12 makes this indicative only, not deployable** — with
only 6 alerts per rule ID, "rare in training" and "genuinely-detected
anomalous behavior" are not distinguishable from this sample.

**Consequence — corrected bucket shares (supersedes A1's table above):**

| bucket | n | share |
|---|--:|--:|
| rate-shaped | 169 | 55.2% (unchanged) |
| structural/identity (ssh-key + account-mgmt) | 6 + 12 = 18 | **5.9%** (was 2.0%, +12) |
| untraced, confirmed not rate-shaped | 0 | **0.0%** (was 3.9%, now resolved) |
| structurally unmeasurable (T1110.001) | 119 | 38.9% (unchanged) |

169 + 18 + 119 = 306, exact, no remainder. **A2's consequence statement is
now stronger, not just asserted**: every one of the 306 novel-technique
alerts behind F1=0.8702 falls into a bucket that is either tempo-
contaminated, an identity/rarity proxy, or structurally unmeasurable —
there is no longer an unresolved residual bucket standing between this
study and the claim that zero percent of the 306 is confirmed
content-driven behavioral detection.

### A10 — Unified recall/FPR/N table, and correcting a conflation: carrier-type and measurability are two independent axes, not one partition

**10a. Per rule, side by side — recall, FPR, attack N, benign N.** Computed
directly with the identical production-v5defer scoring path used
throughout this file (`combined_decision_v6.score_alert`, defer mechanism
live, θ_xgb=0.07538, θ_ocsvm=−0.33500), grouped by `rule_id` instead of by
technique/path-subset — this is the only granularity at which both sides
(attack recall, benign FPR) are jointly defined, since the benign
collection carries `rule_id` but was never labeled by attack technique.
New artifact: `newCol/a10_recall_fpr_per_rule_table.csv` (reuses
`f1_phaseA_lnx.extract_attack_features`/`extract_benign_features`, no new
extraction logic).

| rule | attack N | recall | benign N | FPR | note |
|---|--:|--:|--:|--:|---|
| 550 | 96 | 94.8% | 6 | **50.0%** | mixed carrier: 90 T1136-incidental (rate-shaped) + 6 ssh-key (structural/identity); benign side is not separable below rule_id |
| 553 | 20 | 100.0% | 1 | **100.0%** | rate-shaped (T1136-incidental only) |
| 554 | 59 | 72.9% | 2 | **50.0%** | rate-shaped (all four sub-techniques sharing this rule_id: cron/systemd/shell-rc/T1136-incidental) |
| 5710 | 113 | 76.1% | 0 | **N/A** | carrier untraced (A4); benign N=0 |
| 5712 | 6 | 100.0% | 0 | **N/A** | frequency/composite rule, carrier untraced; benign N=0 |
| 5901 | 6 | 100.0% | 0 | **N/A** | structural/identity (A9); benign N=0 |
| 5902 | 6 | 100.0% | 0 | **N/A** | structural/identity (A9); benign N=0 |
| 5903 | 0 | n/a (all 7 alerts label='uncertain') | 0 | **N/A** | inert to the headline regardless |

**The pattern holds exactly as stated**: every rule where FPR is
measurable at all (550, 553, 554) falls in **50.0–100.0%**; every rule
where it isn't measurable (5710, 5712, 5901, 5902, 5903) has **benign
N=0**. (Rule 31101, the KNOWN-side memorization case from Finding #1, is
deliberately excluded from this table — its FPR is measurable and low
[4.8%], but that is a *different*, already-documented mechanism [A8]:
low FPR from memorizing the benign class the same way the attack class
was memorized, not a NOVEL-rule behavioral result. Including it here
would blur two distinct findings into one row.)

**10b. Carrier-type and measurability are orthogonal axes — restating the
bucket table as a cross-tab so nothing is double-counted.** The A9
correction (account-management, n=12, reclassified to structural/identity)
exposed a conflation running through this whole section: "structural/
identity" is a claim about *what carries the detection signal*, while
"structurally unmeasurable" (A4) is a claim about *whether a benign
comparison is even possible*. These were being treated as if they were
mutually exclusive slots in one partition. They are not — 5901/5902 are
the direct counterexample: identity-carried (A9) **and** unmeasurable
(benign N=0, confirmed again in 10a) **at the same time**. Presented as
one partition, that pair either double-counts or forces an arbitrary
choice of which fact to keep. Presented as two columns, both facts survive
intact:

| carrier-type ↓ / measurable? → | measurable (benign N>0) | not measurable (benign N=0) | row total |
|---|--:|--:|--:|
| **rate-shaped** | 169 (550/553/554 sub-populations) | 0 | 169 (55.2%) |
| **structural/identity** | 6 (ssh-key, rule 550) | 12 (account-mgmt, 5901/5902) | 18 (5.9%) |
| **untraced** (no swap/ablation test performed) | 0 | 119 (T1110.001, 5710/5712) | 119 (38.9%) |
| **column total** | 175 (57.2%) | 131 (42.8%) | 306 |

Read across, not down: **every carrier-type row is still 100%
non-behavioral** (rate-shaped is tempo-contaminated regardless of column;
structural/identity is a rarity/severity proxy regardless of column;
untraced has, by definition, no positive finding either way) — so A2's
"zero percent confirmed behavioral" conclusion is unaffected by this
correction. What changes is that "structurally unmeasurable" is now
correctly scoped to the **measurability column** (131/306, 42.8%) rather
than being folded into a fourth carrier-type bucket that overlapped with
structural/identity. **T1110.001's "untraced" carrier-type label is also
now kept separate from its unmeasurability**: A4 was right that 5710/5712
can never be FPR-checked with the collected data, but that is independent
of, and should not have been read as resolving, the still-open question
of what feature carries its attack-side recall — that remains genuinely
untraced, not "unmeasurable" (unmeasurable describes the benign side
only).

---

## PRE-MS FIX 2 — correction to A10's "pattern holds exactly" claim (§A10, 10a; nothing above deleted)

A10's 10a table reports 550/553/554 FPR as 50.0%/100.0%/50.0% on benign N
of 6/1/2, then states "the pattern holds exactly as stated." At benign
N=1 (rule 553), 100.0% is one alert — the claim of exactness is a
denominator artifact, not a demonstrated pattern, and is withdrawn.
Restated as counts: 550 = 3 of 6 flagged, 553 = 1 of 1, 554 = 1 of 2;
aggregate, **5 of 9** benign alerts across these three rules were flagged.
Honest form of the pattern: every rule with any measurable FPR has *at
least one* benign alert flagged; every rule without one has benign N=0 —
no specific percentage is claimed as exact. Per ART-C
(`newCol/art_contamination_check.md`), those 9 benign alerts are
themselves CUPS daemon state-file churn (8 of 9,
`/etc/cups/subscriptions.conf` and shadow copies) plus one organic SSH
`known_hosts` append — not representative organizational file activity.
Full derivation: `newCol/pre_ms_number_fixes.md` FIX 2.

## PRE-MS FIX 3/4 — E8 amended: two labeled configurations, positive claim deleted (§1e; supersedes the recommended wording there, nothing deleted)

§1e's recommended E8 wording states the 96.6% (115/119) recall "reflects
genuine generalization rather than rule-ID memorization" — a positive
claim — while classifying the same finding's carrier as untraced
elsewhere in this file (§A10, §A5). Both cannot stand together. Per
PRE-MS FIX 4, the positive claim is deleted; the negative-only claim
("these rule IDs are absent from training, so this cannot be rule-ID
memorization") is kept. Per PRE-MS FIX 3, 96.6% (115/119) is raw L1 only,
no defer (`newCol/eval_summary.md`, v6 L2, no defer mechanism applied) —
it is not in conflict with the 77.3% (92/119) production v5+defer
combined figure in this file's own A10 table; they measure different
pipeline configurations. The full corrected E8 wording (superseding this
section's draft and the fuller draft in
`newCol/ew_report_edit_impact_list_E1_E8.md` §E8) is in
`newCol/pre_ms_number_fixes.md` FIX 4.
