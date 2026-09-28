# Report-edit impact list — E1–E8 (Task 4, EW-P5)

**Scope limitation, stated up front rather than discovered by the reader:**
this repository and the EW-P5 prompt itself only give the text of three of
the eight items (E1, E3, E8) — as a short description embedded in the
prompt's Task 4 section, not as the manuscript's own wording. No file in
this repository (`newCol/`, `results_v2/`, project root, or the `Sources/`
literature folder) contains a document with entries labeled E1–E8; that
numbering belongs to an external report/manuscript this session has no
access to. Per the no-fabrication rule, **E2, E4, E5, E6, E7 are reported
as "cannot determine" below, not guessed at.** Do not treat their absence
here as "leaves untouched" — that would itself be a fabricated verdict.

| item | verdict | basis |
|---|---|---|
| E1 | **amends (recommended reading below) — exact current wording not available to verify against** | see below |
| E2 | **cannot determine** | no source text available in this repository or prompt history |
| E3 | **blocked** | depends on a separate, not-yet-run prompt (L1 threshold recalibration) |
| E4 | **cannot determine** | no source text available |
| E5 | **cannot determine** | no source text available |
| E6 | **cannot determine** | no source text available |
| E7 | **cannot determine** | no source text available |
| E8 | **amends** | new wording below, per Task 1e + A10 |

---

## E1 — reads "reclassifies defer as diagnostic"

I do not have E1's exact current sentence, so this is a reading to weigh
against, not a rewrite to insert verbatim. The instruction that prompted
this check was: does the justified-deferral finding (31101 at 99.96%
recall / **99.52% FPR** on raw L1) strengthen or weaken a framing that
treats defer as merely diagnostic?

**Reading:** it strengthens the case for defer as a **necessary production
mitigation**, not just a diagnostic device that reveals a modeling flaw
and stops there. Raw L1 on 31101 is not "somewhat unreliable" — at 99.52%
FPR it is functionally a near-constant "attack" output on live data
(`f1_final_summary.md` PHASE A, RAW row: FPR=86.89% combined, and
`ew_phase4_deferral_report.md`'s isolated 31101 raw-L1 figure of 99.52%
FPR specifically). A9/A10's separate finding (A8: 31101's *benign-side*
FPR under the deferred/production config is only 4.8%, a **different**,
also-memorized number) reinforces this from the other direction: L1's raw
31101 behavior is unreliable in both directions (near-constant positive
raw; artificially low, likely also memorized, once deferred and
re-measured on the benign side) — supporting defer as a real, load-bearing
part of the production pipeline, not a debugging artifact incidental to
the study.

**Recommendation:** if E1 currently frames defer as revealing a flaw
*without* also crediting it as the correct operational response to that
flaw, it should be **amended**, not superseded outright, to add the
99.52%-FPR justification. I am not rewriting E1's actual sentence because
I cannot see it; this is a reading for the person holding the source
document to apply.

## E3 — production-routing claim

**Blocked, as instructed.** E3 depends on the L1 threshold recalibration,
which is tracked as a separate prompt that has not been run in this
session. Not attempted here; no reading offered, since attempting one
without the recalibration would be exactly the kind of unearned number
this project's rules prohibit.

## E8 — T1110.001 (ssh-brute) recall claim

**Supersedes the bare "96.6% recall" framing.** New wording (folds in
Task 1e's original draft and the A10 correction that separates "carrier
untraced" from "FPR unmeasurable" — these are independent facts and were
previously at risk of reading as one):

> L1 achieves 96.6% recall (115/119) on T1110.001 (SSH brute force, rules
> 5710/5712) — rule IDs absent from L1's training vocabulary, so this
> reflects genuine generalization, not rule-ID memorization. Two separate
> limitations apply, and they should not be conflated into one caveat:
> (1) **no false-positive rate can be reported alongside it** — the fresh
> benign collection contains zero alerts of either rule (n=0/267), and
> 5712 is additionally a Wazuh frequency/composite rule that by
> construction can never be given an individual benign baseline, with or
> without more data; and (2), independently of the FPR gap, **no
> ablation or feature-swap test in this repository identifies which
> feature(s) carry this recall** — it is classified as untraced, not
> attributed to any specific feature family. (An earlier characterization
> of this carrier as "endogenous auth aggregates" had no supporting
> artifact anywhere in this repository and should not be repeated —
> see the claim-provenance control, `ew_carrier_classification.md` A5.)
> Given that this project's rate/count-derived `AgentHistory` features
> have, on other techniques in this same study, been shown to sometimes
> carry nothing but capture-session identity (a measured 135× mean-rate
> difference between the Linux attack and benign collection rounds), this
> recall figure should be read as an upper bound on real-world
> performance, not a deployable detection rate. Per the no-further-
> collection rule governing this study, neither the benign-side
> measurement nor the carrier trace will ever be produced for this
> dataset — this is a permanent limitation, not an open item.

---

## Additional item outside E1–E8 (per the prior prompt): v8 Windows restatement

**A correction is needed to the instruction that produced this item**,
not just to v8 itself. The prior prompt's proposed replacement wording
described L1 on Windows as "inert (0% recall / 0% FPR)." That specific
figure does **not** match the verified data and was not re-derived before
being handed down — checked directly against `f1_final_summary.md`'s own
PHASE B table:

| pipeline | L1 recall | L1 FPR |
|---|--:|--:|
| un-normalized | 6.04% | 28.36% |
| normalized (real cross-platform) | 57.74% | 83.08% |

Neither is 0%/0% — L1 does fire, non-trivially, in both pipelines. What
**is** verified, directly from the same table with no re-run needed, is a
different and more precise fact: **combined (L1-or-L2) equals L2 alone,
exactly, in both pipelines** —

| pipeline | L2 (TP,FP,TN,FN) | combined (TP,FP,TN,FN) |
|---|---|---|
| un-normalized | 265, 151, 50, 0 | 265, 151, 50, 0 |
| normalized | 265, 201, 0, 0 | 265, 201, 0, 0 |

identical to four decimal places of the underlying counts, in both rows.
**L1 contributes zero incremental detections beyond L2 on Windows in
either pipeline** — every alert L1 flags is already flagged by L2, so
OR-ing the two layers changes nothing. This is the correct, verified
"inert" claim; "0% recall / 0% FPR" is not, and should not be used in the
manuscript.

**Restated routing justification (replaces the prior prompt's proposed
wording):** the routing *decision* (favor L1+defer on Linux; do not deploy
this pipeline on Windows without retraining) stands, re-justified on
mechanism: L1 contributes no incremental value on Windows (combined ==
L2 exactly, both pipelines, verified above) and L2 alone is either a
transfer-failure artifact (un-normalized: 75.1% FPR from treating the
whole Windows distribution as out-of-domain) or fully saturated
(normalized: 100%/100%, a decision-function ceiling, not detection).
Neither of these is the population-mismatch defect that affects v8
specifically (A6) — this is an independent, additional reason the
Windows pipeline is not deployable as-is, on top of v8's own defect.

---

## PRE-MS FIX 3/4 — E8 amended again (supersedes the §E8 draft above; nothing above deleted)

Two defects found in the §E8 draft above, ahead of manuscript writing:

**FIX 4 — internal contradiction.** The draft above asserts the recall
"reflects genuine generalization, not rule-ID memorization" (a positive
claim), then in the same entry classifies the carrier as untraced. A
recall cannot be confirmed genuine generalization *and* have an unknown
carrier. The positive claim is deleted; only the negative form survives:
these rule IDs are absent from L1's training vocabulary, so the recall
**cannot be rule-ID memorization** — that specific mechanism is ruled
out, and nothing more is claimed about what the recall *does* reflect.

**FIX 3 — the 96.6% figure was unlabeled.** `newCol/eval_summary.md`
(Task 2, "Phase 4 — v6 model evaluation") is the source of 96.6%
(115/119): **raw L1 only, no defer mechanism, L2 = `v6_retrained_31151_5710`**
— a different, earlier configuration than the current production
pipeline. It is not in conflict with the 77.3% (92/119) figure elsewhere
in this project (`newCol/v5_temporal_leakage_report.md` Table 7.1;
`newCol/a10_recall_fpr_per_rule_table.csv`; the two agree exactly) —
that figure is the **production v5+defer combined L1-or-L2 recall**,
where defer suppresses L1's verdict on rule 5710 (113 of the 119 alerts).
Both are genuine and correctly computed; only the configuration label was
missing.

**Corrected E8 (final, supersedes both the recommended wording in
`newCol/ew_carrier_classification.md` §1e and the draft immediately above
in this file):**

> L1 achieves 96.6% recall (115/119) on T1110.001 (SSH brute force, rules
> 5710/5712), measured as **raw L1 output with no defer mechanism applied**
> (`newCol/eval_summary.md`, v6 L2, `thresholds_production_v3.json`). These
> rule IDs are absent from L1's training vocabulary, so this recall
> **cannot be rule-ID memorization** — that specific mechanism is ruled
> out by construction. This is a negative-only finding: ruling out
> memorization does not establish what the recall *does* reflect. No
> ablation or feature-swap test in this repository identifies which
> feature(s) carry it — the carrier is **untraced**, not attributed to any
> specific feature family, and the recall should not be characterized as
> "genuine generalization" (a positive claim this project cannot support)
> until a carrier is actually found.
>
> Two further limitations apply, independently of each other and of the
> point above: (1) **no false-positive rate can be reported alongside
> this number** — the fresh benign collection contains zero alerts of
> either rule (n=0/267), and 5712 is additionally a Wazuh frequency/
> composite rule that by construction can never be given an individual
> benign baseline, with or without more data; (2) given that this
> project's rate/count-derived `AgentHistory` features have, on other
> techniques in this same study, been shown to sometimes carry nothing
> but capture-session identity (a measured 135× mean-rate difference
> between the Linux attack and benign collection rounds), an untraced
> carrier here is not merely an open question but a specific, named risk.
> An earlier characterization of this carrier as "endogenous auth
> aggregates" had no supporting artifact anywhere in this repository and
> should not be repeated (claim-provenance control, A5).
>
> Under the **current production configuration** (v5-reverted L2 +
> defer, which suppresses L1's verdict on rule 5710), the combined
> L1-or-L2 recall on the same 119 alerts is **77.3% (92/119)** —
> reproduced independently in `newCol/v5_temporal_leakage_report.md`
> Table 7.1 and `newCol/a10_recall_fpr_per_rule_table.csv`, which agree
> exactly. The 96.6% and 77.3% figures are not in conflict: they measure
> raw-L1-without-defer and production-with-defer respectively, and the
> **77.3% figure is the deployable one** — it is what the actual
> production pipeline does, not a diagnostic upper bound. Per the
> no-further-collection rule governing this study, neither the
> benign-side measurement nor the carrier trace will ever be produced for
> this dataset — this is a permanent limitation, not an open item.

Full derivation of both fixes: `newCol/pre_ms_number_fixes.md` FIX 3/4.
