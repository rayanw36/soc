# Pre-manuscript number fixes (PRE-MS)

Four inconsistencies flagged before manuscript writing begins. Analysis
only — no retraining, no new collection, no threshold changes. This file
is the consolidated record; corrections are also appended in place to each
artifact FIX 1–4 revises (listed under each fix), per the append/supersede
convention — nothing below deletes or rewrites a prior claim, it
supersedes it explicitly.

---

## FIX 1 — Reconcile the 29 false positives

**The two statements as written cannot both be literally true, and the
resolution is the first of the three offered options: ART-C's "all 29"
framing was overstated.** Path matching can only ever apply to alerts that
carry a `syscheck.path` field — FIM/syscheck alerts only. `art_contamination_paths.csv`
(already produced, not re-derived) shows exactly which of the 29 have one:

| rule | n (of 29) | has `syscheck.path`? | path(s) |
|---|--:|---|---|
| 550 | 3 | yes | `/etc/cups/subscriptions.conf`, `/etc/cups/subscriptions.conf.O` ×2 |
| 553 | 1 | yes | `/etc/cups/subscriptions.conf.N` |
| 554 | 1 | yes | `/home/lnx-dmz/.ssh/known_hosts` |
| 5402 | 10 | **no** | — |
| 31101 | 10 | **no** | — |
| 52002 | 2 | **no** | — |
| 5501 | 1 | **no** | — |
| 5502 | 1 | **no** | — |

Only **5 of 29** carry a path, and all 5 literally path-match to CUPS
housekeeping or the organic `known_hosts` entry — that part of ART-C's
claim is correct as far as it goes. The remaining **24 of 29** (31101,
5402, 52002, 5501, 5502) are not FIM alerts, have no `syscheck.path` at
all, and were checked by a *different* method already documented in
ART-C's own Task 3c body text — a full-JSON-body substring search for the
literal strings `coluser`, `col_cron`, `col_svc`, `col_profile`, and
`COLLECTNOVEL` — which also returned zero matches. Both checks are valid
and both came back negative; the error was ART-C's own headline sentence
collapsing two different methods into one phrase ("path-matches... across
all 29"), which is imprecise for the 24 that were never eligible for path
matching in the first place.

**Second offered option, checked and rejected with evidence, not
inferred:** rule 31101 is not CUPS-generated. Sampled `full_log`/`data`
fields for 31101 benign alerts show `curl` requests to `/api/status`,
`/contact`, `/about` returning HTTP 404 — an application web server
(`nginx`, per `newCol/audit_lnxdmz.log`'s own service-check records),
port unspecified but structurally unrelated to CUPS's admin interface
(port 631, `/etc/cups/subscriptions.conf`). No URL, host, or port field in
any 31101 alert references CUPS. This explanation does not hold and is
not being adopted.

**Correction (supersedes ART-C's headline paragraph, does not delete
it):** appended to `newCol/art_contamination_check.md` below the original
text. Corrected statement: of the 29 false positives, 5 carry a
`syscheck.path` and path-match to routine CUPS/SSH-client activity
(unrelated to any ART artifact); the other 24 carry no path at all and
were separately confirmed unrelated via full-body string search for every
Task 1 artifact identifier. **The Task 5 conclusion (no contamination
found) is unchanged** — this fix corrects an imprecise summary sentence,
not the underlying per-alert evidence, which was already computed
correctly in `art_contamination_paths.csv`.

---

## FIX 2 — Per-rule FPR table as counts

**Original table** (`newCol/eval_set_definition.md`, `newCol/ew_carrier_classification.md`
A10) reports 550/553/554 FPR as 50.0%, 100.0%, 50.0% on benign N of 6, 1,
2. At n=1, "100.0%" is one alert; the percentage form implies a precision
these denominators cannot support.

**Restated as counts:**

| rule | attack N | attack recall | benign N | benign alerts flagged (raw count) |
|---|--:|--:|--:|--:|
| 550 | 96 | 94.8% | 6 | 3 of 6 |
| 553 | 20 | 100.0% | 1 | 1 of 1 |
| 554 | 59 | 72.9% | 2 | 1 of 2 |
| 5710 | 113 | 76.1% | 0 | not measurable (benign N=0) |
| 5712 | 6 | 100.0% | 0 | not measurable (benign N=0) |
| 5901 | 6 | 100.0% | 0 | not measurable (benign N=0) |
| 5902 | 6 | 100.0% | 0 | not measurable (benign N=0) |
| 5903 | 0 | n/a | 0 | not measurable (benign N=0) |

Aggregate, stated the way the manuscript should state it: **5 of the 9
benign alerts across rules 550/553/554 were flagged** by the production
v5-defer pipeline. Attack-side recall percentages are left as percentages
since those denominators (96/20/59) are large enough to support them;
only the benign/FPR side is restated as counts.

**"Pattern holds exactly, not approximately" — deleted, not softened.**
This phrase appears in two places (`newCol/eval_set_definition.md:235`,
`newCol/ew_carrier_classification.md:458`) and is wrong as stated: with
benign N=1 for rule 553, "exactly 100%" is a denominator artifact, not a
measured pattern. The correct, appended replacement: every rule where FPR
is nominally measurable (550, 553, 554) has *some* benign alerts flagged
(non-zero), and every rule without any (5710/5712/5901/5902/5903) has
benign N=0 — this is the honest form of the same observation, without
claiming a precision the data does not support.

**What those 9 benign alerts actually are, stated plainly (per FIX 1's
CUPS finding, not previously spelled out here):** 8 of the 9 are CUPS's
own periodic subscription-lease file rewrite —
`/etc/cups/subscriptions.conf` and its `.O`/`.N` shadow copies, touched in
tight sub-second bursts, already documented in
`newCol/benign_fim_collection_runbook.md` as routine, non-scripted CUPS
daemon activity, not organizational file-change diversity. The 9th is one
organic SSH `known_hosts` append. In short: **daemon state-file churn**,
not a representative sample of legitimate admin file activity — a
relevant caveat for how much these FPR figures should be trusted to
generalize, independent of the small-N caveat above.

**Correction location:** appended to `newCol/eval_set_definition.md`
(new block, existing blocks untouched) and `newCol/ew_carrier_classification.md`
(new appended note under A10).

---

## FIX 3 — Reconcile T1110.001 recall (96.6% vs ~77.3%)

**Not an error — two different, correctly-labeled-once-you-trace-them
pipeline configurations, currently presented without that label attached.**

- **96.6% (115/119)** — raw **L1 only**, no defer mechanism, from
  `newCol/eval_summary.md` Task 2 ("Phase 4 — v6 model evaluation"):
  `theta_xgb=0.07538`, L2 = `v6_retrained_31151_5710` (not the current
  production L2), and **defer is not applied** in that script at all —
  it predates the defer-vs-revert decision. This is the figure E8 quotes,
  unlabeled.
- **77.3% (92/119)** — **production v5+defer, combined L1-or-L2**,
  reproduced independently in two places that agree exactly:
  `newCol/v5_temporal_leakage_report.md` Table 7.1 (`2/119 (1.7%) L1 |
  92/119 (77.3%) L2 | 92/119 either`) and `newCol/a10_recall_fpr_per_rule_table.csv`
  (5710: 76.1% of 113 = 86.0 + 5712: 100.0% of 6 = 6.0 → 92.0/119 =
  77.3%, arithmetic check passes exactly). Under production, defer
  suppresses L1's verdict on rule 5710 (113 of the 119 alerts), so this
  figure is effectively "L2 alone on 5710, combined with L1-or-L2 on
  5712" — and L1's residual 2/119 in the temporal-leakage table is
  consistent with L1 firing on some of 5712's 6 alerts (not suppressed)
  while contributing nothing on the suppressed 5710 alerts.

**Both figures are genuine, both are correctly computed under their own
config, and neither is the "real" number in isolation — they answer
different questions** (what can L1 alone do on unseen rule IDs, vs. what
does the actual deployed pipeline do). The defect is that E8 states the
first without naming its configuration, inviting exactly the apparent
contradiction this fix was opened to resolve.

**Correction:** E8's wording is amended (Task 4 below covers the
positive-claim defect in the same amendment) to state both figures, each
explicitly labeled with its configuration, rather than one bare number.

---

## FIX 4 — E8 internal contradiction (generalization claim vs. untraced carrier)

E8's current text (`newCol/ew_carrier_classification.md` §1e,
`newCol/ew_report_edit_impact_list_E1_E8.md` §E8) asserts in one sentence
that the recall "reflects genuine generalization... not rule-ID
memorization" — a **positive** claim about what the recall *is* — and
then, later in the same paragraph, classifies the carrier as untraced and
flags it as a plausible tempo-contamination candidate. A recall cannot
simultaneously be confirmed genuine generalization and have an unknown,
possibly-artifactual carrier. Per the instruction, the fix keeps the
**negative-only** claim and deletes the positive one.

**Amended E8 (supersedes both prior drafts, quoted in full, replaces the
earlier "recommended wording" in `ew_carrier_classification.md` §1e and
the fuller draft in `ew_report_edit_impact_list_E1_E8.md` §E8):**

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

**Correction location:** appended to both `newCol/ew_carrier_classification.md`
(§1e) and `newCol/ew_report_edit_impact_list_E1_E8.md` (§E8), each marked
as superseding the respective prior draft in place, without deleting it.

---

## Summary table

| fix | verdict | artifacts corrected |
|---|---|---|
| FIX 1 | ART-C's "all 29" headline was overstated; underlying per-alert data was already correct | `newCol/art_contamination_check.md` |
| FIX 2 | small-N percentages restated as counts; "exactly" phrase deleted; benign alerts identified as CUPS daemon churn | `newCol/eval_set_definition.md`, `newCol/ew_carrier_classification.md` |
| FIX 3 | not an error — two different configurations, now each explicitly labeled | folded into the FIX 4 amendment (same E8 passage) |
| FIX 4 | positive "genuine generalization" claim deleted; negative-only ("cannot be memorization; carrier untraced") retained | `newCol/ew_carrier_classification.md`, `newCol/ew_report_edit_impact_list_E1_E8.md` |

**CHECKPOINT: `newCol/pre_ms_number_fixes.md` complete. STOP.**
