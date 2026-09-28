# Phase 2 — Leakage audit of the EW features

Run before any EW model is trained (Phase 4). Uses only
`newCol/ew_features/ew_augmented_per_alert.csv` (Phase 1 output). Script:
`newCol/ew_phase2_leakage_audit.py`. Raw outputs: `ew_phase2_mi_results.csv`,
`ew_phase2_mi_user_conditional.csv`, `ew_phase2_burst_report.json`,
`ew_phase2_swap_medians.json`, `ew_phase2_class_balance.json`.

## 2a. Pre-registration

Done in Phase 1, ahead of this audit, per instruction — see
`newCol/ew_feature_preregistration.md`. Not repeated here.

## 2b. Mutual information

**Method note:** the original 26-feature audit
(`results/rule_memorization_audit/exp1-2`) used XGBoost gain/SHAP importance
attribution against a manually-assigned RULE-IDENTITY/RULE-CORRELATED/
BEHAVIORAL taxonomy, not literal mutual information. This audit computes
genuine `sklearn.feature_selection.mutual_info_classif` instead, and
computes it FRESH for a same-units RULE-IDENTITY/RULE-CORRELATED reference
set (`rule_id_encoded`, `desc_len`, `rule_level`, `mitre_tactic_id`,
`is_auth_failure`, `is_web_attack`, `rule_diversity_10min`,
`high_sev_ratio_20`) on the identical subset/label, so "does an EW feature's
MI rival rule-identity" is an actual same-method comparison rather than a
cross-methodology guess. This is a deliberate methodological improvement,
flagged as a deviation from "same method as the 26-feature audit" per the
instruction to flag ambiguity rather than silently pick one reading.

**"Per collection" is computed per PLATFORM** (attack + benign collections
combined, `uncertain` rows dropped), not per individual collection — a
single collection alone has one label value by construction (the benign
collections are 100% benign) so within-collection MI against label is
undefined. This is stated explicitly since it's a deviation from a literal
reading of "per collection."

### Class balance (after dropping `uncertain`)

| platform | n_attack | n_benign | n_uncertain_dropped | attack:benign ratio |
|---|--:|--:|--:|--:|
| lnx | 22,769 | 286 | 293 | ~80:1 |
| win | 336 | 204 | 62 | ~1.6:1 |

Linux is severely imbalanced; MI estimates there are noisier and generally
compressed toward zero for that reason alone, independent of any feature's
real informativeness. Windows is close to balanced.

### Linux: EW MI barely separates from the rule-identity reference

| | max MI |
|---|--:|
| RULE-IDENTITY/CORRELATED reference (best: `high_sev_ratio_20`) | 0.0563 |
| Best EW feature (`ew_global_trail5m_distinct_syscheck_path_class_count`) | 0.0665 |

Top EW features by MI are almost entirely **GLOBAL-block volume/rate
features** (`alert_count`, `mean_interarrival_s`, `syscheck_*_count`) —
every one within ~15% of each other, all barely above the reference. This
flat, undifferentiated MI profile, combined with the 2e testbed-artifact
finding below, is a warning sign: it looks like these features are
recovering "which capture round this alert is from" rather than a specific
attack behavior. **Full table: `ew_phase2_mi_results.csv`.**

### Windows: EW MI substantially exceeds the rule-identity reference

| | max MI |
|---|--:|
| RULE-IDENTITY/CORRELATED reference (`rule_id_encoded`) | 0.3101 |
| Best EW feature (`ew_global_trail60m_auth_success_after_failure_flag`) | 0.6330 |

The top of the list (`auth_success_after_failure_flag`, `auth_failure_count`,
`min_interarrival_s`, `max_rate_10s`, all ≥0.57) is exactly the brute-force
behavioral signature the thesis is testing for, and it clears the
rule-identity reference by ~2×, not by a small margin. **Caveat that must
travel with this number: the Windows attack collection (n=401, 336 after
dropping uncertain) is dominated by a single technique, T1110.001 (Windows
brute force, 249/401 alerts). High MI for auth-failure/auth-success features
is close to tautological for a collection whose majority content IS a brute
force campaign — this measures "T1110.001 detectability," not general
attack detectability on Windows.** It's a real, well-traced result for that
one technique family, not evidence the EW approach generalizes across
Windows attack types. Full table: `ew_phase2_mi_results.csv`.

### Conditional MI: the user-pivot block, restricted to rows where it applies

Most alerts have no user field at all (31101 dominates Linux volume and
never carries one), which dilutes an unconditional MI estimate for reasons
unrelated to whether the user-block features are informative *when
applicable*. Restricting to `ew_user_present == 1`:

- **Linux** (n=242, 205 attack / 37 benign): `ew_user_trail60m_min_interarrival_s`
  (MI=0.29) and `mean_interarrival_s` (0.27) lead — meaningful signal exists
  in the user-scoped timing pattern even on this small subset.
- **Windows** (n=509, 325 attack / 184 benign): `ew_user_trail60m_min_interarrival_s`
  (MI=0.55) leads by a wide margin over the rest of the user block.

Both platforms show the SAME feature (`min_interarrival_s`, user-scoped)
as the standout of the user block — a consistent cross-platform signal,
worth carrying into Phase 4 as a specific hypothesis to test rather than
just reporting the aggregate table. Full table: `ew_phase2_mi_user_conditional.csv`.

## 2d/2e. Benign-burst search and testbed-artifact check (run together — the results depend on each other)

| collection | n | span | max_10s_rate | mean alerts/s |
|---|--:|--:|--:|--:|
| lnx_attack | 23,081 | 2,581s (43.0 min) | **4,104** | 8.944 |
| lnx_benign | 267 | 4,037s (67.3 min) | **5** | 0.066 |
| win_attack | 401 | 6,418s (107.0 min) | **11** | 0.062 |
| win_benign | 201 | 4,854s (80.9 min) | **22** | 0.041 |

**Linux: no benign burst exists — confirmed testbed-artifact degeneracy.**
The busiest 10-second window in the entire 267-alert benign collection
contains 5 alerts of mixed, unrelated types (log rotation, sudo, PAM
open/close) — ordinary background housekeeping, not a burst by any
reasonable definition. Benign peak rate reaches **0.1%** of the attack
round's peak rate (5 vs 4,104). **Per instruction: this must be stated as a
threat to validity in every downstream table caption that uses a Linux
GLOBAL rate/volume feature, not buried.** The Linux GLOBAL-block MI
results above (2b) are directly implicated — a classifier trained on
`alert_count`/`max_rate_10s`/etc. cannot be distinguished, on this data,
from a classifier that has simply learned "which of the two capture
sessions is this." Recorded as the one collection gap for Phase 6
(a genuine high-rate *benign* Linux round is needed — no such data exists
to substitute).

**Windows: a genuine benign burst exists — designated as the benign-burst
control set.** The busiest 10-second window in the Windows benign
collection (2026-07-12 11:30:18–11:30:24, right at session start) contains
22 alerts — actual events, not a synthetic construction: 9× rule 92200
(various Sysmon process-creation detections), 6× rule 60106 (logon
success), plus 91823/91820/92052/92213/92217 — a **login/session-start
burst** (a user logging in and their profile/startup routine spawning
several processes in quick succession), not a package-update storm like
the prompt's example, but a legitimate high-rate benign event by the same
standard. Its peak rate (22/10s) actually *exceeds* the Windows attack
round's peak (11/10s) — **benign reaches 200% of attack's peak rate.** This
means the Windows EW MI results in 2b are NOT explained by the Linux-style
degeneracy: raw burstiness alone does not trivially separate Windows attack
from benign on this data, which is direct evidence (not proof, but a real
check that could have failed and didn't) that the Windows brute-force
signal found above is not a testbed-density artifact in the same way the
Linux one plausibly is.

## 2c. Counterfactual swap machinery (prepared; execution is Phase 4)

`swap_to_benign_typical()` / `swap_to_attack_typical()` implemented in
`ew_phase2_leakage_audit.py`, operating on the per-platform median values
below (full JSON: `ew_phase2_swap_medians.json`). No model exists yet to run
these against — that's Phase 4's job; this phase only prepares the machinery
and reports the value gap the swap will actually be moving alerts across.

| feature | lnx attack median | lnx benign median | win attack median | win benign median |
|---|--:|--:|--:|--:|
| `ew_global_trail60m_alert_count` | 11,006 | 133 | 205.5 | 100 |
| `ew_global_trail60m_max_rate_10s` | 4,104 | 4 | 9 | 22 |
| `ew_global_trail60m_distinct_url_count` | 4,557 | 3 | 0 | 0 |
| `ew_global_trail60m_path_repetition_ratio` | 0.570 | 0.971 | 0 | 0 |

The Linux `alert_count`/`max_rate_10s` gap (83×/1026×) is enormous — exactly
what 2e says to be suspicious of. The Windows gap for the same features is
small and, for `max_rate_10s`, inverted (benign median exceeds attack
median) — consistent with 2e's finding that Windows isn't degenerate the
same way. `distinct_url_count`/`path_repetition_ratio` are 0 for both Windows
arms (Windows alerts carry no URL field — expected, not a bug).

## Addendum — two gating checks run before Phase 3 (revises the Windows verdict above)

Two checks requested before Phase 3 could proceed, both confirming real
problems the burst-rate check above did not catch.

### Zero-failures check

Does the BENIGN collection ever contain an auth-failure-family alert at all
(Linux rule 5710/5712; Windows rule 60122/60204)?

| platform | attack: auth-fail alerts | benign: auth-fail alerts |
|---|--:|--:|
| lnx | 120 | **0** |
| win | 85 | **0** |

**Both platforms are zero.** This is the exact degeneracy pattern flagged
for Linux's alert-rate features in 2e — restated here for auth-failure
features specifically, and it was NOT caught by the burst-rate check,
because the Windows benign burst (2d) is a login/session-start sequence made
entirely of *successful* logins; it never contains a failed one. **This
directly retracts the "Windows brute-force EW features... genuinely
promising, passed the one check that could have falsified it" framing
above.** The check that mattered for THIS feature family (auth-failure
occurrence in benign) was never run in the first pass — the burst-rate check
answered a different question (does benign ever get busy) and happened to
pass, which is not the same as (does benign ever fail a login), which fails
completely. `auth_failure_count > 0` and `auth_success_after_failure_flag`
being informative on Windows is now equally suspect as a testbed-density
artifact, for the same underlying reason as Linux's volume features: the
benign capture round simply never contains the event type being counted.

### User-pivot composition check

Is the `ew_user_present==1` subset (the one behind the "min_interarrival_s
is a consistent cross-platform signal" claim above) actually just a
rule-identity proxy — one rule type populating the attack side, a different
rule type populating the benign side?

**Linux: yes, confirmed confounded.** In the 242-row user-present subset,
the attack side is 55.1% rule 5710 (ssh brute force — which per the
zero-failures check above has **zero** benign-side occurrences at all), and
the benign side is 70.3% rule 5501 (routine PAM login). The Linux
`ew_user_trail60m_min_interarrival_s` MI=0.29 result is very plausibly
"which rule type is this row" (fast-fire dictionary attack vs. sparse
routine logins) wearing a behavioral-feature costume, not genuine per-user
temporal behavior in the sense the EW thesis is testing for. **Retracted as
a clean cross-platform finding.**

**Windows: not the same failure mode, but not clean either.** Rule 92004
(PowerShell→cmd spawn) is the single largest rule on BOTH the attack (25.8%)
and benign (42.4%) sides of the user-present subset — so there's no
single-rule-per-class split the way Linux has. That's a genuine point in its
favor. But `60122`/`60204` (the auth-failure rules) are present only on the
attack side (75 + 8 occurrences, 0 in benign) within this same subset — the
zero-failures degeneracy is embedded inside the user-pivot composition too,
not just at the platform level. The Windows `min_interarrival_s` MI=0.55
number is a mix of a possibly-genuine PowerShell-timing signal and a
definitely-degenerate auth-failure-occurrence signal, not separable from
this check alone.

### Revised bottom line

**No feature family audited in Phase 2 has cleanly survived every check
run against it.** Linux volume/rate features fail the burst check. Windows
auth-failure features fail the zero-failures check (despite passing the
burst check — a reminder that one passed check does not clear a feature,
only the specific failure mode it tests for). The Linux user-pivot
`min_interarrival_s` result fails the rule-composition check. Only the web
scan (31101) mechanism — which Phase 3 examines directly, and where the
pre-registered claim was already downgraded to "mechanism, not
generalization" before any of this ran — remains to be checked on its own
terms; nothing above should be read as pre-clearing it, and nothing above
should be read as pre-condemning it either.

## Summary verdict for Phase 4 planning

- **Linux GLOBAL rate/volume features: proceed to Phase 4 only with the
  mirror-control swap (2c machinery, ready) run FIRST and reported at equal
  prominence to any recall gain.** If FPR explodes or the detection is shown
  to ride on `alert_count` alone under the swap, the honest-outcome rule
  requires downgrading the Linux volume-feature story to "testbed-density
  artifact," not "entity-window mechanism."
- **[SUPERSEDED by the addendum below — do not cite this bullet on its own]**
  ~~Windows brute-force EW features... genuinely promising, passed the one
  check that could have falsified it~~ — the zero-failures check (addendum)
  found the Windows benign collection has zero auth-failure alerts too,
  the same degeneracy pattern as Linux, just for a different feature family.
  `auth_failure_count`/`auth_success_after_failure_flag` need the same
  mirror-control treatment as the Linux volume features before Phase 4 can
  claim anything from them.
- **[SUPERSEDED by the addendum below]** ~~User-scoped `min_interarrival_s`
  is a consistent cross-platform signal~~ — confirmed rule-composition
  confounded on Linux (55.1% rule 5710, absent from benign entirely); mixed
  signal on Windows (no single-rule split, but the auth-failure rules within
  the user-present subset carry the same zero-failures problem). Not a clean
  finding on either platform as stated.
- **What actually remains untested going into Phase 3: only the 31101
  mechanism**, examined on its own terms, with the pre-registered
  mechanism-not-generalization downgrade already in place before Phase 3
  runs.
  reporting.
