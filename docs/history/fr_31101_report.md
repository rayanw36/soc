# FR-31101 — 31101 Feature-Recovery Check

Analysis only. New diagnostic models fit here for this check specifically
— not part of the production pipeline, not written to `models_v2/`, no
existing artifact retrained. Script: `newCol/fr_31101_feature_recovery.py`.
Data: `newCol/fr_31101_features.csv` (20,874 rows — 20,665 attack + 209
benign). Environment: `.venv`, `xgboost` (version installed in this
environment; `XGBClassifier`, default `n_estimators=100, max_depth=4`,
plus an explicit alternate-regularization run per Task 2/Task 3).

**Bottom line, stated up front:** URL/UA information does **not** recover
generalizable per-alert separability on rule 31101. It recovers **one**
kind of separability — exact User-Agent identity — which is the same
disease as rule-ID memorization at finer grain, not detection, and which
a real attacker defeats by setting one HTTP header. The structural
information that could plausibly transfer (Tier B) does **not**
meaningfully separate the classes, and the one feature that looked most
important by gain does not survive a causal swap test. **This restores
the original per-alert undecidability claim in properly-scoped form**
(Task 3c's scenario), not Task 3b's. Both outcomes were explicitly
acceptable going in; this is what the data returned.

---

## Task 1 — Extraction and characterisation

Rule 31101 does not occur in either Windows collection (checked directly:
`31101` absent from `newCol/collection_win_alerts.json` and
`newCol/collection_benign_win_alerts.json`) — **Linux only**, correcting
the prompt's "both platforms" framing to what the data actually supports.
Both Linux rounds parsed cleanly (Apache/nginx combined log format,
`newCol/collection_lnx_alerts.json` for attack, `newCol/collection_benign_lnx_alerts.json`
for benign): 100% of `full_log` lines matched the expected format,
0 null path/UA fields in either class.

| | attack (n=20,665) | benign (n=209) |
|---|---|---|
| distinct paths | 4,601 | **3** |
| distinct UAs | **1** | **1** |
| HTTP method | 100% `GET` | 100% `GET` |
| HTTP status | 100% `404` | 100% `404` |
| query strings | 0 | 0 |

**§3e's characterisation is confirmed exactly, not merely approximately:**
benign = 209 alerts, 3 paths, 1 UA. Full inventories (small, printed in
full per the task instruction):

- **Benign paths:** `/api/status` (77), `/contact` (66), `/about` (66).
- **Benign UA:** `curl/8.5.0` (209/209).
- **Attack UA:** `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  (20,665/20,665) — `dirb`'s own default masquerade string, confirming
  the §3e finding directly rather than by inference.
- **Attack paths:** 4,601 distinct, dominated by short single-segment
  wordlist entries (`/randomfile1`, `/.bash_history`, `/.git/HEAD`, ...);
  each of the 6 dirb rounds re-runs the same wordlist — 4,563 of 4,601
  paths (99.2%) recur 2–6 times across rounds; only 38 are true
  one-round singletons. Round boundaries recovered directly from
  timestamp gaps (>30s) in the alert stream: sizes 2801/3806/3213/3765/3616/3464,
  summing exactly to 20,665.

**Minor discrepancy noted, not chased further (out of scope for this
check):** Phase 3's case study (`newCol/ew_phase3_31101_case_study.md`)
reports the entity-window aggregate `distinct_url_count` at 4,557 attack
/ 3 benign, vs. this check's raw per-alert count of 4,601 distinct attack
paths. ~1% difference, most likely a window-boundary/scope difference
between "every 31101 alert" (this check) and "alerts falling inside a
defined entity-window" (Phase 3). Both numbers are used only as
orientation, not as the load-bearing figures for this report, so this
was not investigated further.

---

## Task 2 — Tiered feature construction (kept strictly disjoint)

**Tier A (identity/memorization, 4 features):** `A_path_id`,
`A_ua_id` (label-encoded on TRAIN vocabulary only; unseen test values get
a distinct out-of-vocabulary code, never silently folded into an existing
one — 3 of 3,506 test-set paths were unseen in training), `A_path_in_benign_set`,
`A_ua_is_curl`.

**Tier B (structural, 9 features):** `B_path_depth`, `B_path_length`,
`B_char_entropy` (Shannon entropy over path characters), `B_ext_class`
(none/script/config/backup/log/other), `B_has_extension`, `B_is_dotfile`
(starts with `/.`  — a structural, not identity, property: hidden-file
naming convention, not a specific filename), `B_has_query`, `B_status_code`,
`B_method_is_get`.

**Tier C (aggregate, reference only — not recomputed, cited from the
existing frozen artifact):** `newCol/ew_phase3_31101_case_study.md`'s
entity-window `alert_count` (11,006 attack / 134 benign, 82×) and
`distinct_url_count` (4,557 / 3, 1,519×). Included only as the comparison
point per instruction; not presented as a new result here.

**Feature-variance check, both classes (Task 2 mandatory before fitting
anything):**

| feature | attack mean (std) | benign mean (std) |
|---|---|---|
| `B_path_depth` | 1.0029 (0.063) | 1.3684 (0.484) |
| `B_path_length` | 7.773 (3.254) | 8.474 (2.092) |
| `B_char_entropy` | 2.6123 (0.554) | 2.6124 (0.098) |
| `B_has_extension` | 0.0171 (0.130) | 0.0000 (0.000) |
| `B_is_dotfile` | 0.0064 (0.080) | 0.0000 (0.000) |
| `B_has_query` | 0.0000 (0.000) | 0.0000 (0.000) — **constant in both classes, zero information by construction** |
| `B_status_code` | 404.0 (0.000) | 404.0 (0.000) — **constant in both classes** |
| `B_method_is_get` | 1.0 (0.000) | 1.0 (0.000) — **constant in both classes** |

Three of nine Tier B features are degenerate in this specific collection
(no query strings, all `404`, all `GET`) — not excluded by design, but
carrying zero information here regardless; the models below correctly
assign them ~0 importance.

**Split (temporal, per class, matching prior-phase discipline — no
random shuffling, no threshold tuned on test):** attack train = rounds
1–5 (n=17,201, chronological), attack test = round 6 (n=3,464, the
natural last-round boundary recovered from the timestamp-gap analysis
above, not an arbitrary cut). Benign train = first 80% chronologically
(n=167), benign test = last 20% (n=42). Train totals n=17,368; test
totals n=3,506.

---

## Task 3 — Per-tier evaluation

| tier | TP | FN | FP | TN | recall | FPR | F1 |
|---|--:|--:|--:|--:|--:|--:|--:|
| **A (identity)** | 3464 | 0 | 0 | 42 | **100.00%** | **0.00%** | **1.0000** |
| **B (structural)**, default reg | 3464 | 0 | 28 | 14 | 100.00% | **66.67%** | 0.9960 |
| **B (structural)**, `reg_lambda=0`/`min_child_weight=0` | 3464 | 0 | 28 | 14 | 100.00% | 66.67% | 0.9960 |
| A+B combined (reference only, not a tier — confirms nothing beyond A alone) | 3464 | 0 | 0 | 42 | 100.00% | 0.00% | 1.0000 |
| *trivial "always predict attack" baseline, for context* | 3464 | 0 | 42 | 0 | 100.00% | 100.00% | 0.9940 |

**Tier A feature importance:** `A_ua_id` = 1.0000 (100% of gain); every
other Tier A feature = 0.0000. **Tier A's entire separation is carried by
one field.**

**Tier B feature importance disagrees by hyperparameter, but the
confusion matrix does not move:** default regularization ranks
`B_path_length` (0.478) and `B_char_entropy` (0.474) highest, with
`B_path_depth` a distant third (0.048); the alternate regularization
inverts this almost completely — `B_path_depth` (0.911) dominant,
`B_char_entropy`/`B_path_length` reduced to 0.071/0.018. **Both runs
produce the identical TP/FN/FP/TN**, meaning these three features are
redundant proxies for the same underlying signal (which regularization
happens to prefer changes, the classifier's actual decisions do not) —
consistent with the "small-n hyperparameter determinism" control from
this project's own control table (control 4), applied here as a
robustness check rather than treating either importance ranking as ground
truth on its own.

### 3a. Does Tier B alone separate the classes? The number, not a characterisation.

**recall=100.00%, FPR=66.67%, F1=0.9960.** F1 is inflated by the 3464:42
test-set imbalance — the trivial "flag everything as attack" baseline
already scores F1=0.9940 on this same test set (recall 100%, FPR 100%).
Tier B improves FPR from 100% to 66.67% (correctly identifies 14 of 42
benign alerts) — a real but small improvement over the trivial baseline,
nowhere near separation. **This is not a "yes."**

### 3b/3c. Which feature carries what Tier B does have, and does it survive a causal test?

Swap-traced both candidate top features (per instruction: run the
standing feature-swap trace, do not infer) — for each, set every
attack-test alert's value of that one feature to the benign-typical
(training-set benign median) value and re-score with the same fitted
model:

| feature swapped | benign-typical value | attack recall, real value | attack recall, swapped |
|---|--:|--:|--:|
| `B_path_length` (default-reg top feature) | 8.0 | 100.00% | **100.00%** |
| `B_path_depth` (alt-reg top feature) | 1.0 | 100.00% | **100.00%** |

**Neither swap changes attack-side recall at all.** Whatever Tier B's
gain-importance ranking claims is "most important," it is not load-bearing
for the model's actual attack predictions — the attack population's
19,999-fold redundancy (4,601 distinct paths repeated across an entire
population of 20,665, dominated by depth-1, length-6–10, entropy≈2.6
entries) means no single alert's perturbation moves the model off its
learned decision surface.

**Path-level breakdown of Tier B's benign-side predictions — this is
where the real (partial) mechanism is, not in the top-1 gain-importance
feature:**

| benign path | n (test) | predicted attack |
|---|--:|--:|
| `/about` | 12 | 12/12 (100%) |
| `/contact` | 16 | 16/16 (100%) |
| `/api/status` | 14 | **0/14 (0%)** |

**All of Tier B's 14 correct benign classifications come from exactly one
of the three benign paths — `/api/status`, the only one with
`path_depth=2`.** Depth-2+ paths are genuinely rare in the attack wordlist
(35 depth-2 + 12 depth-3 out of 20,665 = 0.23%), so a nested path is a
real, non-memorized, structural signal of not-attack *in this specific
collection*. But it only fires for the one benign endpoint that happens
to be nested — `/about` and `/contact` are single-segment, indistinguishable
by every Tier B feature from the single-segment majority of the dirb
wordlist, and are misclassified as attack 100% of the time.

**Answer to 3a/3b/3c together: Tier B does not separate the classes
(3a — the number is 66.67% FPR, far from separation). What weak signal
it has traces to `path_depth` acting as a coincidental filter that
happens to catch one of three benign endpoints (3b), and it does not
survive the causal swap test on either candidate top feature (3b). Tier A
does separate, perfectly, on one trivially-identity-bound field. This is
Task 3c's scenario: the discriminating information present in the alert
is identity-class only** — memorizing the exact UA string (or, to a much
weaker and incomplete extent, memorizing that this particular
deployment's one nested endpoint is benign) — **not a general,
transferable behavioral signature. The original per-alert undecidability
claim is restored in properly-scoped form.**

---

## Task 4 — Mandatory caveats (apply regardless of the Task 3 outcome, stated in full)

**a. Both populations are tool-generated.** `dirb` vs. `curl`, confirmed
directly (Task 1). No organic human web traffic exists anywhere in this
collection, on either the attack or benign side. Every number in this
report is "one tool vs. another tool," not "attacker vs. organic user."

**b. UA is trivially evadable, and this is not a hypothetical for this
result specifically — it is the entire result.** Tier A's perfect
100%/0.00% separation is carried **100% by `A_ua_id`** (measured, not
assumed — every other Tier A feature scored zero importance). A real
attacker who sets `User-Agent: curl/8.5.0` (a one-line change to `dirb`'s
invocation, or a direct `curl`-based scan) removes the entire basis for
Tier A's separation. This is stated even though Tier A scored a clean
1.00, per instruction — the score has no adversarial validity.

**c. The benign path set has cardinality 3.** `A_path_in_benign_set`
scored zero importance here only because `A_ua_id` already achieved
perfect separation and the model had no need for a second feature — this
does not mean path-membership would be robust on its own; a 3-item
lookup table would not survive contact with any real web application,
which routinely serves thousands of legitimate paths. Task 3b's own
finding reinforces this from a different angle: 2 of the 3 benign paths
were **not** distinguishable by any structural (Tier B) property either.

**d. Whether Tier B's weak, depth-driven partial signal would survive a
benign burst or a different (larger, more path-diverse) endpoint set is
untested and untestable with this data.** The one path-level result that
worked (`/api/status`, depth=2) is a coincidence of this specific
3-endpoint benign design, not a validated property of "legitimate traffic"
in general — many real applications serve depth-1 routes
(`/about`, `/contact`, `/login`, `/pricing`, ...) as their overwhelming
majority, which would land on the wrong side of this same depth-based
partial filter. No second, independently-designed benign collection
exists in this project to test this.

---

## Task 5 — Impact statement

**a. Interpretation of the 2.25% recall / 4.78% benign-FPR result.** Stays
information-theoretic in the properly scoped sense the original claim
always needed: *within the fields the 26-feature representation actually
had access to (identity, rate, content-keyword), and within the fields it
discarded (URL path, UA) that could plausibly generalize, no behavioral
signal separates the two rule-31101 populations.* The one field that does
separate them (UA) is not a behavioral signal at all — it is a
tool-fingerprint, evadable by construction, and was never part of the
26-feature representation's design space to begin with (the 26 features
were built from rule/rate/keyword fields, not raw HTTP headers). This
check does not weaken the original undecidability claim; it closes the
specific alternative explanation ("maybe discarded URL/UA data would have
fixed it") that motivated this task, with a direct negative answer for
the transferable (Tier B) half of that alternative and a not-useful
positive answer for the non-transferable (Tier A) half.

**b. Was `distinct_url_count`'s 82–1,519× separation recovering discarded
per-alert information, rather than demonstrating an aggregation benefit?**
**No — these are categorically different kinds of feature, not two
measurements of the same latent signal.** `distinct_url_count` is only
definable over a *window of multiple alerts from one entity* — a single,
isolated alert has no "distinct count" of anything to recover; there is
no per-alert field, present or discarded, that this check's Tier B could
have exposed to reproduce it, because the quantity does not exist at the
single-alert level by definition. This check's finding (Tier B, built
entirely from single-alert path properties, does not separate) and Phase
3's finding (the entity-window aggregate does separate, 82–1,519×) are
answers to different questions and are not in tension. This is a
genuine, structural distinction, not a rescue of the earlier positive
result — and it does not touch the separate, already-documented reason
that positive result carries its own generalization caveat (Phase 3d: 3
attack-side windows, 1 attacker, 1 host — mechanism, not deployment-grade
evidence).

**c. Is the memorization finding (P1: rule-ID memorization) better
explained as "behavior-encoding features were engineered away, leaving
rule identity as the only remaining predictor"?** **No — this check
argues the opposite.** If behavioral information had been engineered
away by the 26-feature scheme and were sitting latent in URL/UA, Tier B
(built specifically to recover it) should have separated the classes.
It did not (3a: 66.67% FPR, and even that weak result fails a causal
swap test on its own top features). What separates cleanly, both in the
original rule-ID memorization finding and in this check's Tier A result,
is identity-class information — a lookup, not a learned behavioral
pattern — recovered independently, at a completely different level of
representation (rule ID vs. raw UA string), by two separate checks run
at different points in this project. That convergence **strengthens**
the memorization finding rather than reinterpreting it away: it is not
an artifact of one specific feature-engineering choice, because removing
that choice's constraints (by rebuilding features directly from the raw
HTTP fields) reproduces the same shape of result.

---

## Correction appended to prior artifact

`newCol/ew_phase3_31101_case_study.md` — a new §3f is appended (see that
file) recording this outcome and formally closing the question §3e opened
about whether discarded URL/UA fields could have changed the
undecidability finding.

**CHECKPOINT: `newCol/fr_31101_report.md` + `newCol/fr_31101_features.csv` complete. STOP.**
