# FIM Feature-Degeneracy Check (v8 follow-up)

Analysis only — nothing was trained, no pipeline code or existing artifact was modified.
Source data: `newCol/labeled_lnx.csv`, `newCol/labeled_win.csv`,
`newCol/collection_benign_{lnx,win}_alerts.json`, `models_v2/ocsvm_normalized.pkl`,
`models_v2/scaler_normalized.pkl`, `models_v2/imputer_normalized.pkl`. Full feature
table: `newCol/v8_fim_feature_table.csv`.

## Bottom line

The hypothesis is **confirmed in outcome but not in mechanism**. FIM detection is
genuinely weak and the cause is genuinely a coverage gap in the 22-feature schema —
but it is not NaN-imputation-driven (0% NaN throughout) and not literal vector
collapse to "a handful of vectors" (68.6% of FIM vectors are unique). The real
mechanism: the schema's per-rule override table forces the two most semantically
diagnostic features (`event_category`, `event_outcome`) to a **fixed constant per
rule_id** for the FIM rule family (550/553/554), regardless of what the file event
actually was. What little FIM recall exists is not file-integrity detection at all —
it's leakage from temporal proximity to unrelated scan/brute-force noise. Separately,
`ocsvm_normalized.pkl`'s saturation (the ~160.869 ceiling) is a distribution-shift
artifact affecting fresh data from *both* platforms, not a FIM-specific or
imputation-specific problem. The correct manuscript claim: **"the ECS
event-classification for the FIM rule family is under-specified, forcing FIM
separability onto coincidental temporal context rather than the file event
itself — a fixable coverage gap, not a fundamental weakness of the normalized
representation."**

---

## Task 1 — Feature-space autopsy

**Groups:** FIM attacks (rules 550/553/554, n=175), non-FIM attacks (rules
5710/5712/5901/5902/5903, n=131), fresh matched Linux benign (n=267).

**(a) Pre-imputation NaN rate: 0.00% in every group.** `extract_normalized()` never
emits true NaN — every field has an explicit fallback. The imputer is a no-op on
this data; the "NaN→imputed" mechanism in the original hypothesis does not apply.

**(b)/(c) Post-imputation constant-feature count:** FIM = 8/22, non-FIM = 8/22
(tied), benign = 11/22 (worse than either attack group). FIM is not uniquely
degenerate in aggregate.

**(d) Vector collapse:** FIM 175→120 unique vectors (68.6% unique, 31.4% duplicate
rate) vs. non-FIM 131→123 unique (93.9% unique, 6.1% duplicate) vs. benign 267→96
unique (36.0% unique, 64% duplicate — worse than FIM). FIM shows real, measurable
collapse relative to non-FIM attacks, but nowhere near "a handful of vectors," and
benign alerts collapse more than FIM attacks do.

**Full feature table:** see `newCol/v8_fim_feature_table.csv`. Key columns: NaN%
(FIM/non-FIM/benign), distinct values, variance, per feature.

**Verdict: partial.** Real effect, wrong mechanism as originally framed. The actual
cause, found by reading `_classify_rule()`/`_RULE_OVERRIDES` in `normalize_schema.py`:
rules 550 and 554 have hardcoded per-rule category overrides; rule 553 falls into
the same group-based bucket. Result: `event_category` and `event_outcome` are
**perfectly constant across all 175 FIM alerts** (always `EC_FILE`/`EO_UNKNOWN`).
The features that do vary within the FIM group (`time_since_last_high`: 53 distinct
values, `failed_login_5min`: 13, `alert_rate_1min`: 7) are temporal/behavioral
context, not anything about the file event itself.

---

## Task 2 — Explaining the identical 12/79 (and 3/96) counts

Note first: T1053.003/T1543.002/T1546.004 sharing "12/79" is **trivially expected**,
not evidence of anything — those three techniques map to the identical
discriminative rule set `{553,554}` (n=79) in the project's technique→rule table,
so they score the same 79 alerts three times under three labels. The real,
non-trivial data point is T1098.004's "3/96" (rule 550 alone).

**(a) Same alert indices across candidates: yes, exactly.** C1, C2, and C3 —
trained on different benign mixes — detect the **identical 15 of 175** FIM alerts
(554: 12/59, 553: 0/20, 550: 3/96). Zero disagreement between any pair. Three
independently-trained models converging on a byte-identical detection set indicates
a wide-margin, near-discrete separator, not a genuinely learned continuous boundary.

**(b) Vector-group alignment: perfect.** 120 unique vectors, 23 duplicate-vector
groups (size≥2); **0 have split detection** for any candidate — every group sharing
an identical vector is entirely detected or entirely missed.

**(c) What separates detected (n=15) from missed (n=160):**

| feature | detected | missed |
|---|---|---|
| `scan_preceded` | always 1 | mostly 0 |
| `brute_preceded` | always 1 | mostly 0 |
| `unique_src_ip_10min` | always 1 | mostly 0 |
| `failed_login_5min` | median 13 | median 0 |

The 15 detected FIM alerts are not distinguished by anything about the file event —
`event_category`/`event_outcome` are constant across all 175 (Task 1). They're
distinguished by landing inside an `AgentHistory` window still carrying recent
failed-login/scan noise from a *different* attack stage. **It's guilt by temporal
association with unrelated auth/scan activity, not file-integrity detection.** The
other 160 FIM alerts, occurring without that coincidental noise nearby, are
invisible to all three candidates identically. Detail:
`newCol/v8_fim_task2_detected_vs_missed.csv`.

---

## Task 3 — REF ceiling explanation

| test | score | vs. ceiling (160.869) |
|---|--:|---|
| synthetic all-imputed-constant vector | **6.85** | 154.0 away — nowhere near |
| fresh Linux benign (n=267) | median 160.869 | 96.3% within 0.01, 98.5% within 1.0 |
| fresh Windows benign (n=201) | median 160.847 | 47.3% within 0.01, 92.0% within 1.0 |
| AIT-ADS test benign (REF's own training distribution) | median −17.46 | far below |
| AIT-ADS test attack (same) | median 12.51 | far below |

**Verdict: distribution-shift-driven, not imputation-driven.** The synthetic
median-everything vector scores a mundane 6.85 — near the AIT-ADS training center,
not remotely anomalous. If saturation were imputation-driven, that vector would sit
at the ceiling too; it doesn't. Fresh data from *both* platforms lands overwhelmingly
at 160.869 — the RBF-kernel OC-SVM's mathematical ceiling (the value
`decision_function` converges to when every kernel similarity to every support
vector is ≈0). AIT-ADS's own test data reaches this ceiling only in a thin tail
(medians −17.5/+12.5). REF is not blind to Windows specifically — it's blind to
anything that isn't AIT-ADS-shaped, Linux included.

---

## Task 4 — Fixability sketch (no code, no schema changes made)

Field-presence check across all 175 FIM alerts (not just samples):
`path`/`event`/`size_after`/`perm_after`/`uid_after`/`uname_after`/`mtime_after`
present in **100%**; `changed_attributes`/`size_before`/`diff`/`mtime_before` present
in **54.9%** (96/175 — "modified" events only; "added"/"deleted" have no prior state).

**Additional finding along the way:** of rule 550's 96 alerts, only **6** actually
touch `/root/.ssh` (the real T1098.004 signal). The other 90 are `/etc/passwd-`,
`/etc/shadow.lock`, `/etc/group-`, `/etc/subuid-`, etc. — incidental lock/backup
files `useradd`/`usermod` create as a side effect, most likely leakage from the
co-occurring T1136.001 (create-local-user) activity. "T1098.004 n=96" currently
conflates two very different populations that a path-aware feature would split
immediately.

| # | candidate feature | source field (presence) | proposed encoding | technique(s) separated |
|---|---|---|---|---|
| 1 | `syscheck_persistence_path_class` | `syscheck.path` (100%) | categorical: cron / systemd / profile.d / ssh-key / other, by path match | **all four** — directly the information currently discarded |
| 2 | `syscheck_content_changed` | `syscheck.changed_attributes` (54.9%) | binary: hash attribute (md5/sha1/sha256) changed vs. metadata-only | T1098.004 |
| 3 | `syscheck_size_delta_bucket` | `syscheck.size_before`/`size_after` (54.9%) | discretized: shrink-to-zero / shrink / unchanged / grow | T1098.004 |
| 4 | `syscheck_owner_root_and_perm_flags` | `syscheck.uid_after`/`uname_after`, `syscheck.perm_after` (100%) | two binaries: owned-by-root, setuid-or-world-writable | T1546.004, T1543.002 |
| 5 | `syscheck_diff_has_key_pattern` | `syscheck.diff` (54.9%) | binary regex: `ssh-rsa\|ssh-ed25519\|ssh-dss` in diff text | T1098.004 (near-ground-truth: matches exactly the 6 genuine `/root/.ssh` alerts, not the 90 incidental ones) |

`normalize_schema.py` was not modified — this is a proposal for future work, not an
implementation.
