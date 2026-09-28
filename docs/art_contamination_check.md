# ART-C — Post-Attack Artifact Persistence Contamination Check

**Scope:** `lnx-dmz` only (the platform this hypothesis was raised for). No
collection, no retraining, no threshold changes — forensic check against
already-collected data only, per the governing rules. Existing artifacts
(`models_v2/*.pkl`, `newCol/collection_*`, `newCol/labeled_lnx.csv`, etc.)
are read-only; this file and `newCol/art_contamination_paths.csv` are the
only new artifacts.

**Hypothesis under test:** the attack rounds (2026-07-08) ran before the
benign round (2026-07-12), on the same host. Five of the six novel
techniques install artifacts designed to persist. If cleanup did not run,
those artifacts could still have been present four days later and some
benign-labeled false positives could actually be leftover attack residue.

**Headline result, stated up front:** direct evidence rules this out for
every persistence artifact this check can name. Cleanup is directly
confirmed for the rounds the surviving audit log covers, and every
benign-window FIM/syscheck alert path-matches to something unrelated (CUPS
housekeeping and one organic SSH `known_hosts` entry), not to any
ART-created path or account name, across the full 267-alert benign
collection and specifically across all 29 false positives behind the
10.86% FPR. This is a negative result, and per the honest-outcome rule it
is reported as a genuine, valuable finding, not softened or searched past.

---

## Task 1 — What ART actually created

**Evidence source:** `newCol/audit_lnxdmz.log`, the `auditd` log for the
2026-07-08 `lnx-dmz` attack session, tagged with audit key
`atomictest_exec` on the relevant `execve` calls. Verified byte-identical
(`diff -q`, zero output) to the copy of the same filename inside
`collection_lnx_alerts.zip`, confirming this is the actual archived log
for that session, not a separately truncated excerpt introduced later.

**Coverage caveat (load-bearing for what follows):** the log's own first
record is timestamped `2026-07-08T20:42:43Z` — this is not round 1, it is
**round 5's** `T1136.001` step, per exact match against
`newCol/collect_markers_lnx.txt`. The log contains **no records for rounds
1–4, and no records for round 5 before its `T1136.001` step** (i.e. round
5's own `T1053.003`/`T1543.002`/`T1098.004` steps are also missing). It
does fully cover round 5's `T1136.001`/`T1546.004` tail, all of round 6
(all six techniques, KNOWN and NOVEL), and roughly 29 minutes past
collection end (through the archival `cp` at `21:17:02Z`). This gap exists
in the archived log itself — it is a property of the collected evidence,
not an artifact of how this repository stored it. Per the no-fabrication
rule, artifact names below are marked **CONFIRMED** only where the log
directly shows them, and **not directly confirmed** elsewhere.

| technique | artifact | round 6 (full) | round 5 (`T1136.001` leg only) | rounds 1–4 |
|---|---|---|---|---|
| T1053.003 (cron) | `/etc/cron.d/col_cron` | **CONFIRMED** — `tee /etc/systemd/system/col_svc.service`-style write at `20:45:55Z` (line 5197/5318), matches round 6 `T1053.003` START exactly | not in log range | not directly confirmed |
| T1543.002 (systemd) | `/etc/systemd/system/col_svc.service` | **CONFIRMED** — `tee` write at `20:46:21Z` (line 5841/5962), matches round 6 `T1543.002` START exactly; never `enable`d or `start`ed (no such call anywhere in the log) | not in log range | not directly confirmed |
| T1546.004 (shell-rc) | `/etc/profile.d/col_profile.sh` | **CONFIRMED** — `tee -a` at `20:47:41Z` (line 7686/7807), matches round 6 `T1546.004` START exactly | not in log range | not directly confirmed |
| T1098.004 (ssh-keys) | `/root/.ssh/authorized_keys`, appended line tagged with marker string `COLLECTNOVEL` | **CONFIRMED** — `mkdir -p /root/.ssh` + `tee -a .../authorized_keys` at `20:46:48Z` (line 6372–6622), matches round 6 `T1098.004` START exactly | not in log range | not directly confirmed |
| T1136.001 (create-user) | account `coluser` (uid/gid 1001, home `/home/coluser`) | **CONFIRMED** — `useradd -m coluser` at `20:47:14Z` (line 6918+), matches round 6 `T1136.001` START exactly | **CONFIRMED** — `useradd`/`ADD_USER` records at `20:42:43Z` (line 63–95), matches round 5 `T1136.001` START exactly | not directly confirmed |

**Inference, labeled as inference:** `collect_markers_lnx.txt` shows all
six rounds running the identical technique sequence at near-identical
per-step durations (e.g. every round's `T1053.003` takes 18–19s, same
order, same technique set) — consistent with one fixed script invoked six
times. If so, rounds 1–4 used the same artifact names. This is a
reasonable inference from the script's own repeated-timing signature, but
it is **not** something the surviving log evidence directly shows, and it
is reported here as inference, not fact, per the instruction not to infer
exact names from the ART catalog generally.

---

## Task 2 — Cleanup evidence

**Cleanup confirmed** for round 5 and round 6, directly, from `execve`
records:

- Round 5 end (`20:43:37Z`, immediately after `T1546.004` END and
  immediately before the round's `BASELINE quiet 90s`): `rm -f
  /etc/cron.d/col_cron /etc/systemd/system/col_svc.service
  /etc/profile.d/col_profile.sh` (line 778/899) → `sed -i
  '/COLLECTNOVEL/d' /root/.ssh/authorized_keys` (line 907/1033, surgical
  marker-based removal of just the appended line, not the whole file) →
  `userdel -r coluser` (line 1045/1182, confirmed by `DEL_USER`/`DEL_GROUP`
  success records) → `systemctl daemon-reload` (line 1420/1541). All five
  artifact classes, in well under one second, clearly one scripted
  teardown step.
- Round 6 end (`20:48:07–08Z`, immediately after `T1546.004` END and the
  `EXPORT_TO`/`COLLECTION DONE` markers): the **identical** four-command
  sequence runs twice in a row (line 8085 and again at line 9098) —
  `rm -f` the same three files, `sed` the same marker line, `userdel -r
  coluser`. The second pass's `userdel` fails with `deleting user not
  found` (line 9490, `res=failed`), i.e. it is a harmless no-op re-run
  against an account already removed by the first pass, not evidence of
  incomplete cleanup.
- No `col_`-prefixed path or `coluser` reference appears anywhere in the
  log after `20:48:08Z`, through the last record at `21:17:02Z` (checked
  directly, not inferred) — nothing resurfaced in the ~29 minutes of
  post-collection log this file still covers.
- The systemd unit was created and `daemon-reload`d but **never
  `enable`d or `start`ed** at any point in the log — so even absent
  cleanup, it had no boot/restart trigger to persist through. This
  narrows the systemd technique's actual risk before cleanup is even
  considered.

**Rounds 1–4: cannot determine directly** — outside the log's coverage
window (Task 1). Given the scripted, identical-per-round structure and
that a dedicated marker-based cleanup routine clearly exists and ran
correctly twice in the covered rounds, it is reasonable to expect the same
step ran after every round — but this is inference, not confirmed
evidence, and is reported as such rather than assumed because it "would be
good practice."

**Verdict: cleanup confirmed** for the rounds the evidence covers (5, 6);
**cannot determine** for rounds 1–4, with the same caveat carried into
Task 3's interpretation.

---

## Task 3 — Path matching against the benign window

**Method:** `newCol/art_contamination_check.py`. Loads the fresh Linux
benign collection (267 alerts) via the existing, unmodified
`extract_benign_features()` (same function `f1_phaseA_v5defer.py` uses),
re-scores every alert through the identical production v5-defer path
(`combined_decision_v6.score_alert`, `models_v2/ocsvm_nu05.pkl`) to get
the exact same 29 false positives reported elsewhere in this study, then
for every one of the 267 alerts checks `syscheck.path` (and, separately,
every alert's full JSON body for the strings `coluser` and `COLLECTNOVEL`)
against the Task 1 artifact list. Full per-alert output:
`newCol/art_contamination_paths.csv`.

**a/b. All benign-window syscheck alerts.** Rules 550/553/554 are the only
syscheck-family rules present (9 alerts total: 550×6, 554×2, 553×1; no
other syscheck rule fires in this collection). Every one of the 9:

| rule | timestamp | path | event |
|---|---|---|---|
| 550 | 11:12:27.175 | `/etc/cups/subscriptions.conf` | modified |
| 550 | 11:12:27.450 | `/etc/cups/subscriptions.conf.O` | modified |
| 554 | 11:15:06.697 | `/etc/cups/subscriptions.conf.N` | added |
| 550 | 11:15:06.800 | `/etc/cups/subscriptions.conf` | modified |
| 553 | 11:15:06.805 | `/etc/cups/subscriptions.conf.N` | deleted |
| 550 | 11:15:06.810 | `/etc/cups/subscriptions.conf.O` | modified |
| 554 | 11:19:49.016 | `/home/lnx-dmz/.ssh/known_hosts` | added |
| 550 | 12:13:30.031 | `/etc/cups/subscriptions.conf` | modified |
| 550 | 12:13:30.046 | `/etc/cups/subscriptions.conf.O` | modified |

Bucket for all 9: **unrelated**. Eight are CUPS's own internal
subscription-lease bookkeeping under `/etc/cups/` — already documented as
routine, non-scripted background activity in
`newCol/benign_fim_collection_runbook.md`'s path-monitoring table, not a
path any Task 1 artifact touches. The ninth (`known_hosts`, round-trip SSH
client behavior) sits under `/home/lnx-dmz/.ssh/`, a different directory
tree than the technique's actual target, `/root/.ssh/authorized_keys` —
the same runbook explicitly lists these as two separate, independently
confirmed path classes, one attack-associated and one organic. No exact
match; **no directory-class match either**, once the specific directory
the technique used (`/root/.ssh/`, not a generic `/home/*/.ssh/`) is
applied precisely rather than loosely.

**c. The 29 false positives specifically.** All 29 re-derived exactly
(matches `newCol/a8_fp_rule_breakdown.csv` and `f1_final_summary.md`
per-rule and total). Bucket breakdown:

| bucket | count |
|---|---|
| exact match | 0 |
| directory-class match only | 0 |
| unrelated | 29 |

The 5 FIM-rule FPs among the 29 (550×3, 553×1, 554×1) are the CUPS/
known-hosts alerts above. The other 24 (31101×10, 5402×10, 52002×2,
5502×1, 5501×1) carry no `syscheck.path` at all (they are web-scan, sudo,
AppArmor, and PAM-session rules, not FIM rules) and were separately
checked, full-body, for any reference to `coluser`, `col_cron`,
`col_svc`, `col_profile`, or `COLLECTNOVEL` — none found. Spot-checked
`full_log` content for 5402/5501/5502/52002 confirms routine `apt-get`,
`systemd-user`/`polkit-1` sessions, and AppArmor denials — nothing
referencing any Task 1 artifact.

**d. Account-name reference check.** Searched all 267 benign-window
alerts (every field, not just `syscheck.path`) for the literal string
`coluser`: **zero matches**, across the full collection and across the 29
FPs. No benign alert references the ART-created account by name.

---

## Task 4 — Periodicity check

Raw inter-arrival intervals, rules 550/553/554, chronological (the only
rules with fire timestamps relevant to a hypothetical residual
`T1053.003` cron job):

| from → to | Δt |
|---|---|
| 11:12:27.175 → 11:12:27.450 | 0.275s |
| 11:12:27.450 → 11:15:06.697 | 159.247s |
| 11:15:06.697 → 11:15:06.800 | 0.103s |
| 11:15:06.800 → 11:15:06.805 | 0.005s |
| 11:15:06.805 → 11:15:06.810 | 0.005s |
| 11:15:06.810 → 11:19:49.016 | 282.206s |
| 11:19:49.016 → 12:13:30.031 | 3221.015s |
| 12:13:30.031 → 12:13:30.046 | 0.015s |

**Verdict: not periodic.** The pattern is two tight sub-second clusters
(multiple syscheck events from a single file-write operation touching a
file and its `.O`/`.N` shadow copies — the expected signature of one edit,
not recurring activity) separated by irregular gaps of 159s, 282s, and
3221s (~53.7 minutes). A cron job on any fixed short schedule (the
hypothesis names 1/5/10-minute intervals) would produce far more numerous,
evenly-spaced hits across the full ~60-minute benign window
(`11:20:13`–`12:20:24` per `newCol/benign_markers_lnx.txt`); instead there
are 4 irregularly-spaced clusters total, with one gap alone spanning
nearly the whole window. This is independent, confirmatory evidence
against contamination — consistent with, not contradicting, the path-match
result in Task 3.

(Note, not otherwise relevant to this check: alert timestamps here run
~8 minutes before the marker file's stated `BENIGN_START`, consistent with
ordinary export-margin padding of the kind documented elsewhere in this
project's collection convention, not a new finding.)

---

## Task 5 — Impact scope

**Unaffected — verified, not assumed:**
- The rule-ID memorization audit (31101 raw-L1 behavior) — no persistence
  artifact touches rule 31101 at all; its benign alerts are ordinary web
  traffic to the DMZ host, confirmed unrelated in Task 3c.
- 31101 per-alert undecidability (2.25% recall vs. 4.78%/4.8% benign
  FPR) — same reasoning.
- The 135.2× Linux tempo asymmetry — this check adds no attack-rate
  alerts to the benign window; contamination, had it existed, could only
  ever have added alert volume, never explained an *absence* (of burst,
  of auth failures), so this finding was never at risk from this
  hypothesis regardless of outcome.
- The absent benign burst and the zero benign auth-failures (5710/5712)
  — same reasoning; contamination cannot explain a rule that fires *zero*
  times.

**Candidate for effect, resolved negative:** the per-rule FPR table
(550/553/554, each resting on benign N=1/2/6) and the precision term of
F1=0.8702 were the two places this check could, in principle, have
changed something. It did not. Every alert behind those FPR figures
path-matches to routine CUPS/SSH-client activity, not to any named ART
artifact, and the one rule family theoretically at risk from a residual
cron job (via 550/553/554, since `T1053.003`'s own target directory
`/etc/cron.d/` is FIM-watched) shows no periodicity signature at all.

**Stated the way the rules require:** this is not a recovered positive
result, and there was never a directional question to resolve once the
match came back empty — the 550/553/554 FPR figures and the F1=0.8702
precision term stand exactly as previously reported. What this check adds
is a closed threat to validity: the alternative explanation "these are
leftover attack artifacts, not genuine benign false positives" is now
directly checked, for the specific artifacts this study can name, and
found not to hold. This strengthens confidence in the existing FPR
findings; it does not revise them.

---

## Task 6 — Control mechanism (#7)

| # | control | what it catches | cost to run | finding it caught in this study |
|---|---|---|---|---|
| 7 | **Post-attack artifact persistence contamination** | a benign collection run on the same host *after* an attack round, where persistence-designed artifacts (cron jobs, systemd units, shell-rc edits, accounts, authorized-key entries) from the attack round are still present and produce alerts that get labeled benign | (i) enumerate exact artifact paths/names from the attack session's own audit/launch logs, not the general technique catalog; (ii) confirm cleanup ran, from direct log evidence, not from the assumption that a runbook step "would have" run; (iii) exact-path-match every benign-window alert of the relevant rule families against that list, distinguishing exact match from mere directory-class overlap; (iv) for any rate-shaped technique (e.g. a cron job), check inter-arrival periodicity as a second, independent signal | run here: found **negative** — cleanup directly confirmed for the covered rounds, zero exact/directory-class path matches across all 267 benign alerts and all 29 FPs, no periodicity in the one rule family that could show it. Closes this threat to validity for the 550/553/554 FPR figures and the F1=0.8702 precision term rather than surfacing a new defect |

**What it catches, generally:** collection order is a design choice
(attack-then-benign, same host) that most FPR analyses do not examine
after the fact — a false positive is silently assumed to be a genuine
benign misclassification, when for persistence techniques specifically it
could instead be the model correctly detecting real leftover attacker
state that was mislabeled by the collection window rather than by the
model. Unlike controls 1–5 (which catch a feature reading capture
identity instead of behavior), this control catches a **label**
integrity risk, not a feature one — a false positive that is not actually
false.

**How to avoid it, for future collections:** collect the benign round
*before* the attack round wherever the study design allows it (eliminates
the risk structurally, as opposed to depending on cleanup fidelity);
where attack-then-benign ordering is required, treat cleanup verification
as a collection deliverable with its own evidence requirement (an explicit
teardown log, or a syscheck *deleted*/`userdel` confirmation captured at
teardown time) rather than an assumed step; or restore from a snapshot
between rounds. This study's own collection happened to get this right —
the scripted teardown (Task 2) used exact-match markers (`col_` prefix,
`COLLECTNOVEL` tag) specifically designed to be swept up cleanly — but
that was verified here, not assumed, which is the point of the control.

---

## Deliverables

- `newCol/art_contamination_check.md` — this file.
- `newCol/art_contamination_paths.csv` — per-alert bucket assignment for
  all 267 benign-window Linux alerts (rule, timestamp, `syscheck.path`,
  FP flag, bucket, matched artifact if any), produced by
  `newCol/art_contamination_check.py`.

**CHECKPOINT. STOP.**

---

## Correction (PRE-MS FIX 1) — the "all 29" headline was overstated

**This supersedes the headline paragraph at the top of this file; nothing
above is deleted.** That paragraph's closing clause — "every
benign-window FIM/syscheck alert path-matches to something unrelated...
across the full 267-alert benign collection and specifically across all
29 false positives" — is imprecise. Path matching (`syscheck.path`
comparison) can only apply to alerts that carry that field: FIM/syscheck
alerts only. Of the 29 false positives, only **5** (550×3, 553×1, 554×1)
carry a `syscheck.path`, and those 5 do path-match to CUPS housekeeping
or the organic `known_hosts` entry, as stated. The other **24** (31101×10,
5402×10, 52002×2, 5501×1, 5502×1) carry no `syscheck.path` at all — they
were correctly checked and correctly found unrelated in Task 3c above, but
by a *different* method (full-JSON-body substring search for
`coluser`/`col_cron`/`col_svc`/`col_profile`/`COLLECTNOVEL`), not by path
matching. The per-alert evidence (`art_contamination_paths.csv`) was
always correct; only the summary sentence conflated two methods into one
phrase. The Task 5 conclusion (no contamination found, nothing changes) is
unaffected — see `newCol/pre_ms_number_fixes.md` FIX 1 for the full
per-alert breakdown and the rejected alternative explanation (31101 is not
CUPS-generated; its alerts are `curl` requests to an nginx application
server, confirmed from `full_log`/`data` fields, not inferred).
