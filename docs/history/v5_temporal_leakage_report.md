# v5 Temporal-Leakage Check (gating check for Table 7.1)

Analysis only — nothing trained, no pipeline code or existing artifact modified.
Full config: `newCol/eval_set_definition.md`. Scripts: `newCol/v5_temporal_task0.py`,
`v5_temporal_task1.py`, `v5_temporal_task2.py`.

## Question

Does v5's 26-feature FIM detection (Table 7.1) survive without temporal/session
context, or is it the same coincidence found in the 22-feature space (v8 FIM
degeneracy check) in a different feature space?

## Answer: mixed. Three of four FIM techniques are pure temporal leakage; one
survives, carried by a coarse severity feature, not by anything content-specific.

---

## Task 0 — Table 7.1 reproduction

**Config archaeology (one timeboxed pass, per instruction):** not a git repo, no
historical duplicate threshold file, and the only phase4-era script outside
`newCol/` (`phase4_transfer.py`, 2026-06-17) is CORAL domain-transfer testing on
different data that predates the July 2026 collection — cannot be the source.
**The historical config behind the published "shell-rc 3/6" is untraceable and was
not pursued further.**

**Predicate recovered and validated:** `newCol/verify_labels_lnx.py` §2.3
("ARTIFACT-PATH CONFUSION") reproduces the published §6.2 confusion-matrix
diagonal exactly — **6, 6, 151, 6, 6**, 175/175 agreement, 0 mislabeled. This
confirms `labeled_lnx.csv`'s `technique` column (time-window assignment) against
independent `syscheck.path`-derived ground truth. Under the same predicate,
discriminative-rule totals give T1110.001=119 and T1136.001=163 — exact matches
to Table 7.1's other two published n's. Full config, file hashes, and the
predicate are frozen in `newCol/eval_set_definition.md`.

**Canonical Table 7.1 (regenerated under the frozen production config — supersedes
the earlier draft):**

| technique | n | L1 | L2 | either |
|---|--:|---|---|---|
| cron (T1053.003) | 6 | 2/6 (33.3%) | **6/6 (100%)** | 6/6 |
| systemd (T1543.002) | 6 | 3/6 (50.0%) | **6/6 (100%)** | 6/6 |
| ssh-key (T1098.004) | 6 | 0/6 (0%) | **6/6 (100%)** | 6/6 |
| shell-rc (T1546.004) | 6 | 5/6 (83.3%) | 5/6 (83.3%) | 5/6 |
| T1110.001 | 119 | 2/119 (1.7%) | 92/119 (77.3%) | 92/119 |
| T1136.001 | 163 | 61/163 (37.4%) | 143/163 (87.7%) | 143/163 |

Three of four FIM techniques (cron, systemd, ssh-key) match the published draft
exactly; shell-rc reproduces at 5/6, not the published 3/6, under an
untraceable historical config. **Table 7.1 is regenerated as canonical above; see
the manuscript note at the end of this document.**

---

## Task 1 — Detected-vs-missed autopsy (v5, 26-feature space)

n=24 (6 per technique, discriminative rules only: 554→cron/systemd/shell-rc by
path, 550→ssh-key by path). 23 detected, 1 missed (the shell-rc miss). Every
intrinsic feature is identical between detected and missed (same rule → same
`desc_len`, `rule_level`, `kw_*`, `mitre_tactic_id`, `rule_id_encoded`); every
temporal feature differs in the same direction found in the v8 (22-feature)
check: `scan_preceded`/`brute_preceded` = 1 vs 0, `failed_login_5min` = 10 vs 0,
`time_since_last_high` = 18.9s vs 999 (no recent high-severity alert nearby).
**Caveat:** thin (n=1 missed) — suggestive, not conclusive on its own. Full
table: `newCol/v5_temporal_task1_detected_vs_missed.csv`.

---

## Task 2 — Temporal-ablation scoring (the decisive test)

| technique | n | original | (a) ZEROED | (b) BENIGN-TYPICAL |
|---|--:|--:|--:|--:|
| cron | 6 | 6/6 | 6/6 | **0/6** |
| systemd | 6 | 6/6 | 6/6 | **0/6** |
| shell-rc | 6 | 5/6 | 6/6 | **0/6** |
| ssh-key | 6 | 6/6 | 6/6 | **6/6** |
| **OVERALL** | 24 | 23/24 | 24/24 | **6/24** |

**(a) ZEROED is not a valid ablation** — it *increases* detections (23→24).
Zeroing count-style temporal features doesn't simulate a quiet network; it
creates an even more statistically unusual vector, which an RBF-kernel OC-SVM
reads as anomalous on its own. **(b) BENIGN-TYPICAL (realistic quiet-network
values) is the real test, and it's decisive:** cron/systemd/shell-rc collapse to
zero; ssh-key is untouched.

**Mirror control:** fresh Linux benign FPR goes from 6.7% (18/267) to **100%**
(267/267) when its temporal features are set to FIM-attack-typical medians.
Temporal context alone is sufficient to flip nearly any alert to "detected" in
either direction.

**What carries ssh-key's survival — tested, not assumed:** swapping only
`rule_id_encoded` (550→554) while holding benign-typical temporal values changed
nothing (score unchanged, still 6/6). Swapping only `rule_level` (7→5, the other
FIM rules' value) collapsed it to **0/6** (score −0.431 vs threshold −0.335).
**`rule_level` — Wazuh's own static severity rating for rule 550 ("Integrity
checksum changed," level 7, vs. level 5 for the other FIM rules) — is the
carrier.** This is genuinely non-temporal, but it's still a coarse, rule-identity-
adjacent signal ("this rule is rated severity 7"), not evidence the model
understood anything about SSH key tampering specifically.

Full ablation table: `newCol/v5_temporal_leakage_ablation.csv`.

---

## Verdict: Outcome C (mixed) — reported per-technique, not softened

- **Cron, systemd, shell-rc (3 of 4): pure temporal leakage.** Zero intrinsic
  signal survives ablation. Identical failure mode to the 22-feature normalized
  pipeline (v8 FIM degeneracy check) — this is not a normalized-schema-specific
  artifact, it exists in the 26-feature production space too.
- **ssh-key (1 of 4): survives**, carried by `rule_level`, a static per-rule
  severity annotation — real, non-temporal, but coarse (rule-identity-adjacent,
  not content-aware).

## Corrected wording for the manuscript

**Table 7.1 caption (replacing the current caption):**

> Table 7.1 regenerated under the frozen production configuration (26-feature
> v5+defer, `models_v2/ocsvm_nu05.pkl`, `rule_confound_fixes_v5.json`, deployed
> thresholds; predicate and config hashes in `newCol/eval_set_definition.md`);
> earlier draft numbers were produced under an intermediate pipeline state that
> could not be traced. L2 recall shown is nominal, not a measure of file-event
> detection — see the temporal-ablation result in Section [X].

**"Division of labor" paragraph (replacing the current claim that "file-write
persistence is entirely L2's job"):**

> L2's apparent detection of FIM persistence techniques is, for three of the four
> techniques tested (cron, systemd, shell-rc), attributable entirely to session
> context rather than to the file-write event itself: recall collapses from 6/6,
> 6/6, and 5/6 to 0/6 in all three cases when temporal/behavioral features
> (`scan_preceded`, `brute_preceded`, `failed_login_5min`, and related
> `AgentHistory` aggregates) are replaced with realistic quiet-network values,
> and a mirror-control test shows the same temporal context alone is sufficient
> to push ordinary benign alerts to 100% flag rate. The correct characterization
> is that L2 flags persistence-adjacent alerts occurring within an active attack
> session, not that it detects file-integrity events as such. The fourth
> technique, ssh-key (T1098.004), is a partial exception — its detection survives
> the same ablation intact — but even this is carried by the rule's static
> severity rating (`rule_level`), not by anything specific to SSH-key tampering.
> This mirrors the finding in the 22-feature normalized pipeline (v8 FIM
> degeneracy check): the temporal-leakage failure mode is not specific to that
> schema, it is present in the 26-feature production space as well. Closing this
> gap requires the alert-intrinsic features already proposed there (syscheck
> path-family classification, content-vs-metadata change detection, size delta,
> ownership/permission flags) — this is necessary work for a genuine
> file-integrity detection claim, not future work.
