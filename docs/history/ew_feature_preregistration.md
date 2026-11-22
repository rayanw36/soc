# EW feature pre-registration

Written during Phase 1 (extractor construction), before any label correlation,
MI, or leakage statistic has been computed on these features. This satisfies
Phase 2a ahead of schedule, per instruction: the downgraded 31101 claim and
the per-feature real-world-signal claims must be on record before Phase 2's
audit runs, not discovered retroactively.

## Headline pre-registered claim (the thesis test)

Rule 31101 (web scan) is provably undecidable per-alert — attack-31101 and
benign-31101 OC-SVM score distributions overlap completely on every
non-rule-identity feature (frozen finding). The `distinct_url_count` /
`path_repetition_ratio` / `alert_count` / `max_rate_10s` features in the
GLOBAL block are hypothesized to carry a dirb-style scanning signature that
per-alert features cannot: high request rate, and a repeated/enumerating
path pattern, accumulating over a window. **Given the single-attacker-IP,
single-host testbed (`newCol/ew_phase0_inventory.md`, Phase 0d), any
separation this shows demonstrates MECHANISM, not deployment-grade
generalization — there is exactly one attacker entity in this data.** This
downgrade is asserted now, not after Phase 2 or Phase 3 produce a flattering
number.

A first look at real (not yet audited) values already shows a shape worth
flagging in both directions before Phase 2 formalizes it:
- Attack-window (lnx_attack) 10-min buckets: `path_repetition_ratio` ≈
  0.39–0.43 over ~7,300–7,900 alerts/bucket during the dense scan phase.
- Benign-window (lnx_benign) 10-min buckets: `path_repetition_ratio` ≈
  0.90–0.93 over only 17–49 alerts/bucket, with just 3 distinct URLs seen.
- **These numbers run the opposite direction from a naive prior** (benign
  repetition ratio is HIGHER than attack, not lower) — driven by the benign
  collection revisiting a tiny fixed set of URLs (e.g. a health-check
  endpoint) at low volume, versus the attack's dirb enumeration touching
  many distinct paths at high volume but with real repetition mixed in. The
  separating signal, if any, is more likely `alert_count`/`max_rate_10s`
  (volume) than `path_repetition_ratio` in isolation. This is flagged now so
  Phase 2's MI audit is a confirmation/refutation of a stated hypothesis, not
  the first time this pattern is seen.

## Per-feature-family real-world signal claims

| feature family | pivot(s) | hypothesized real-world signal |
|---|---|---|
| `alert_count`, `max_rate_10s` | global, user | burst/flood activity: scanning, brute force, or any automated tool firing many events in a short span |
| `mean_interarrival_s`, `min_interarrival_s` | global, user | automation signature — machine-paced requests have small, low-variance gaps; human-paced activity does not |
| `distinct_rule_count` | global, user | breadth of behavior in the window — a single repeated action (e.g. one scanner) has low rule diversity; a multi-stage attack chain has high diversity |
| `distinct_url_count`, `path_repetition_ratio` | global | scanner/enumeration signature (dirb-style tools sweep a wordlist, producing high path diversity relative to a legitimate client hitting a handful of routes repeatedly) — **see the counter-intuitive real values above; this is a hypothesis to be tested, not assumed** |
| `distinct_syscheck_path_class_count`, `syscheck_{cron,systemd,shell_rc,ssh_key,account_mgmt,other}_count` | global | persistence-mechanism fingerprint — which class(es) of file a window's FIM activity touches, replacing the raw path string (forbidden) with the coarse taxonomy `v8_fim_degeneracy_report.md` proposed (amended with `account_mgmt` to split the 90/96 incidental rule-550 alerts from genuine ssh-key events) |
| `distinct_dst_count` | global, user | **structurally unavailable on this data (no destination host/port field in the alert schema) — retained as a constant-zero column only because the spec named it; it MUST be flagged as non-operative in Phase 2, not treated as a genuine zero-value feature |
| `auth_failure_count`, `auth_success_after_failure_flag` | global, user | brute-force / credential-stuffing shape — repeated failures, especially followed by a success, is the classic compromise signature |
| `ew_auth_after_webscan_flag` | same-user-else-global | attack-chain signal: reconnaissance (web scan) followed by an authentication attempt from the same actor suggests the scan informed a targeted follow-on |
| `ew_syscheck_after_login_flag` | same-user-else-global | attack-chain signal: a file-integrity event following a login by the same actor suggests post-auth persistence/tampering rather than an unrelated background FIM event |
| `ew_acctmgmt_after_auth_flag` | same-actor-else-global | attack-chain signal: account creation/deletion following authentication activity — **fixed during Phase 1 checkpoint (was an open caveat, now resolved): rule 5902 ("New user added") carries only `data.dstuser` (the newly-created account, e.g. `coluser` — the passive object of the action, not the actor who ran `useradd`), and rule 5901 carries no user field at all. The original `user` extraction fell back to `dstuser` when `srcuser` was absent, so `coluser` masqueraded as an actor with its own empty history, defeating this flag. Fixed by making the `user` pivot actor-only (`srcuser` only, never `dstuser`, on every EW feature, not just this flag) — see `newCol/eval_set_definition.md`'s "EW block v1" entry. Verified on real data: the flag went from 0→1 on every 5902 alert once the global auth history it's actually downstream of became visible.** |
| `ew_time_since_entity_first_seen_s`, `ew_time_since_entity_last_alert_s` | user else global | novelty / recency — a first-ever-seen entity (9999 sentinel) is qualitatively different from one with an established history; short gaps since the last alert indicate sustained/repeated activity from the same entity |
| `ew_user_present` | — (auxiliary flag) | marks whether the user-pivot block is populated for this alert at all (24/22 distinct users exist, but most rule families carry no user field — e.g. 31101 never does) — needed so a model doesn't confuse "user block is genuinely 0" with "user block is not applicable" |

## Explicitly degenerate / non-operative pivots (carried forward from Phase 0d, restated here)

`srcip` and `agent`/host pivots are NOT separately computed (see module
docstring) because Phase 0d found them constant across every live
collection. Any apparent "signal" from a feature that claims to be
srcip- or host-keyed on this data would be an artifact of the constant
value, not a real pivot — this extractor avoids the artifact by construction
rather than needing Phase 2 to catch it after the fact.
