# Phase 0 — Inventory and verification (Entity-Window experiment)

No modeling performed. All numbers below are read directly from the existing
collections; nothing simulated.

## 0a. Collection inventory

| collection | file(s) | n | time span (UTC) | distinct rule_id | distinct srcip | distinct agent | label source |
|---|---|--:|---|--:|--:|--:|---|
| Linux attack | `newCol/labeled_lnx.csv` / `collection_lnx_alerts.json` | 23,081 | 2026-07-08 20:18:17 – 21:00:59 (43 min) | 19 | 1 | 1 | time-window assignment, validated against `syscheck.path` ground truth for FIM alerts (§6.2 reproduction, 175/175 agreement — see `eval_set_definition.md`) |
| Linux benign | `newCol/collection_benign_lnx_alerts.{csv,json}` | 267 | 2026-07-12 11:11:56 – 12:19:13 (67 min) | — (raw, unlabeled by rule breakdown not yet tallied here) | 1 | 1 | collection-time provenance (whole collection is benign by construction — no attack markers active during capture) |
| Windows attack | `newCol/labeled_win.csv` / `collection_win_alerts.json` | 401 | 2026-07-08 21:42:05 – 23:29:04 (107 min) | 18 | n/a (no srcip field on this platform) | 1 | time-window assignment (`round`/`attack_log.txt` markers), per `label_win_provenance.py` |
| Windows benign | `newCol/collection_benign_win_alerts.{csv,json}` | 201 | 2026-07-12 11:30:18 – 12:51:12 (81 min) | — | n/a | 1 | collection-time provenance |
| AIT-ADS training | `data/ait_ads/AIT_alerts/AIT_alerts.csv` | 2,655,821 | 2022-01-14 – 2022-02-08 (8 scenarios) | n/a (different rule taxonomy) | 87 | 29 hosts, 8 scenarios | AIT-LDS ground truth (`time_label`/`event_label`) |

Label breakdown:
- Linux attack: `attack`=22,769, `uncertain`=293, `benign`=19
- Windows attack: `attack`=336, `uncertain`=62, `benign`=3
- AIT-ADS: `label`=1 (attack) 1,836,793 rows (dominated by `dirb`=1,690,884, i.e. the AIT-ADS analogue of rule 31101); `label`=0 (`false_positive`) 819,028 rows

Raw-log archival:
- Linux attack window: **archived**, `newCol/audit_lnxdmz.log` (16,762 lines, raw auditd). Coverage 2026-07-08 20:42:43–21:32:09 — starts ~24 min after the alert window opens and ends ~31 min after it closes; not fully coextensive with the 20:18:17–21:00:59 alert span. Anything needing raw-log join for alerts before 20:42:43 has no source.
- Linux benign window (July 12): **not archived**. Checked `audit_lnxdmz.log`'s epoch range directly — zero lines fall in the July 12 11:00–13:00 UTC window. No raw auditd exists for the benign collection.
- Windows attack window: **archived**, `newCol/sysmon_wincl1.evtx` + derived `sysmon_eid1.csv` / `sysmon_artifacts.csv`. `sysmon_artifacts.csv` is a cumulative table spanning 2025-09-21 to 2026-07-08 23:22:13 — it covers the start of the label window (21:42:05) but stops ~7 minutes before the label window's end (23:29:04). Coverage gap in the last ~7 minutes of the attack round.
- Windows benign window (July 12): **not archived**. Zero rows in `sysmon_artifacts.csv` for the July 12 11:00–13:00 UTC window.

**Implication for Phase 4c (provenance features):** the provenance/PID-tree arm is only computable at all for the Linux and Windows *attack* windows, and even there coverage is partial (Linux: gap before 20:42:43; Windows: gap after 23:22:13). It cannot be computed for either benign collection — there is no raw process-tree data for July 12. This must be stated as the join-coverage caveat in Phase 4c, not worked around.

## 0b. Pivot-key population / null rates

**Linux** (n=23,081, `labeled_lnx.csv`):

| field | null rate | distinct values |
|---|--:|--:|
| `srcip` | 2.9% | **1** (`127.0.0.1`) |
| `srcuser` | 98.8% | 24 |
| `agent_name` | 0.0% | **1** (`lnx-dmz-VirtualBox`) |
| `agent_ip` | 0.0% | **1** (`192.168.30.31`) |
| `url` | 3.5% | 4,610 |
| `syscheck_path` | 98.5% | 39 |
| `timestamp` | 0.0% | 16,002 |

No field is >50% null in a way that blocks its *use*, but `srcip` and `agent_*` are **not null**, they are **constant** — a stronger problem than nullity, flagged below in 0d.

**Windows** (n=401, `labeled_win.csv`):

| field | null rate | distinct values |
|---|--:|--:|
| `target_user` | **58.4%** ⚠ | 22 |
| `image` | **50.6%** ⚠ | 7 |
| `parent_image` | **51.1%** ⚠ | 4 |
| `process_guid` | **50.6%** ⚠ | 198 |
| `event_id` | 0.0% | 12 |
| `timestamp` | 0.0% | 342 |

**Flag**: `target_user`, `image`, `parent_image`, and `process_guid` are all >50% null. This is because roughly half of the 401 Windows alerts are non-Sysmon (Windows Security auditing rules like 60106/60122, logon/logoff events) which don't carry process-tree fields — the null rate reflects two disjoint alert families being unioned, not missing instrumentation within a family. The `user`-pivot on Windows should key off whichever of `target_user` / the Security-auditing subject-user field applies per alert family, not assume one column covers everything. This needs to be handled explicitly in the extractor (Phase 1c), not dropped.

The Linux/Windows benign collections (`collection_benign_*_alerts.csv`) as currently written contain **no entity fields at all** — only `timestamp, rule_id, level, description, path`. The richer fields (`srcip`, `agent`, `data.*`) exist in the underlying `.json` (confirmed: `data.srcip` present on 209/267 Linux benign records, all `127.0.0.1`; agent constant `003`/`lnx-dmz-VirtualBox` for Linux, `002`/`WIN-CL1` for Windows), but the `.csv` extraction the rest of the pipeline reads does not carry them. The Phase 1 extractor must read the `.json`, not the `.csv`, for the benign sets, or these fields are 100% unavailable to it.

## 0c. Timezone handling

Checked fresh, not assumed fixed:
- `newCol/label_lnx_timeonly.py`: `syscheck.mtime_after` is documented and handled as **UTC** (naive ISO string, explicitly annotated "NOT the [local] reading" — this is the exact bug class the checkpoint asked about, and it was already fixed in this script with an explicit comment justifying the UTC interpretation via the cron/col_cron timing check).
- `newCol/label_win_provenance.py`: uses `data.win.system.systemTime`, documented as "exact UTC and present on ALL 401 alerts" — no local-time ambiguity on the Windows side.
- Raw alert `timestamp` fields on all four live collections carry an explicit `+0000` offset — unambiguous UTC.
- AIT-ADS `dt` column has no explicit offset string; not investigated further here since AIT-ADS is training-only and out of scope for the live entity-window features, but flag for anyone reusing AIT-ADS timestamps directly.

No new timezone bug found. The one historical bug class (mtime_after) remains correctly handled as of this check.

## 0d. Entity diversity — the honest answer

**Source-IP diversity is effectively zero across both live platforms.**

- Linux: every alert across both the attack collection (23,081 alerts) and the benign collection (267 alerts) that carries a `srcip` field carries the *same* value, `127.0.0.1`. This is true for both `label='attack'` and `label='benign'` rows. There is exactly **one** distinct source IP in the entire Linux dataset, attack and benign combined.
- Windows: there is no `srcip`-equivalent field at all on this platform's alert schema; Sysmon process-creation and Security-auditing events don't carry a remote source IP for local-host activity.
- Host/agent diversity is also zero within each collection: Linux is single-agent (`003`/`lnx-dmz-VirtualBox`, 1 host) across attack *and* benign; Windows is single-agent (`002`/`WIN-CL1`, 1 host) across attack *and* benign.
- The only pivot key with real diversity on the live data is `user`: 24 distinct values on Linux (`root`, `lnx-dmz`, `coluser`, `baduser1`–`baduser7`, …), 22 distinct values on Windows.

**Conclusion: an entity-disjoint split by `srcip` or by `agent` is categorically impossible on the current Linux/Windows collections** — not merely underpowered, but structurally absent, because both testbeds are single-host, single-network-path setups (the "attacker" traffic and the "victim" traffic are generated on/against the same box, so Wazuh logs loopback). Any entity-window feature keyed on `srcip` (fan-out, distinct-IP-count, etc.) is **non-operative** on this data by construction — it will be constant and uninformative, not merely weak. The extractor should still compute it (per spec) but Phase 2/4 must report it as structurally degenerate, not silently omit it and not let it inflate MI/leakage numbers by coincidence.

A **user-keyed** entity-window is viable (24/22 distinct values with real spread — `baduser1`–`baduser7` look like adversary-simulation accounts, `root`/`lnx-dmz`/`coluser` look like legitimate accounts). A **temporal** split (train earlier time spans, test later) is viable on all four collections independent of entity diversity.

AIT-ADS, by contrast, has real entity diversity (87 IPs, 29 hosts, 8 independent scenarios) — but it is a structurally different data source (different rule taxonomy, different era, used only for L1 training) and is out of scope for direct entity-window feature reuse without separate validation; it is not a substitute for entity diversity on the live testbed.

## Other observations flagged during inventory (not asked for verbatim, but load-bearing)

- `EvalSteps/` (`lnx_dmz_all_alerts.json`, `lnx_dmz_alerts.json`, `lnx_dmz_ai_detections.json`) contains alerts from **May 2026 and December 2025** — a different time span than the July 8–12 2026 collections this experiment is scoped to, and `__EvalSteps_Error.txt` / `___All_Errors.txt` in the project root indicate this folder had a **failed/incomplete download sync** ("file size exceeds the allowed limit", "the following file/folder has not been downloaded: 0. EvalSteps"). Treated as out of scope and unreliable for this experiment; not used in any inventory number above.
- `rules id/collection_benign_*` appears to be a duplicate of `newCol/collection_benign_*` (same filenames). Not reconciled here since `newCol/` is the canonical location per the prompt; flagging in case the two ever diverge.

## Summary table for Phase 1 planning

| pivot key | Linux | Windows | usable for entity-disjoint split? |
|---|---|---|---|
| `srcip` | constant (127.0.0.1) | not present | **no** |
| `agent`/host | constant, 1 host | constant, 1 host | **no** |
| `user` | 24 distinct | 22 distinct | **yes, best available** |
| time | full range available | full range available | yes (temporal split, all collections) |

Per Rule 2 (STOP at every checkpoint): this is the Phase 0 checkpoint.
