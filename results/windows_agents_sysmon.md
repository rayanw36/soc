# Windows alerts: agents, labels and Sysmon

Produced by `analysis/windows_agents_sysmon.py` from `data/testbed_collection/collection_win_alerts.json` (attack round, n=401, with `labeled_win.csv`) and `collection_benign_win_alerts.json` (benign, n=201). Read-only.

**Answer.** Every one of the 602 Windows alerts comes from a single agent, `WIN-CL1` (agent id 002). `WIN-DC` produced no alert in either collection, so no alert from it carries any label (zero attack-labelled alerts from `WIN-DC`) and no Sysmon event from it appears. The data cannot say whether `WIN-DC` ran Sysmon at all, because nothing was collected from it. All Sysmon events in the collections come from `WIN-CL1`.

## Alerts per agent name

| agent name (id) | attack round, attack | attack round, uncertain | attack round, benign | attack round, total | of which `sysmon` group | benign collection, total | of which `sysmon` group |
|---|---:|---:|---:|---:|---:|---:|---:|
| `WIN-CL1` (002) | 336 | 62 | 3 | 401 | 198 | 201 | 122 |
| `WIN-DC` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Labels are the `label` column of `labeled_win.csv` (time-window / process-tree labelling; `uncertain` = outside the session or ambiguous). That file has no agent column, so it was joined to the raw alerts row by row (timestamp and rule id agree on all 401 rows). The benign collection is a separate benign-only session and is not labelled through `labeled_win.csv`.

Sysmon alerts by label in the attack round (rule group `sysmon`):

| agent | attack | uncertain | benign |
|---|---:|---:|---:|
| `WIN-CL1` | 192 | 6 | 0 |

## Why this is read as one host

- Agent fields: `WIN-CL1` id ['002'], ip ['192.168.20.104'].
- The Windows event's own `data.win.system.computer` is `WIN-CL1.lab.local` on all 602 alerts, so no alert is a forwarded event from another machine.
- Sysmon provider on the `sysmon` alerts: `Microsoft-Windows-Sysmon` (320).
- Process GUIDs carry the machine part as their first 8 hex digits. In `sysmon_eid1.csv` (9,838 rows): `b7327453` (9,838); in `sysmon_artifacts.csv` (35,140 rows): `b7327453` (35,140); inside the Sysmon alert messages: `b7327453` (599). One prefix throughout, so one machine's Sysmon.
- Where `WIN-DC` is named in the repository's code and data files: `analysis/f1_phaseB_win.py` (1), `results/rule_memorization_audit/exp1_feature_classification.csv` (1), `results/rule_memorization_audit/exp1_feature_classification.py` (1), `shared_constants.py` (1). The only functional use is the `agent_criticality` lookup (`shared_constants.py`: `"win-dc": 3`), a weight for an agent name that never occurs in these collections. It is not evidence that `WIN-DC` was monitored.

## Reading this

- All 336 attack-labelled Windows alerts, the 62 uncertain and the 3 benign-labelled ones are from `WIN-CL1`. The attack hosts are not separable from the benign host in this data: the same single endpoint is both.
- The paper should not describe a domain controller as monitored, or as an attack host, on the strength of these alerts. If `WIN-DC` ran Sysmon, that evidence is not in the repository.
