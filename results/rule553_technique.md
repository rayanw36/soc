# Rule 553 in the novel-attack set: which technique produced the 20 alerts

Produced by `analysis/rule553_technique.py` from `data/testbed_collection/labeled_lnx.csv` and `collection_lnx_alerts.json` (row-aligned; timestamp and rule id agree on all rows). Read-only.

**Answer.** All 20 attack-labelled rule-553 alerts are labelled **T1136.001 (Create Account: Local Account)**, the `useradd` / `userdel coluser` step of the collection. No other technique produced any of them. The rule's own Wazuh description is **"File deleted."** (rule level 7; groups `ossec,syscheck,syscheck_entry_deleted,syscheck_file`).

## The 20 alerts

| property | value |
|---|---|
| Wazuh rule | 553, description "File deleted.", level 7 |
| rule's own MITRE mapping (in the alert) | T1070.004,T1485 (File Deletion, Data Destruction): 20 |
| technique label (`technique`) | T1136.001: 20 |
| path-based label (`artifact_technique`: any passwd-family path maps to T1136.001) | T1136.001: 20 |
| syscheck event | deleted: 20 |
| label confidence | VLOW-time: 20 |
| time source | alert_timestamp: 20 |
| collection round | round 2: 7, round 4: 6, round 5: 7 |

Files named in the alerts (`syscheck.path`):

| path | alerts |
|---|---:|
| `/etc/group.lock` | 3 |
| `/etc/gshadow.lock` | 3 |
| `/etc/passwd.lock` | 3 |
| `/etc/shadow.lock` | 3 |
| `/etc/subgid.lock` | 3 |
| `/etc/subuid.lock` | 2 |
| `/etc/group.14337` | 1 |
| `/etc/passwd.11818` | 1 |
| `/etc/passwd.14337` | 1 |

The technique windows that contain them (`window_start` to `window_end`, from the collection markers):

| round | window start | window end |
|---:|---|---|
| 2 | 2026-07-08T20:29:07+00:00 | 2026-07-08T20:29:27+00:00 |
| 4 | 2026-07-08T20:38:12+00:00 | 2026-07-08T20:38:31+00:00 |
| 5 | 2026-07-08T20:42:43+00:00 | 2026-07-08T20:43:02+00:00 |

## How to read it

- Rule 553 is the generic FIM "File deleted" rule. It is not specific to any technique, and its own MITRE tags (T1070.004,T1485) are file-deletion techniques that are not what the collection ran.
- The 20 alerts are deletions of `useradd`/`userdel` working files: `*.lock` files and numbered temporary copies of `/etc/passwd`, `/etc/group` and the shadow files. They are side effects of creating and removing the account, not the account creation itself. `docs/eval_set_definition.md` and `docs/history/ew_carrier_classification.md` already count them as the "T1136.001 incidental" population.
- Label strength is the weakest tier: `VLOW-time`. Rule 553 carries no usable event time (`syscheck.mtime_after` is the file's last modification, not the deletion time), so the label rests on the alert timestamp falling inside the T1136.001 window, with the 18-80 s ingestion lag unresolved. The path-based mapping above also gives T1136.001 for all 20; it is a prefix rule over the passwd-family paths in `labelling/label_lnx_timeonly.py`, so it is a consistency check on the window label, not independent evidence.
- Rule 553 has 85 alerts in the attack round in all. The other 65 are not attack-labelled: 5 uncertain (UNCERTAIN-out-of-session), 60 uncertain (UNCERTAIN-artifact-teardown).
