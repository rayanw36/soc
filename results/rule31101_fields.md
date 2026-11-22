# Rule 31101: field inventory and collision check

Produced by `analysis/rule31101_fields.py` from the live Linux collections `data/testbed_collection/collection_lnx_alerts.json` (attack, n=20,665) and `collection_benign_lnx_alerts.json` (benign, n=209), rule id 31101 only. Read-only analysis: no model is fitted and no existing file is changed.

## 1. Fields an alert carries

`wazuh:*` is the Wazuh alert JSON (nested keys joined with `.`; list-valued keys compared as a whole). `nginx:*` is the access line parsed out of `full_log` (`remote_addr ident auth_user [time_local] "method target http_version" status bytes "referer" "user_agent"`; `target` is split into `path` and `query_string`). "Both" is the number of distinct values that occur in the attack set and also in the benign set. "Cheap" marks the four fields an attacker controls at no cost (User-Agent, source IP, query string, referrer).

| field | distinct in attack | distinct in benign | distinct in both | note |
|---|---:|---:|---:|---|
| `wazuh:timestamp` | 14,482 | 207 | 0 | alert time |
| `wazuh:rule.level` | 1 | 1 | 1 |  |
| `wazuh:rule.description` | 1 | 1 | 1 |  |
| `wazuh:rule.id` | 1 | 1 | 1 |  |
| `wazuh:rule.firedtimes` | 20,665 | 149 | 149 | running counter |
| `wazuh:rule.mail` | 1 | 1 | 1 |  |
| `wazuh:rule.groups` | 1 | 1 | 1 |  |
| `wazuh:rule.pci_dss` | 1 | 1 | 1 |  |
| `wazuh:rule.gdpr` | 1 | 1 | 1 |  |
| `wazuh:rule.nist_800_53` | 1 | 1 | 1 |  |
| `wazuh:rule.tsc` | 1 | 1 | 1 |  |
| `wazuh:agent.id` | 1 | 1 | 1 |  |
| `wazuh:agent.name` | 1 | 1 | 1 |  |
| `wazuh:agent.ip` | 1 | 1 | 1 |  |
| `wazuh:manager.name` | 1 | 1 | 1 |  |
| `wazuh:id` | 20,665 | 209 | 0 | Wazuh alert id |
| `wazuh:full_log` | 20,665 | 209 | 0 | whole access line |
| `wazuh:decoder.name` | 1 | 1 | 1 |  |
| `wazuh:data.protocol` | 1 | 1 | 1 | copy of `nginx:method` |
| `wazuh:data.srcip` | 1 | 1 | 1 | cheap; copy of `nginx:remote_addr` |
| `wazuh:data.id` | 1 | 1 | 1 | copy of `nginx:status` |
| `wazuh:data.url` | 4,601 | 3 | 2 | copy of request target (path plus query string) |
| `wazuh:location` | 1 | 1 | 1 |  |
| `nginx:remote_addr` | 1 | 1 | 1 | cheap |
| `nginx:ident` | 1 | 1 | 1 |  |
| `nginx:auth_user` | 1 | 1 | 1 |  |
| `nginx:time_local` | 18 | 209 | 0 |  |
| `nginx:method` | 1 | 1 | 1 |  |
| `nginx:http_version` | 1 | 1 | 1 |  |
| `nginx:status` | 1 | 1 | 1 |  |
| `nginx:bytes` | 1 | 1 | 0 |  |
| `nginx:referer` | 1 | 1 | 1 | cheap |
| `nginx:user_agent` | 1 | 1 | 0 | cheap (attacker-set header) |
| `nginx:path` | 4,601 | 3 | 2 |  |
| `nginx:query_string` | 1 | 1 | 1 | cheap |

Copy checks (alerts for which the equality holds, out of 20,874): `wazuh:data.srcip == nginx:remote_addr`: 20,874; `wazuh:data.id == nginx:status`: 20,874; `wazuh:data.protocol == nginx:method`: 20,874; `wazuh:data.url == request target (path?query)`: 20,874.

Every field above is present in every one of the 20,874 alerts (no missing values).

## 2. Collisions after removing the cheap fields

Cheap fields removed: User-Agent, source IP, query string, referrer. Representation kept: `method`, `path`, `status`, `bytes` (response size), `rule.id`, `rule.level`, `rule.groups`. An alert "collides" when another alert of the opposite class has exactly the same representation.

| representation | distinct (attack) | distinct (benign) | distinct in both | benign alerts colliding | attack alerts colliding |
|---|---:|---:|---:|---:|---:|
| method, path, status, bytes, rule id/level/groups | 4,601 | 3 | 0 | 0 / 209 (0.00%) | 0 / 20,665 (0.00%) |
| same, path removed (method, status, bytes, rule id/level/groups) | 1 | 1 | 0 | 0 / 209 (0.00%) | 0 / 20,665 (0.00%) |
| extra: bytes removed instead (method, path, status, rule id/level/groups) | 4,601 | 3 | 2 | 132 / 209 (63.16%) | 10 / 20,665 (0.05%) |
| extra: path and bytes both removed (method, status, rule id/level/groups) | 1 | 1 | 1 | 209 / 209 (100.00%) | 20,665 / 20,665 (100.00%) |

The first two rows are the main check. Both give zero collisions, but only because of `bytes`: `method`, `status` and every rule field take a single value in both classes, and `path` is the only other field that varies. The two extra rows show what happens when `bytes` is taken out as well.

Response size and User-Agent as they occur together:

| class | bytes | user_agent | alerts |
|---|---:|---|---:|
| attack | 564 | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` | 20,665 |
| benign | 162 | `curl/8.5.0` | 209 |

In this data `bytes` is therefore a one-to-one stand-in for the User-Agent: 564 with the attack scanner's MSIE 6.0 string, 162 with `curl/8.5.0`. The cause is not recorded in the repository (no nginx configuration is included). One possible mechanism is nginx's `msie_padding` directive, which pads error pages for old MSIE clients; this is an unverified hypothesis, not something the data shows. What the data does show is that size is not a function of the path: `/about` and `/contact` occur in both classes (section 3) with 564 bytes in the attack scan and 162 bytes in the benign traffic, so it varies with the client. Every attack alert has one User-Agent and one size, so the two cannot be separated further here.

Representations shared by both classes, with the alert count on each side:

**with path**

- none

**path removed**

- none

**bytes removed**

| representation | attack alerts | benign alerts |
|---|---:|---:|
| method=GET, path=/about, status=404, rule.id=31101, rule.level=5, rule.groups=["web", "accesslog", "attack"] | 6 | 66 |
| method=GET, path=/contact, status=404, rule.id=31101, rule.level=5, rule.groups=["web", "accesslog", "attack"] | 4 | 66 |

**path and bytes removed**

| representation | attack alerts | benign alerts |
|---|---:|---:|
| method=GET, status=404, rule.id=31101, rule.level=5, rule.groups=["web", "accesslog", "attack"] | 20,665 | 209 |

### Which remaining field carries the separation (leave one out, path kept in unless it is the one dropped)

| field dropped from the representation | benign alerts colliding | attack alerts colliding |
|---|---:|---:|
| `method` | 0 / 209 | 0 / 20,665 |
| `path` | 0 / 209 | 0 / 20,665 |
| `status` | 0 / 209 | 0 / 20,665 |
| `bytes` | 132 / 209 | 10 / 20,665 |
| `rule.id` | 0 / 209 | 0 / 20,665 |
| `rule.level` | 0 / 209 | 0 / 20,665 |
| `rule.groups` | 0 / 209 | 0 / 20,665 |

### For context: adding one cheap field back to the full remaining representation

| cheap field added | benign alerts colliding | attack alerts colliding |
|---|---:|---:|
| `query_string` | 0 / 209 | 0 / 20,665 |
| `referer` | 0 / 209 | 0 / 20,665 |
| `remote_addr` | 0 / 209 | 0 / 20,665 |
| `user_agent` | 0 / 209 | 0 / 20,665 |

## 3. Benign endpoints versus the attack scan

| benign endpoint (path) | benign alerts | attack alerts with the same path | appears in the attack scan |
|---|---:|---:|---|
| `/api/status` | 77 | 0 | no |
| `/contact` | 66 | 4 | yes |
| `/about` | 66 | 6 | yes |

Distinct paths: 4,601 in attack, 3 in benign, 2 in both.

