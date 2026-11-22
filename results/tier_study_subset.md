# Tier-study test set: where 3,464 attack / 42 benign comes from

Produced by `analysis/tier_study_subset.py`. Read-only: it rebuilds the split from the raw collections and checks it against `analysis/fr_31101_features.csv`; nothing is fitted.

**Script.** The raw-HTTP tier study is `analysis/fr_31101_feature_recovery.py` (writes `analysis/fr_31101_features.csv`, report in `docs/history/fr_31101_report.md`) and the plot is `figures/fig3b_31101_tier_study.py` (`figures/out/fig3b_31101_tier_study.*`, Fig. 3b in this repository's numbering; `figures/fig5_tempo_asymmetry.py` is a different figure). Both scripts, and this one, read the two Linux collections from `data/testbed_collection/`.

## 1. Where the requests come from

| | attack | benign |
|---|---|---|
| file | `data/testbed_collection/collection_lnx_alerts.json` | `data/testbed_collection/collection_benign_lnx_alerts.json` |
| alerts in file (all rules) | 23,081 | 267 |
| rule 31101 alerts | **20,665** | **209** |
| log source (`location`) | `/var/log/nginx/access.log` | `/var/log/nginx/access.log` |
| Wazuh agent | `lnx-dmz-VirtualBox` | `lnx-dmz-VirtualBox` |
| source IP in the access line | `127.0.0.1` | `127.0.0.1` |
| first / last alert timestamp | 2026-07-08T20:22:47.314+0000 / 2026-07-08T20:46:03.610+0000 | 2026-07-12T11:19:37.523+0000 / 2026-07-12T12:19:13.339+0000 |
| distinct paths | 4,601 | 3 |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` | `curl/8.5.0` |

Both sets are requests made to the lab's own nginx on the Linux agent (source address loopback), not traffic from outside users. The attack set is a wordlist content-discovery scan; the repository identifies it as `dirb` from its default User-Agent string and the wordlist-style paths (`docs/history/fr_31101_report.md`, Task 1). The benign set is `curl` requesting three fixed endpoints in rotation. Only the access-log lines are in the repository; the scan and polling commands themselves are not, so "dirb" and "curl loop" are read from the log contents, not from a recorded command line.

Other rules in the two files (not used by the tier study):

| class | rules (id: alerts) |
|---|---|
| attack | 31101: 20,665, 31151: 1,585, 550: 177, 5710: 114, 553: 85, 554: 82, 5402: 76, 5501: 76, 5502: 76, 80711: 75, 31516: 23, 31104: 11, 5903: 7, 5712: 6, 1010: 6, 5901: 6, 5902: 6, 591: 3, 80730: 2 |
| benign | 31101: 209, 5501: 22, 5502: 11, 5402: 10, 550: 6, 81102: 2, 554: 2, 52002: 2, 503: 1, 40704: 1, 553: 1 |

## 2. How the train/test split was made

By time, per class, with no randomisation, so there is no split seed. (The only seed in the script is `random_state=0` for XGBoost, which affects the fitted trees, not which alerts are in the test set.)

- **Attack:** alerts sorted by timestamp; a new scan round starts wherever the gap between consecutive alerts exceeds 30 s. That gives 6 rounds. Rounds 1-5 are train, round 6 is test.

| round | alerts | first alert | last alert | gap before it (s) |
|---:|---:|---|---|---:|
| 1 | 2,801 | 2026-07-08T20:22:47.314+0000 | 2026-07-08T20:23:18.841+0000 |  |
| 2 | 3,806 | 2026-07-08T20:27:16.885+0000 | 2026-07-08T20:28:18.250+0000 | 238.0 |
| 3 | 3,213 | 2026-07-08T20:31:51.069+0000 | 2026-07-08T20:32:28.415+0000 | 212.8 |
| 4 | 3,765 | 2026-07-08T20:36:25.451+0000 | 2026-07-08T20:37:13.775+0000 | 237.0 |
| 5 | 3,616 | 2026-07-08T20:40:55.461+0000 | 2026-07-08T20:41:35.090+0000 | 221.7 |
| 6 (test) | 3,464 | 2026-07-08T20:45:27.303+0000 | 2026-07-08T20:46:03.610+0000 | 232.2 |

  Train = 17,201, test = 3,464; 17,201 + 3,464 = 20,665.

- **Benign:** alerts sorted by timestamp; the first `int(0.8 x 209)` = 167 are train and the remaining 42 are test (the last 20% in time).

- **Ratio:** not one ratio for the whole set. Benign is 80/20 (167/42); attack is whatever the last scan round holds (3,464 of 20,665, 16.8%). Overall the test set is 3,506 alerts (16.8% of 20,874).

Rebuilt here from the raw files, the train and test sets are identical, alert for alert, to the `split` column of `analysis/fr_31101_features.csv` (train n=17,368, test n=3,506).

## 3. Why 3,464 attack and 42 benign

- **3,464** is the size of the sixth and last scan round. The test set takes the last round as a unit, so its size is fixed by how many requests that one pass of the wordlist produced, not by a chosen ratio. The five earlier rounds hold 17,201.
- **42** is 209 minus `int(0.8 x 209)` = 209 - 167. It is the last fifth of the benign session in time (2026-07-12T12:07:04.217+0000 to 2026-07-12T12:19:13.339+0000).
- The class imbalance in the test set (82.5:1) is therefore a consequence of the collection: one scan round is large and the benign session is a slow 209-alert poll. It was not tuned. It is the reason the trivial "always attack" rule already reaches F1 = 0.9940 on this test set (`docs/history/fr_31101_report.md`, 3a).
- In the attack test round, 3 of 3,464 alerts request a path that never occurs in rounds 1-5; the other rounds replay the same wordlist, so the held-out round is not held out in path terms.

## 4. The 42 benign test alerts by endpoint

| endpoint | benign total | benign train | benign test (of the 42) | share of the 42 | attack-scan alerts with this path (test round) |
|---|---:|---:|---:|---:|---:|
| `/api/status` | 77 | 63 | **14** | 33.3% | 0 |
| `/contact` | 66 | 50 | **16** | 38.1% | 1 |
| `/about` | 66 | 54 | **12** | 28.6% | 1 |
| total | 209 | 167 | **42** | 100.0% | |

The three endpoints are not equally represented in the test set, because the cut falls at an arbitrary point in the rotation rather than on a cycle boundary. The Tier B false positives follow the endpoint, not the alert: `docs/history/fr_31101_report.md` (Task 3b/3c) records that Tier B passes every `/api/status` alert (0 of 14 flagged) and flags every `/about` and `/contact` alert (12 + 16 = 28 flagged). That is where 28/42 comes from; the per-endpoint numbers in that report match the counts in this table (not re-derived here, since that would mean refitting the Tier B model).

## 5. Wilson 95% intervals

Wilson score interval, z = 1.96, on the test-set counts used in `figures/fig3b_31101_tier_study.py`.

| quantity | k / n | point estimate | Wilson 95% interval |
|---|---:|---:|---|
| Tier A false positives (0/42) | 0 / 42 | 0.00% | [0.0%, 8.4%] |
| Tier B false positives (28/42) | 28 / 42 | 66.67% | [51.6%, 79.0%] |
| Tier B benign alerts correctly passed (14/42) | 14 / 42 | 33.33% | [21.0%, 48.4%] |
| trivial always-attack false positives (42/42) | 42 / 42 | 100.00% | [91.6%, 100.0%] |
| Tier A / Tier B attack-side recall (3464/3464) | 3,464 / 3,464 | 100.00% | [99.9%, 100.0%] |

The two intervals are [0.0%, 8.4%] for Tier A (0/42) and [51.6%, 79.0%] for Tier B (28/42). The intervals do not overlap, so Tier A and Tier B differ on this test set.

Caveats on reading these intervals:

- The 42 alerts are not 42 independent draws. They are repeats of 3 fixed requests (`/contact` x 16, `/api/status` x 14, `/about` x 12) from a single `curl` loop on one host, and Tier B's outcome is decided per endpoint (section 4). The effective sample for the benign side is closer to three endpoints than to 42 alerts, and the Wilson interval, which treats alerts as independent, is narrower than the evidence supports.
- Tier A's 0/42 is a statement about this one benign User-Agent (`curl/8.5.0`), which the model has memorised from training; the interval bounds the rate on this benign stream, not on benign traffic in general.

