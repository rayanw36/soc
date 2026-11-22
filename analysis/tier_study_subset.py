"""
tier_study_subset.py -- where the 3,464 attack / 42 benign test set of the raw-HTTP
tier study (figures/fig3b_31101_tier_study.py; analysis/fr_31101_feature_recovery.py)
comes from.

Rebuilds the split from the two raw Linux collections with the same rules the
tier study used, checks the result row by row against the committed
analysis/fr_31101_features.csv, and writes results/tier_study_subset.md.
Read-only: nothing is fitted and no existing file is changed.

Run from the repository root: python analysis/tier_study_subset.py
"""
import json
import math
import os
import re
from collections import Counter

import pandas as pd

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


ATTACK = _p("data/testbed_collection/collection_lnx_alerts.json")
BENIGN = _p("data/testbed_collection/collection_benign_lnx_alerts.json")
FEATURES = _p("analysis/fr_31101_features.csv")
OUT = _p("results/tier_study_subset.md")

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<httpver>[^"]+)" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
GAP_S = 30           # same round-boundary rule as analysis/fr_31101_feature_recovery.py
BENIGN_TRAIN_FRAC = 0.8


def wilson(k, n, z=1.959963984540054):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def load(path, cls):
    all_rules, rows, agents, locs, srcips = Counter(), [], Counter(), Counter(), Counter()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            rid = a["rule"]["id"]
            all_rules[rid] += 1
            if rid != "31101":
                continue
            m = LOG_RE.match(a["full_log"])
            rows.append(dict(cls=cls, timestamp=a["timestamp"], path=m.group("path"),
                             ua=m.group("ua"), method=m.group("method"), status=m.group("status")))
            agents[a["agent"]["name"]] += 1
            locs[a["location"]] += 1
            srcips[m.group("ip")] += 1
    return rows, all_rules, agents, locs, srcips


atk, atk_rules, atk_agents, atk_locs, atk_ips = load(ATTACK, "attack")
ben, ben_rules, ben_agents, ben_locs, ben_ips = load(BENIGN, "benign")
print(f"31101: attack {len(atk)}, benign {len(ben)}")

# --- the split, rebuilt the way the tier study built it -----------------------------
atk_sorted = sorted(atk, key=lambda r: r["timestamp"])
ben_sorted = sorted(ben, key=lambda r: r["timestamp"])
ts = pd.to_datetime([r["timestamp"] for r in atk_sorted])
gaps = ts.to_series().diff().dt.total_seconds().values
gap_idx = [i for i, g in enumerate(gaps) if g and g > GAP_S]
bounds = [0] + gap_idx + [len(atk_sorted)]
round_sizes = [b - a for a, b in zip(bounds[:-1], bounds[1:])]
round_spans = [(atk_sorted[a]["timestamp"], atk_sorted[b - 1]["timestamp"]) for a, b in zip(bounds[:-1], bounds[1:])]
gap_lengths = [float(gaps[i]) for i in gap_idx]

atk_train, atk_test = atk_sorted[:gap_idx[-1]], atk_sorted[gap_idx[-1]:]
n_ben_train = int(BENIGN_TRAIN_FRAC * len(ben_sorted))
ben_train, ben_test = ben_sorted[:n_ben_train], ben_sorted[n_ben_train:]
print("rounds:", round_sizes, "| test:", len(atk_test), len(ben_test))
assert len(atk_test) == 3464 and len(ben_test) == 42

# --- check against the committed features CSV, row by row ---------------------------
fr = pd.read_csv(FEATURES)


def sig(rows):
    return Counter((r["cls"], r["timestamp"], r["path"], r["ua"]) for r in rows)


csv_rows = lambda split: [dict(cls=r.cls, timestamp=r.timestamp, path=r.path, ua=r.ua)
                          for r in fr[fr.split == split].itertuples()]
match_test = sig(atk_test + ben_test) == sig(csv_rows("test"))
match_train = sig(atk_train + ben_train) == sig(csv_rows("train"))
print("rebuilt split identical to fr_31101_features.csv  train:", match_train, " test:", match_test)
assert match_test and match_train

# --- the 42, by endpoint ------------------------------------------------------------
ben_all_by_path = Counter(r["path"] for r in ben_sorted)
ben_train_by_path = Counter(r["path"] for r in ben_train)
ben_test_by_path = Counter(r["path"] for r in ben_test)
atk_test_paths = Counter(r["path"] for r in atk_test)
train_atk_paths = {r["path"] for r in atk_train}
unseen_atk_test = sum(1 for r in atk_test if r["path"] not in train_atk_paths)
test_first, test_last = ben_test[0]["timestamp"], ben_test[-1]["timestamp"]
ben_first, ben_last = ben_sorted[0]["timestamp"], ben_sorted[-1]["timestamp"]
# order of the endpoints in the rotation, to show whether the cut falls mid-cycle
rotation = [r["path"] for r in ben_sorted]

# --- intervals ---------------------------------------------------------------------
CIS = {name: (k, n, wilson(k, n)) for name, (k, n) in {
    "Tier A false positives (0/42)": (0, 42),
    "Tier B false positives (28/42)": (28, 42),
    "Tier B benign alerts correctly passed (14/42)": (14, 42),
    "trivial always-attack false positives (42/42)": (42, 42),
    "Tier A / Tier B attack-side recall (3464/3464)": (3464, 3464),
}.items()}
for name, (k, n, (lo, hi)) in CIS.items():
    print(f"  {name}: {100 * k / n:.2f}%  Wilson 95% [{100 * lo:.1f}, {100 * hi:.1f}]")
lo0, hi0 = CIS["Tier A false positives (0/42)"][2]
lo1, hi1 = CIS["Tier B false positives (28/42)"][2]
assert round(100 * hi0, 1) == 8.4 and round(100 * lo1, 1) == 51.6 and round(100 * hi1, 1) == 79.0

# --- write ---------------------------------------------------------------------------
L = []
w = L.append
w("# Tier-study test set: where 3,464 attack / 42 benign comes from\n")
w("Produced by `analysis/tier_study_subset.py`. Read-only: it rebuilds the split from the raw collections and checks "
  "it against `analysis/fr_31101_features.csv`; nothing is fitted.\n")
w("**Script.** The raw-HTTP tier study is `analysis/fr_31101_feature_recovery.py` (writes `analysis/fr_31101_features.csv`, "
  "report in `docs/history/fr_31101_report.md`) and the plot is `figures/fig3b_31101_tier_study.py` "
  "(`figures/out/fig3b_31101_tier_study.*`, Fig. 3b in this repository's numbering; `figures/fig5_tempo_asymmetry.py` "
  "is a different figure). Both scripts, and this one, read the two Linux collections from `data/testbed_collection/`.\n")

w("## 1. Where the requests come from\n")
w("| | attack | benign |")
w("|---|---|---|")
w(f"| file | `data/testbed_collection/collection_lnx_alerts.json` | `data/testbed_collection/collection_benign_lnx_alerts.json` |")
w(f"| alerts in file (all rules) | {sum(atk_rules.values()):,} | {sum(ben_rules.values()):,} |")
w(f"| rule 31101 alerts | **{len(atk):,}** | **{len(ben):,}** |")
w(f"| log source (`location`) | {', '.join(f'`{k}`' for k in atk_locs)} | {', '.join(f'`{k}`' for k in ben_locs)} |")
w(f"| Wazuh agent | {', '.join(f'`{k}`' for k in atk_agents)} | {', '.join(f'`{k}`' for k in ben_agents)} |")
w(f"| source IP in the access line | {', '.join(f'`{k}`' for k in atk_ips)} | {', '.join(f'`{k}`' for k in ben_ips)} |")
w(f"| first / last alert timestamp | {atk_sorted[0]['timestamp']} / {atk_sorted[-1]['timestamp']} | {ben_first} / {ben_last} |")
w(f"| distinct paths | {len({r['path'] for r in atk}):,} | {len({r['path'] for r in ben})} |")
w(f"| User-Agent | {', '.join(f'`{k}`' for k in {r['ua'] for r in atk})} | {', '.join(f'`{k}`' for k in {r['ua'] for r in ben})} |")
w("")
w("Both sets are requests made to the lab's own nginx on the Linux agent (source address loopback), not traffic from "
  "outside users. The attack set is a wordlist content-discovery scan; the repository identifies it as `dirb` from its "
  "default User-Agent string and the wordlist-style paths (`docs/history/fr_31101_report.md`, Task 1). The benign set is `curl` "
  "requesting three fixed endpoints in rotation. Only the access-log lines are in the repository; the scan and polling "
  "commands themselves are not, so \"dirb\" and \"curl loop\" are read from the log contents, not from a recorded "
  "command line.\n")
w("Other rules in the two files (not used by the tier study):\n")
w("| class | rules (id: alerts) |")
w("|---|---|")
w(f"| attack | {', '.join(f'{k}: {v:,}' for k, v in atk_rules.most_common())} |")
w(f"| benign | {', '.join(f'{k}: {v:,}' for k, v in ben_rules.most_common())} |")
w("")

w("## 2. How the train/test split was made\n")
w("By time, per class, with no randomisation, so there is no split seed. "
  "(The only seed in the script is `random_state=0` for XGBoost, which affects the fitted trees, not which alerts "
  "are in the test set.)\n")
w("- **Attack:** alerts sorted by timestamp; a new scan round starts wherever the gap between consecutive alerts "
  f"exceeds {GAP_S} s. That gives {len(round_sizes)} rounds. Rounds 1-5 are train, round 6 is test.\n")
w("| round | alerts | first alert | last alert | gap before it (s) |")
w("|---:|---:|---|---|---:|")
for i, (sz, (a, b)) in enumerate(zip(round_sizes, round_spans), 1):
    gl = f"{gap_lengths[i - 2]:.1f}" if i > 1 else ""
    w(f"| {i}{' (test)' if i == len(round_sizes) else ''} | {sz:,} | {a} | {b} | {gl} |")
w("")
w(f"  Train = {len(atk_train):,}, test = {len(atk_test):,}; {len(atk_train):,} + {len(atk_test):,} = {len(atk):,}.\n")
w(f"- **Benign:** alerts sorted by timestamp; the first `int({BENIGN_TRAIN_FRAC} x {len(ben)})` = {n_ben_train} are train and "
  f"the remaining {len(ben_test)} are test (the last 20% in time).\n")
w("- **Ratio:** not one ratio for the whole set. Benign is 80/20 "
  f"({n_ben_train}/{len(ben_test)}); attack is whatever the last scan round holds ({len(atk_test):,} of {len(atk):,}, "
  f"{100 * len(atk_test) / len(atk):.1f}%). Overall the test set is {len(atk_test) + len(ben_test):,} alerts "
  f"({100 * (len(atk_test) + len(ben_test)) / (len(atk) + len(ben)):.1f}% of {len(atk) + len(ben):,}).\n")
w(f"Rebuilt here from the raw files, the train and test sets are identical, alert for alert, to the `split` column of "
  f"`analysis/fr_31101_features.csv` (train n={len(atk_train) + len(ben_train):,}, test n={len(atk_test) + len(ben_test):,}).\n")

w("## 3. Why 3,464 attack and 42 benign\n")
w(f"- **3,464** is the size of the sixth and last scan round. The test set takes the last round as a unit, so its size "
  f"is fixed by how many requests that one pass of the wordlist produced, not by a chosen ratio. The five earlier rounds "
  f"hold {sum(round_sizes[:-1]):,}.")
w(f"- **42** is {len(ben)} minus `int(0.8 x {len(ben)})` = {len(ben)} - {n_ben_train}. It is the last fifth of the benign "
  f"session in time ({test_first} to {test_last}).")
w(f"- The class imbalance in the test set ({len(atk_test) / len(ben_test):.1f}:1) is therefore a consequence of the collection: "
  f"one scan round is large and the benign session is a slow 209-alert poll. It was not tuned. It is the reason the "
  f"trivial \"always attack\" rule already reaches F1 = 0.9940 on this test set (`docs/history/fr_31101_report.md`, 3a).")
w(f"- In the attack test round, {unseen_atk_test:,} of {len(atk_test):,} alerts request a path that never occurs in "
  f"rounds 1-5; the other rounds replay the same wordlist, so the held-out round is not held out in path terms.\n")

w("## 4. The 42 benign test alerts by endpoint\n")
w("| endpoint | benign total | benign train | benign test (of the 42) | share of the 42 | attack-scan alerts with this path (test round) |")
w("|---|---:|---:|---:|---:|---:|")
for p, _ in ben_all_by_path.most_common():
    w(f"| `{p}` | {ben_all_by_path[p]} | {ben_train_by_path.get(p, 0)} | **{ben_test_by_path.get(p, 0)}** | "
      f"{100 * ben_test_by_path.get(p, 0) / len(ben_test):.1f}% | {atk_test_paths.get(p, 0)} |")
w(f"| total | {len(ben)} | {len(ben_train)} | **{len(ben_test)}** | 100.0% | |")
w("")
w("The three endpoints are not equally represented in the test set, because the cut falls at an arbitrary point in the "
  "rotation rather than on a cycle boundary. The Tier B false positives follow the endpoint, not the alert: "
  "`docs/history/fr_31101_report.md` (Task 3b/3c) records that Tier B passes every `/api/status` alert (0 of "
  f"{ben_test_by_path.get('/api/status', 0)} flagged) and flags every `/about` and `/contact` alert "
  f"({ben_test_by_path.get('/about', 0)} + {ben_test_by_path.get('/contact', 0)} = "
  f"{ben_test_by_path.get('/about', 0) + ben_test_by_path.get('/contact', 0)} flagged). "
  "That is where 28/42 comes from; the per-endpoint numbers in that report match the counts in this table "
  "(not re-derived here, since that would mean refitting the Tier B model).\n")

w("## 5. Wilson 95% intervals\n")
w("Wilson score interval, z = 1.96, on the test-set counts used in `figures/fig3b_31101_tier_study.py`.\n")
w("| quantity | k / n | point estimate | Wilson 95% interval |")
w("|---|---:|---:|---|")
for name, (k, n, (lo, hi)) in CIS.items():
    w(f"| {name} | {k:,} / {n:,} | {100 * k / n:.2f}% | [{100 * lo:.1f}%, {100 * hi:.1f}%] |")
w("")
w("The two intervals are [0.0%, 8.4%] for Tier A (0/42) and [51.6%, 79.0%] for Tier B (28/42). "
  "The intervals do not overlap, so Tier A and Tier B differ on this test set.\n")
w("Caveats on reading these intervals:\n")
w(f"- The 42 alerts are not 42 independent draws. They are repeats of {len(ben_test_by_path)} fixed requests "
  f"({', '.join(f'`{p}` x {n}' for p, n in ben_test_by_path.most_common())}) from a single `curl` loop on one host, "
  "and Tier B's outcome is decided per endpoint (section 4). The effective sample for the benign side is closer to "
  "three endpoints than to 42 alerts, and the Wilson interval, which treats alerts as independent, is narrower than the "
  "evidence supports.")
w("- Tier A's 0/42 is a statement about this one benign User-Agent (`curl/8.5.0`), which the model has memorised from "
  "training; the interval bounds the rate on this benign stream, not on benign traffic in general.\n")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
