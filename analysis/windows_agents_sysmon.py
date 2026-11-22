"""
windows_agents_sysmon.py -- which Windows agents produced the collected alerts, how they are labelled,
and where the Sysmon events come from (attack round n=401, benign collection n=201).

Writes results/windows_agents_sysmon.md. Read-only; nothing existing is changed.
Run from the repository root: python analysis/windows_agents_sysmon.py
"""
import csv
import json
import os
import re
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


D = "data/testbed_collection/"
ATTACK = _p(D + "collection_win_alerts.json")
BENIGN = _p(D + "collection_benign_win_alerts.json")
LABELED = _p(D + "labeled_win.csv")
SYSMON_EID1 = _p(D + "sysmon_eid1.csv")
SYSMON_ART = _p(D + "sysmon_artifacts.csv")
OUT = _p("results/windows_agents_sysmon.md")


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


atk, ben = read_json(ATTACK), read_json(BENIGN)
with open(LABELED, encoding="utf-8", newline="") as fh:
    lab = list(csv.DictReader(fh))
assert (len(atk), len(ben), len(lab)) == (401, 201, 401)
# labeled_win.csv has no agent column; it is row-aligned with the raw file (checked, not assumed)
assert all(a["timestamp"] == r["timestamp"] and str(a["rule"]["id"]) == r["rule_id"] for a, r in zip(atk, lab))


def is_sysmon(a):
    return "sysmon" in (g.strip() for g in a["rule"].get("groups", []))


def computer(a):
    return (((a.get("data") or {}).get("win") or {}).get("system") or {}).get("computer")


agents = defaultdict(lambda: dict(atk=Counter(), atk_sys=Counter(), ben=0, ben_sys=0, computers=set(), ids=set(),
                                  ips=set(), sys_providers=Counter(), sys_rules=Counter()))
for a, r in zip(atk, lab):
    g = agents[a["agent"]["name"]]
    g["atk"][r["label"]] += 1
    g["ids"].add(a["agent"].get("id"))
    g["ips"].add(a["agent"].get("ip"))
    g["computers"].add(computer(a))
    if is_sysmon(a):
        g["atk_sys"][r["label"]] += 1
        g["sys_rules"][str(a["rule"]["id"])] += 1
        g["sys_providers"][((a.get("data") or {}).get("win") or {}).get("system", {}).get("providerName")] += 1
for a in ben:
    g = agents[a["agent"]["name"]]
    g["ben"] += 1
    g["ids"].add(a["agent"].get("id"))
    g["computers"].add(computer(a))
    if is_sysmon(a):
        g["ben_sys"] += 1
        g["sys_providers"][((a.get("data") or {}).get("win") or {}).get("system", {}).get("providerName")] += 1

for name, g in agents.items():
    print(name, dict(g["atk"]), "sysmon in attack round:", dict(g["atk_sys"]), "benign:", g["ben"], g["ben_sys"])

# machine part of the Sysmon ProcessGuid: one prefix = one machine's Sysmon
guid_prefix = Counter()
with open(SYSMON_EID1, encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        guid_prefix[r["process_guid"].strip("{}").split("-")[0]] += 1
art_prefix = Counter()
with open(SYSMON_ART, encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        art_prefix[r["process_guid"].strip("{}").split("-")[0]] += 1
alert_guid_prefix = Counter()
for a in atk + ben:
    if is_sysmon(a):
        for m in re.finditer(r"ProcessGuid: \{([0-9a-f]{8})-", ((a.get("data") or {}).get("win") or {}).get("system", {}).get("message", "") or ""):
            alert_guid_prefix[m.group(1)] += 1

# where else the name WIN-DC occurs
dc_hits = []
for root, _, files in os.walk(REPO_ROOT):
    if any(s in root for s in (os.sep + ".git", "__pycache__")):
        continue
    for f in files:
        if f.endswith((".py", ".csv", ".json")) and os.path.getsize(os.path.join(root, f)) < 30_000_000:
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, 1):
                        if re.search(r"win[-_]?dc", line, re.I) and not path.endswith("windows_agents_sysmon.py"):
                            dc_hits.append((os.path.relpath(path, REPO_ROOT).replace(os.sep, "/"), i))
            except OSError:
                pass
dc_files = dict(sorted(Counter(f for f, _ in dc_hits).items()))
print("files naming win-dc:", dict(dc_files))

L = []
w = L.append
cl = agents["WIN-CL1"]
only_cl1 = list(agents) == ["WIN-CL1"]
w("# Windows alerts: agents, labels and Sysmon\n")
w("Produced by `analysis/windows_agents_sysmon.py` from `data/testbed_collection/collection_win_alerts.json` "
  "(attack round, n=401, with `labeled_win.csv`) and `collection_benign_win_alerts.json` (benign, n=201). Read-only.\n")
w("**Answer.** " + (
    "Every one of the 602 Windows alerts comes from a single agent, `WIN-CL1` (agent id 002). "
    "`WIN-DC` produced no alert in either collection, so no alert from it carries any label (zero attack-labelled alerts "
    "from `WIN-DC`) and no Sysmon event from it appears. The data cannot say whether `WIN-DC` ran Sysmon at all, "
    "because nothing was collected from it. All Sysmon events in the collections come from `WIN-CL1`."
    if only_cl1 else "SEE TABLE: more than one agent present."))
w("")
w("## Alerts per agent name\n")
w("| agent name (id) | attack round, attack | attack round, uncertain | attack round, benign | attack round, total | "
  "of which `sysmon` group | benign collection, total | of which `sysmon` group |")
w("|---|---:|---:|---:|---:|---:|---:|---:|")
for name, g in agents.items():
    w(f"| `{name}` ({', '.join(sorted(g['ids']))}) | {g['atk']['attack']} | {g['atk']['uncertain']} | {g['atk']['benign']} | "
      f"{sum(g['atk'].values())} | {sum(g['atk_sys'].values())} | {g['ben']} | {g['ben_sys']} |")
w("| `WIN-DC` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")
w("")
w("Labels are the `label` column of `labeled_win.csv` (time-window / process-tree labelling; `uncertain` = outside "
  "the session or ambiguous). That file has no agent column, so it was joined to the raw alerts row by row "
  "(timestamp and rule id agree on all 401 rows). The benign collection is a separate benign-only session "
  "and is not labelled through `labeled_win.csv`.\n")
w("Sysmon alerts by label in the attack round (rule group `sysmon`):\n")
w("| agent | attack | uncertain | benign |")
w("|---|---:|---:|---:|")
for name, g in agents.items():
    w(f"| `{name}` | {g['atk_sys']['attack']} | {g['atk_sys']['uncertain']} | {g['atk_sys']['benign']} |")
w("")

w("## Why this is read as one host\n")
agent_fields = ", ".join("`%s` id %s, ip %s" % (n, sorted(g["ids"]), sorted(i for i in g["ips"] if i))
                         for n, g in agents.items())
computers = ", ".join("`%s`" % c for g in agents.values() for c in sorted(x for x in g["computers"] if x))
providers = ", ".join("`%s` (%d)" % (k, v) for g in agents.values() for k, v in g["sys_providers"].items())
w(f"- Agent fields: {agent_fields}.")
w(f"- The Windows event's own `data.win.system.computer` is {computers} on all {len(atk) + len(ben)} alerts, "
  "so no alert is a forwarded event from another machine.")
w(f"- Sysmon provider on the `sysmon` alerts: {providers}.")
w(f"- Process GUIDs carry the machine part as their first 8 hex digits. In `sysmon_eid1.csv` ({sum(guid_prefix.values()):,} rows): "
  f"{', '.join(f'`{k}` ({v:,})' for k, v in guid_prefix.items())}; in `sysmon_artifacts.csv` ({sum(art_prefix.values()):,} rows): "
  f"{', '.join(f'`{k}` ({v:,})' for k, v in art_prefix.items())}; inside the Sysmon alert messages: "
  f"{', '.join(f'`{k}` ({v:,})' for k, v in alert_guid_prefix.items())}. One prefix throughout, so one machine's Sysmon.")
w(f"- Where `WIN-DC` is named in the repository's code and data files: {', '.join(f'`{f}` ({n})' for f, n in dc_files.items()) or 'nowhere'}. "
  "The only functional use is the `agent_criticality` lookup (`shared_constants.py`: `\"win-dc\": 3`), a weight for an "
  "agent name that never occurs in these collections. It is not evidence that `WIN-DC` was monitored.\n")
w("## Reading this\n")
w("- All 336 attack-labelled Windows alerts, the 62 uncertain and the 3 benign-labelled ones are from `WIN-CL1`. "
  "The attack hosts are not separable from the benign host in this data: the same single endpoint is both.")
w("- The paper should not describe a domain controller as monitored, or as an attack host, on the strength of "
  "these alerts. If `WIN-DC` ran Sysmon, that evidence is not in the repository.")
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
