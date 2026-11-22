"""
rule553_technique.py -- which technique produced the 20 attack-labelled alerts of Wazuh rule 553 in the
novel-attack set, and what the rule is.

Reads data/testbed_collection/labeled_lnx.csv (row-aligned with collection_lnx_alerts.json) and the raw alerts.
Writes results/rule553_technique.md. Read-only; nothing existing is changed.
Run from the repository root: python analysis/rule553_technique.py
"""
import csv
import json
import os
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


D = "data/testbed_collection/"
OUT = _p("results/rule553_technique.md")

with open(_p(D + "labeled_lnx.csv"), encoding="utf-8", newline="") as fh:
    lab = list(csv.DictReader(fh))
with open(_p(D + "collection_lnx_alerts.json"), encoding="utf-8") as fh:
    raw = [json.loads(l) for l in fh if l.strip()]
assert len(lab) == len(raw)
assert all(r["timestamp"] == a["timestamp"] and r["rule_id"] == str(a["rule"]["id"]) for r, a in zip(lab, raw))

idx = [i for i, r in enumerate(lab) if r["rule_id"] == "553"]
all553 = [(lab[i], raw[i]) for i in idx]
atk = [(r, a) for r, a in all553 if r["label"] == "attack"]
print("rule 553:", len(all553), "attack:", len(atk))
assert len(atk) == 20


def cnt(rows, f):
    return Counter(f(r, a) for r, a in rows)


tech = cnt(atk, lambda r, a: r["technique"])
art_tech = cnt(atk, lambda r, a: r["artifact_technique"])
desc = cnt(atk, lambda r, a: a["rule"]["description"])
lvl = cnt(atk, lambda r, a: a["rule"]["level"])
grp = cnt(atk, lambda r, a: ",".join(a["rule"].get("groups", [])))
mitre = cnt(atk, lambda r, a: ",".join(a["rule"].get("mitre", {}).get("id", [])))
mitre_name = cnt(atk, lambda r, a: ",".join(a["rule"].get("mitre", {}).get("technique", [])))
conf = cnt(atk, lambda r, a: r["label_confidence"])
tsrc = cnt(atk, lambda r, a: r["time_source"])
rounds = cnt(atk, lambda r, a: int(float(r["round"])))
paths = cnt(atk, lambda r, a: r["syscheck_path"])
ev = cnt(atk, lambda r, a: r["syscheck_event"])
rest = cnt([x for x in all553 if x[0]["label"] != "attack"], lambda r, a: (r["label"], r["label_confidence"]))
rest_paths = cnt([x for x in all553 if x[0]["label"] != "attack"], lambda r, a: r["syscheck_path"])
print(tech, art_tech, desc, mitre, conf, rounds)

# the technique windows of the rounds that contain them
windows = {}
for r, a in atk:
    windows.setdefault(int(float(r["round"])), (r["window_start"], r["window_end"]))

L = []
w = L.append
w("# Rule 553 in the novel-attack set: which technique produced the 20 alerts\n")
w("Produced by `analysis/rule553_technique.py` from `data/testbed_collection/labeled_lnx.csv` and "
  "`collection_lnx_alerts.json` (row-aligned; timestamp and rule id agree on all rows). Read-only.\n")
w("**Answer.** All 20 attack-labelled rule-553 alerts are labelled **T1136.001 (Create Account: Local Account)**, "
  "the `useradd` / `userdel coluser` step of the collection. No other technique produced any of them. "
  "The rule's own Wazuh description is **\"" + ", ".join(desc) + "\"** (rule level " + ", ".join(str(k) for k in lvl) +
  "; groups " + ", ".join(f"`{k}`" for k in grp) + ").\n")
w("## The 20 alerts\n")
w("| property | value |")
w("|---|---|")
w(f"| Wazuh rule | 553, description \"{', '.join(desc)}\", level {', '.join(str(k) for k in lvl)} |")
mitre_pairs = cnt(atk, lambda r, a: "%s (%s)" % (",".join(a["rule"].get("mitre", {}).get("id", [])),
                                                 ", ".join(a["rule"].get("mitre", {}).get("technique", []))))
w("| rule's own MITRE mapping (in the alert) | " + ", ".join("%s: %d" % (k, v) for k, v in mitre_pairs.items()) + " |")
w(f"| technique label (`technique`) | {', '.join(f'{k}: {v}' for k, v in tech.items())} |")
w(f"| path-based label (`artifact_technique`: any passwd-family path maps to T1136.001) | {', '.join(f'{k}: {v}' for k, v in art_tech.items())} |")
w(f"| syscheck event | {', '.join(f'{k}: {v}' for k, v in ev.items())} |")
w(f"| label confidence | {', '.join(f'{k}: {v}' for k, v in conf.items())} |")
w(f"| time source | {', '.join(f'{k}: {v}' for k, v in tsrc.items())} |")
w(f"| collection round | {', '.join(f'round {k}: {v}' for k, v in sorted(rounds.items()))} |")
w("")
w("Files named in the alerts (`syscheck.path`):\n")
w("| path | alerts |")
w("|---|---:|")
for k, v in sorted(paths.items(), key=lambda kv: (-kv[1], kv[0])):
    w(f"| `{k}` | {v} |")
w("")
w("The technique windows that contain them (`window_start` to `window_end`, from the collection markers):\n")
w("| round | window start | window end |")
w("|---:|---|---|")
for k, (s, e) in sorted(windows.items()):
    w(f"| {k} | {s} | {e} |")
w("")
w("## How to read it\n")
w("- Rule 553 is the generic FIM \"File deleted\" rule. It is not specific to any technique, and its own MITRE tags "
  f"({', '.join(mitre)}) are file-deletion techniques that are not what the collection ran.")
w("- The 20 alerts are deletions of `useradd`/`userdel` working files: `*.lock` files and numbered temporary copies "
  "of `/etc/passwd`, `/etc/group` and the shadow files. They are side effects of creating and removing the account, "
  "not the account creation itself. `docs/eval_set_definition.md` and `docs/history/ew_carrier_classification.md` "
  "already count them as the \"T1136.001 incidental\" population.")
w(f"- Label strength is the weakest tier: `{', '.join(conf)}`. Rule 553 carries no usable event time "
  "(`syscheck.mtime_after` is the file's last modification, not the deletion time), so the label rests on the "
  "alert timestamp falling inside the T1136.001 window, with the 18-80 s ingestion lag unresolved. The "
  "path-based mapping above also gives T1136.001 for all 20; it is a prefix rule over the passwd-family paths "
  "in `labelling/label_lnx_timeonly.py`, so it is a consistency check on the window label, not independent evidence.")
w(f"- Rule 553 has {len(all553)} alerts in the attack round in all. The other {len(all553) - len(atk)} are not "
  f"attack-labelled: " + ", ".join(f"{v} {k[0]} ({k[1]})" for k, v in rest.items()) + ".")
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
