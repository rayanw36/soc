"""
rule31101_fields.py -- field inventory and collision check for the live Linux
rule-31101 alerts (attack 20,665; benign 209).

Writes results/rule31101_fields.md. Read-only on the two collections; no
model is fitted and nothing existing is modified.

  1. Every field an alert carries (the Wazuh JSON, flattened, plus the parsed
     Nginx access line): distinct values in attack, in benign, and in both.
  2. Drop the fields an attacker controls cheaply (User-Agent, source IP,
     query string, referrer). On the remaining fields (method, path, status,
     response size, rule id / level / groups) count the benign alerts whose
     exact representation also occurs among the attack alerts, and the
     reverse. Repeat with path removed as well.
  3. Which of the benign endpoints also occur in the attack scan.

Run from the repository root: python analysis/rule31101_fields.py
"""
import json
import os
import re
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


ATTACK = _p("data/testbed_collection/collection_lnx_alerts.json")
BENIGN = _p("data/testbed_collection/collection_benign_lnx_alerts.json")
OUT = _p("results/rule31101_fields.md")

LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+) (?P<ident>\S+) (?P<auth_user>\S+) \[(?P<time_local>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<target>\S+) (?P<http_version>[^"]+)" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)


def flatten(obj, prefix=""):
    """Wazuh JSON -> {dotted.key: value}; lists are kept whole (as JSON text)."""
    out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        elif isinstance(v, list):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out


def load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            if a.get("rule", {}).get("id") != "31101":
                continue
            m = LOG_RE.match(a["full_log"])
            if not m:
                raise ValueError(f"unparsed full_log: {a['full_log']!r}")
            row = {f"wazuh:{k}": v for k, v in flatten(a).items()}
            g = m.groupdict()
            target = g.pop("target")
            path, _, query = target.partition("?")
            g["path"] = path
            g["query_string"] = query
            row.update({f"nginx:{k}": v for k, v in g.items()})
            rows.append(row)
    return rows


atk = load(ATTACK)
ben = load(BENIGN)
assert (len(atk), len(ben)) == (20665, 209), (len(atk), len(ben))
print(f"attack {len(atk)}  benign {len(ben)}")

# ---------------------------------------------------------------- 1. inventory
fields = []
for r in atk + ben:
    for k in r:
        if k not in fields:
            fields.append(k)
# keys must be present in every alert, otherwise the count would silently skip alerts
missing = {f: sum(1 for r in atk + ben if f not in r) for f in fields}
missing = {f: n for f, n in missing.items() if n}
print("fields missing from some alerts:", missing or "none")

# the data.* decoder fields repeat parts of the Nginx line; check, don't assume
dup_checks = {
    "wazuh:data.srcip == nginx:remote_addr": lambda r: r.get("wazuh:data.srcip") == r["nginx:remote_addr"],
    "wazuh:data.id == nginx:status": lambda r: r.get("wazuh:data.id") == r["nginx:status"],
    "wazuh:data.protocol == nginx:method": lambda r: r.get("wazuh:data.protocol") == r["nginx:method"],
    "wazuh:data.url == request target (path?query)": lambda r: r.get("wazuh:data.url") == (
        r["nginx:path"] + ("?" + r["nginx:query_string"] if r["nginx:query_string"] else "")),
}
dup_result = {n: sum(1 for r in atk + ben if f(r)) for n, f in dup_checks.items()}
for n, c in dup_result.items():
    print(f"  {n}: {c}/{len(atk) + len(ben)}")

inv = []
for f in fields:
    sa = {r.get(f) for r in atk}
    sb = {r.get(f) for r in ben}
    inv.append((f, len(sa), len(sb), len(sa & sb), len(sa | sb)))

# ----------------------------------------------------------------- 2. collisions
CHEAP = {"nginx:user_agent", "nginx:remote_addr", "nginx:query_string", "nginx:referer"}
REMAIN = ["nginx:method", "nginx:path", "nginx:status", "nginx:bytes",
          "wazuh:rule.id", "wazuh:rule.level", "wazuh:rule.groups"]
REMAIN_NOPATH = [f for f in REMAIN if f != "nginx:path"]


def key(r, cols):
    return tuple(r[c] for c in cols)


def collisions(cols):
    ka = Counter(key(r, cols) for r in atk)
    kb = Counter(key(r, cols) for r in ben)
    both = set(ka) & set(kb)
    return dict(
        distinct_atk=len(ka), distinct_ben=len(kb), distinct_both=len(both),
        ben_alerts=sum(kb[k] for k in both), atk_alerts=sum(ka[k] for k in both),
        ka=ka, kb=kb, both=both,
    )


c_full = collisions(REMAIN)
c_nopath = collisions(REMAIN_NOPATH)
REMAIN_NOBYTES = [f for f in REMAIN if f != "nginx:bytes"]
REMAIN_NOPATH_NOBYTES = [f for f in REMAIN if f not in ("nginx:path", "nginx:bytes")]
c_nobytes = collisions(REMAIN_NOBYTES)
c_nopath_nobytes = collisions(REMAIN_NOPATH_NOBYTES)
# values of the one remaining field that differs between the classes, next to the
# User-Agent they co-occur with (UA is cheap; shown to see whether bytes is independent of it)
bytes_ua = {cls: Counter((r["nginx:bytes"], r["nginx:user_agent"]) for r in rows)
            for cls, rows in (("attack", atk), ("benign", ben))}
print("(bytes, user_agent) pairs:", {k: dict(v) for k, v in bytes_ua.items()})
# leave-one-field-out, to show which remaining field carries the separation
c_drop = {f: collisions([x for x in REMAIN if x != f]) for f in REMAIN}
# the same, adding back the cheap fields one at a time, for context only
c_plus = {f: collisions(REMAIN + [f]) for f in sorted(CHEAP)}

for name, c in (("remaining fields", c_full), ("remaining, path removed", c_nopath)):
    print(f"{name}: distinct atk={c['distinct_atk']} ben={c['distinct_ben']} both={c['distinct_both']}; "
          f"benign alerts colliding {c['ben_alerts']}/{len(ben)}; attack alerts colliding {c['atk_alerts']}/{len(atk)}")

# ----------------------------------------------------------------- 3. endpoints
ben_paths = Counter(r["nginx:path"] for r in ben)
atk_paths = Counter(r["nginx:path"] for r in atk)
endpoint_rows = []
for p, n in ben_paths.most_common():
    endpoint_rows.append((p, n, atk_paths.get(p, 0)))
print("benign endpoints:", endpoint_rows)

# ----------------------------------------------------------------- write markdown


def pct(a, b):
    return f"{100 * a / b:.2f}%"


def fmt_key(k, cols):
    return ", ".join(f"{c.split(':', 1)[1]}={v}" for c, v in zip(cols, k))


L = []
w = L.append
w("# Rule 31101: field inventory and collision check\n")
w("Produced by `analysis/rule31101_fields.py` from the live Linux collections "
  "`data/testbed_collection/collection_lnx_alerts.json` (attack, "
  f"n={len(atk):,}) and `collection_benign_lnx_alerts.json` (benign, n={len(ben):,}), rule id 31101 only. "
  "Read-only analysis: no model is fitted and no existing file is changed.\n")

w("## 1. Fields an alert carries\n")
w("`wazuh:*` is the Wazuh alert JSON (nested keys joined with `.`; list-valued keys compared as a whole). "
  "`nginx:*` is the access line parsed out of `full_log` "
  "(`remote_addr ident auth_user [time_local] \"method target http_version\" status bytes \"referer\" \"user_agent\"`; "
  "`target` is split into `path` and `query_string`). "
  "\"Both\" is the number of distinct values that occur in the attack set and also in the benign set. "
  "\"Cheap\" marks the four fields an attacker controls at no cost "
  "(User-Agent, source IP, query string, referrer).\n")
w("| field | distinct in attack | distinct in benign | distinct in both | note |")
w("|---|---:|---:|---:|---|")
notes = {
    "nginx:user_agent": "cheap (attacker-set header)",
    "nginx:remote_addr": "cheap",
    "nginx:query_string": "cheap",
    "nginx:referer": "cheap",
    "wazuh:data.srcip": "cheap; copy of `nginx:remote_addr`",
    "wazuh:data.url": "copy of request target (path plus query string)",
    "wazuh:data.id": "copy of `nginx:status`",
    "wazuh:data.protocol": "copy of `nginx:method`",
    "wazuh:full_log": "whole access line",
    "wazuh:timestamp": "alert time",
    "wazuh:id": "Wazuh alert id",
    "wazuh:rule.firedtimes": "running counter",
}
for f, na, nb, nboth, _ in inv:
    w(f"| `{f}` | {na:,} | {nb:,} | {nboth:,} | {notes.get(f, '')} |")
w("")
w("Copy checks (alerts for which the equality holds, out of "
  f"{len(atk) + len(ben):,}): " + "; ".join(f"`{n}`: {c:,}" for n, c in dup_result.items()) + ".")
if missing:
    w("\nFields absent from some alerts: " + ", ".join(f"`{f}` ({n:,})" for f, n in missing.items()) + ".")
else:
    w("\nEvery field above is present in every one of the "
      f"{len(atk) + len(ben):,} alerts (no missing values).")
w("")

w("## 2. Collisions after removing the cheap fields\n")
w("Cheap fields removed: User-Agent, source IP, query string, referrer. "
  "Representation kept: `method`, `path`, `status`, `bytes` (response size), `rule.id`, `rule.level`, `rule.groups`. "
  "An alert \"collides\" when another alert of the opposite class has exactly the same representation.\n")
w("| representation | distinct (attack) | distinct (benign) | distinct in both | benign alerts colliding | attack alerts colliding |")
w("|---|---:|---:|---:|---:|---:|")
for name, c in (("method, path, status, bytes, rule id/level/groups", c_full),
                ("same, path removed (method, status, bytes, rule id/level/groups)", c_nopath),
                ("extra: bytes removed instead (method, path, status, rule id/level/groups)", c_nobytes),
                ("extra: path and bytes both removed (method, status, rule id/level/groups)", c_nopath_nobytes)):
    w(f"| {name} | {c['distinct_atk']:,} | {c['distinct_ben']:,} | {c['distinct_both']:,} | "
      f"{c['ben_alerts']:,} / {len(ben):,} ({pct(c['ben_alerts'], len(ben))}) | "
      f"{c['atk_alerts']:,} / {len(atk):,} ({pct(c['atk_alerts'], len(atk))}) |")
w("")
w("The first two rows are the main check. Both give zero collisions, but only because of `bytes`: "
  "`method`, `status` and every rule field take a single value in both classes, and `path` is the only other field "
  "that varies. The two extra rows show what happens when `bytes` is taken out as well.\n")
w("Response size and User-Agent as they occur together:\n")
w("| class | bytes | user_agent | alerts |")
w("|---|---:|---|---:|")
for cls, cnt in bytes_ua.items():
    for (b, ua), n in cnt.most_common():
        w(f"| {cls} | {b} | `{ua}` | {n:,} |")
w("")
w("In this data `bytes` is therefore a one-to-one stand-in for the User-Agent: 564 with the attack scanner's "
  "MSIE 6.0 string, 162 with `curl/8.5.0`. The cause is not recorded in the repository (no nginx configuration is "
  "included). One possible mechanism is nginx's `msie_padding` directive, which pads error pages for old MSIE "
  "clients; this is an unverified hypothesis, not something the data shows. What the data does show is that "
  "size is not a function of the path: `/about` and `/contact` occur in both classes (section 3) with 564 bytes in "
  "the attack scan and 162 bytes in the benign traffic, so it varies with the client. Every attack alert has one "
  "User-Agent and one size, so the two cannot be separated further here.\n")
w("Representations shared by both classes, with the alert count on each side:\n")
for name, c, cols in (("with path", c_full, REMAIN), ("path removed", c_nopath, REMAIN_NOPATH),
                      ("bytes removed", c_nobytes, REMAIN_NOBYTES),
                      ("path and bytes removed", c_nopath_nobytes, REMAIN_NOPATH_NOBYTES)):
    w(f"**{name}**\n")
    if not c["both"]:
        w("- none\n")
        continue
    w("| representation | attack alerts | benign alerts |")
    w("|---|---:|---:|")
    for k in sorted(c["both"], key=lambda k: (-c["kb"][k], str(k))):
        w(f"| {fmt_key(k, cols)} | {c['ka'][k]:,} | {c['kb'][k]:,} |")
    w("")

w("### Which remaining field carries the separation (leave one out, path kept in unless it is the one dropped)\n")
w("| field dropped from the representation | benign alerts colliding | attack alerts colliding |")
w("|---|---:|---:|")
for f in REMAIN:
    c = c_drop[f]
    w(f"| `{f.split(':', 1)[1]}` | {c['ben_alerts']:,} / {len(ben):,} | {c['atk_alerts']:,} / {len(atk):,} |")
w("")
w("### For context: adding one cheap field back to the full remaining representation\n")
w("| cheap field added | benign alerts colliding | attack alerts colliding |")
w("|---|---:|---:|")
for f, c in c_plus.items():
    w(f"| `{f.split(':', 1)[1]}` | {c['ben_alerts']:,} / {len(ben):,} | {c['atk_alerts']:,} / {len(atk):,} |")
w("")

w("## 3. Benign endpoints versus the attack scan\n")
w("| benign endpoint (path) | benign alerts | attack alerts with the same path | appears in the attack scan |")
w("|---|---:|---:|---|")
for p, nb, na in endpoint_rows:
    w(f"| `{p}` | {nb:,} | {na:,} | {'yes' if na else 'no'} |")
w("")
w(f"Distinct paths: {len(atk_paths):,} in attack, {len(ben_paths):,} in benign, "
  f"{len(set(atk_paths) & set(ben_paths))} in both.")
w("")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
