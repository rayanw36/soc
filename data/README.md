# Data

## AIT-ADS (not included — download separately)

This repository does **not** include the raw AIT-ADS alert data. The
dataset paper does not clearly grant redistribution rights for the raw
files, so they are excluded per this repository's safety review; only
this project's own small derived artifacts (`labels.csv`'s row count,
computed rule/signature statistics, the trained model files under
`models_v2/`) are committed.

**Citation** (cite this if you use AIT-ADS):

> Max Landauer, Florian Skopik, Markus Wurzenberger. "Introducing a New
> Alert Data Set for Multi-Step Attack Analysis." *Proceedings of the
> 17th Cyber Security Experimentation and Test Workshop* (CSET '24),
> pp. 41–53, 2024. DOI: [10.1145/3675741.3675748](https://doi.org/10.1145/3675741.3675748).
> Also on arXiv: [2308.12627](https://arxiv.org/abs/2308.12627).

**Obtaining the data.** The DOI above resolves to the paper, not the
dataset file itself — get the actual download link from the paper's data
availability statement (checked at the time this repository was
prepared, the AIT research group publishes their alert/log datasets
under the `ait-lds`/`ait-aecid` project pages; search "AIT-ADS" or "AIT
Alert Data Set" together with the citation above). Once obtained, expect
8 scenario subdirectories (`fox`, `harrison`, `russellmitchell`,
`santos`, `shaw`, `wardbeck`, `wheeler`, `wilson`), each with a
`*_wazuh.json` and `*_aminer.json` alert stream, plus a `labels.csv` of
`(scenario, attack, start, end)` time-window intervals. Place them at:

```
data/ait_ads/raw/<scenario>_wazuh.json
data/ait_ads/raw/<scenario>_aminer.json
data/ait_ads/labels.csv
```

`download_ait_ads.py` in this directory checks for that layout and
reports what's missing; it does not itself know a hardcoded download URL
(none is asserted here that hasn't been independently verified — see the
script's own docstring).

Every `analysis/`, `labelling/`, and `figures/` script that reads
`data/ait_ads/raw/` will run without it if a script's other inputs
(e.g. the already-committed `models_v2/ait_split.npz`, or the
already-computed `.npz`/`.json` outputs under `analysis/`) are present —
`reproduce.sh` reports which steps need the raw download and skips them
if it's absent, rather than failing silently.

## Testbed collection (`testbed_collection/`)

This project's own fresh Atomic Red Team-style collection: Linux
(`lnx-dmz`) and Windows (`win-cl1`) hosts, an attack round and a separate
dedicated benign-only round per platform. Included in full (well under
GitHub's size limits) since it is this project's own data, not a
third-party redistribution:

| file | what it is |
|---|---|
| `collection_lnx_alerts.{json,csv}`, `collection_win_alerts.{json,csv}` | raw Wazuh/Sysmon alert stream, attack round |
| `labeled_lnx.csv`, `labeled_win.csv` | the same, after labelling (see `labelling/`) |
| `collection_benign_lnx_alerts.{json,csv}`, `collection_benign_win_alerts.{json,csv}` | the dedicated benign-only collection round (Linux n=267, Windows n=201) |
| `audit_lnxdmz.log` | raw Linux auditd log (partial — see `labelling/label_lnx_timeonly.py`'s docstring: rotation lost ~79% of the collection window, which is why Linux labelling does not use a process tree) |
| `sysmon_eid1.csv`, `sysmon_artifacts.csv` | parsed Sysmon process-creation records used to build the Windows process tree (`labelling/build_sysmon_tree.py`) |
| `collect_markers_{lnx,win}.txt` | timestamped `>>> ... START/END` markers delimiting each attack technique window |

**`sysmon_wincl1.evtx` (the 59 MB raw Sysmon export `sysmon_eid1.csv` was
parsed from) is deliberately excluded** — available on request; it adds
no information beyond what `sysmon_eid1.csv`/`sysmon_artifacts.csv`
already carry for this repository's own analysis scripts.

**A privacy note, found during the repository's safety review (see
`REPO_CHANGES.md`):** an email-style Windows account identifier
(`coe551sec@gmail.com`), appearing to be the shared lab/course account
used to run the Windows collection, was found embedded in several raw
and derived files here (`collection_win_alerts.json`,
`collection_benign_win_alerts.json`, `labeled_win.csv`,
`sysmon_artifacts.csv`, the entity-window extractor outputs under
`analysis/ew_features/`, and one mention in `docs/uadiv_check.md`) —
flagged first, then, on confirmation, **replaced with a single
placeholder** (`coe551sec@gmail.com` → `lab-user-1`) across all seven
files. **Correction to an earlier version of this note:** a first-pass
safety scan reported a second, `t`-prefixed identity,
`tcoe551sec@gmail.com`, and an initial redaction attempt treated it as a
second account needing its own placeholder. That was wrong, and the
attempt broke `collection_win_alerts.json`'s JSON validity when it did
(caught immediately by re-running `reproduce.sh`, which failed
`json.loads` on the resulting line — see `REPO_CHANGES.md`). The `t` is
not part of a second address: raw Windows event-log text embeds a
literal `\t\t` (two tab characters) immediately before the address in
several fields, and a same-length substring match glued the escape's `t`
onto the front of the real address, misreading `\t\t` + `coe551sec@gmail.com`
as `\t` + `tcoe551sec@gmail.com`. Checked directly in the original,
unredacted files before re-doing the redaction: the string
`tcoe551sec@gmail.com` never occurs on its own anywhere outside that
tab-adjacency artifact, in either the JSON files or their CSV/markdown
derivatives — there is one account, not two. Redone with the single
placeholder above; `reproduce.sh` re-run clean afterward (`json.loads`
succeeds on every line of both JSON files, and Windows labelling
reproduces the identical 187/336 HIGH-process count as before the
redaction). Zero occurrences of `coe551sec` remain in these seven files
(re-verified by grep) — see `REPO_CHANGES.md` for the full accounting.

**IP addresses** in this data (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`)
are all private/loopback lab ranges from an isolated testbed — no public
IPs are present.
