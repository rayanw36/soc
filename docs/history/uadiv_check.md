# UADIV — Identifying-field diversity check

Script: `newCol/uadiv_check.py`. Full output: `newCol/uadiv_results.json`
(+ `/tmp/uadiv_run.log`, stdout transcript). Labelling discipline
identical to the rest of this audit (`labels.csv` time-window /
`merge_asof`; our own collections use their existing `label` column).
No model trained, no threshold fit — pure descriptive statistics
(coverage, distinct-value counts, entropy, set overlap).

**Bottom line, stated up front: Partially supported.** The hypothesis
holds strongly and cleanly for **User-Agent specifically** — every
population tested shows near-zero within-class diversity and near-zero
cross-class overlap in UA, at volume, wherever UA has meaningful
coverage. It does **not** extend to source IP or URL/path, which show
the *opposite* pattern in several populations (benign more diverse than
attack in source IP; attack far more diverse than benign in URL/path).
The unifying claim available to the manuscript is therefore narrower
than proposed: not "identifying fields are narrow," but "the tool's own
self-announced identity string is narrow and disjoint, while what the
tool does with that identity (targets, source addresses) is not."

---

## Task 1 — Field coverage

| population | n | with User-Agent | coverage |
|---|--:|--:|--:|
| AIT-ADS Wazuh-native | 2,293,628 | 1,696,191 | **73.95%** |
| AIT-ADS Suricata (86601) | 306,635 | 3,597 | **1.17%** |
| AIT-ADS AMiner | 55,558 | 41,373 | **74.47%** |
| Our Linux attack | 22,769 | 22,284 | **97.87%** |
| Our Linux benign | 267 | 209 | **78.28%** |
| Our Windows attack | 336 | 0 | **0.00%** |
| Our Windows benign | 201 | 0 | **0.00%** |

**Scope, stated explicitly (1b):** Windows alerts (Sysmon-based, no HTTP
layer) carry no User-Agent field at all — 0% coverage confirms this
directly rather than assuming it. Where UA does exist, coverage is high
(74-98%) for Wazuh-native, AMiner, and our own Linux collections, because
these are dominated by web/Apache-access-log rule/detector types. **Suricata
is the outlier: only 1.17% of the 86601 population carries UA**, because
most Suricata-via-Wazuh alerts are TLS/DNS/SMTP protocol events with no
HTTP layer at all — this alone is a partial, independent explanation
(distinct from B1's majority-benign-signature finding) for why Suricata's
population is hard to separate on content: the one field this check is
built around is largely **absent**, not just unhelpful, for that
detector.

**Field paths used (1c):**
- AIT-ADS Wazuh-native: regex-parsed from `full_log` (the embedded
  Apache combined-log line) — no structured UA field exists in Wazuh's
  own JSON for these rules.
- AIT-ADS Suricata (86601): structured field `data.http.http_user_agent`
  (present only when `data.app_proto == "http"`).
- AIT-ADS AMiner: regex-parsed from `LogData.RawLogData[0]` (same
  Apache-log-line embedding as Wazuh, independently confirmed present).
- Our Linux collections: regex-parsed from `full_log` (`labeled_lnx.csv`
  / `collection_benign_lnx_alerts.json`).
- Our Windows collections: no equivalent field exists (`labeled_win.csv`
  / `collection_benign_win_alerts.json` are Sysmon process-creation
  events; checked directly, confirmed absent, not assumed).

## Task 2 — Diversity per class (User-Agent)

Normalized Shannon entropy convention, stated once: `-Σp·log2(p) /
log2(n_distinct)`, in [0,1], 0 = single value, 1 = uniform over all
distinct values seen. This is a different, unrelated convention from the
NMI convention used elsewhere in this audit (`xdet_results.md`) — the two
should not be confused; NMI measures association between two variables,
this measures concentration within one.

### AIT-ADS Wazuh-native

| | n with UA | distinct | top-1 share | top-3 share | H (norm.) |
|---|--:|--:|--:|--:|--:|
| attack | 1,695,548 | 7 | **98.38%** | 100.00% | **0.043** |
| benign | 643 | 3 | 54.74% | 100.00% | 0.764 |

Top attack values (verbatim, with counts):
1. `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` — **1,668,052** (dirb's default UA)
2. `WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)` — 27,269
3. `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)` — 159
4. `-` (empty) — 54
5. `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0` — 7

Top benign values:
1. `Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/97.0.4692.71 ...` — 352
2. `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0` — 261
3. `Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/95.0.4638.69 ...` — 30

**Overlap (the decisive number, 2f): 3 shared values.** But volume tells
the real story: those 3 shared values are **100% of benign's UA volume**
but only **0.0008% of attack's** — the dominant attack signal (dirb's
1.67M MSIE-6.0 requests) is completely disjoint from anything benign;
only a vanishing sliver of attack-window traffic (7 genuine Firefox hits,
almost certainly incidental human/QA activity swept into a labelled
attack window) overlaps with benign UA space at all.

### AIT-ADS Suricata (86601) — the outlier, consistent with B1's weak-signal finding

| | n with UA | distinct | top-1 share | top-3 share | H (norm.) |
|---|--:|--:|--:|--:|--:|
| attack | 175 | 2 | 78.86% | 100.00% | 0.744 |
| benign | 3,422 | 4 | 61.16% | 99.47% | 0.523 |

Top attack values: `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` = 138;
`Debian APT-HTTP/1.3 (1.6.12ubuntu0.2)` = 37.
Top benign values: `Debian APT-HTTP/1.3 (1.6.12ubuntu0.2)` = 2,093;
`Debian APT-HTTP/1.3 (1.6.14)` = 1,292; two browser UAs = 19+18.

**Overlap: only 1 shared value — but that one value is `Debian
APT-HTTP/1.3 (1.6.12ubuntu0.2)` (routine package-manager traffic),
representing 21.14% of attack UA volume and 61.16% of benign UA volume.**
This is a materially higher, not lower, overlap share than Wazuh-native's
near-zero — **independent, converging evidence for why Suricata failed
to separate in B1/Addition A**: where this detector does carry a UA
signal at all, a large share of it is shared background system traffic
(automatic APT updates), not tool-exclusive.

### AIT-ADS AMiner

| | n with UA | distinct | top-1 share | top-3 share | H (norm.) |
|---|--:|--:|--:|--:|--:|
| attack | 40,501 | 9 | 67.52% | 99.75% | 0.299 |
| benign | 872 | 9 | 50.57% | 91.51% | 0.590 |

Top attack values: `WPScan v3.8.20 (...)` = 27,347; `Mozilla/4.0
(compatible; MSIE 6.0; Windows NT 5.1)` = 12,998 (dirb, also picked up by
AMiner's Apache-log detectors, not just Wazuh's); `-` = 55; Nmap NSE UA =
54; `python-requests/2.27.1` = 34.
Top benign values: three distinct real-browser UAs (Firefox,
HeadlessChrome ×2) totalling 798; Apache internal dummy-connection UA =
31; `-` = 24.

**Overlap: 5 shared values, but 0.17% of attack UA volume vs. 97.82% of
benign UA volume** — the same pattern as Wazuh-native: the dominant
attack signal is disjoint; overlap captures almost all of benign's
(much smaller) volume, almost none of attack's.

### Our Linux collections (attack round vs. benign round)

| | n with UA | distinct | top-1 share |
|---|--:|--:|--:|
| attack (`labeled_lnx.csv`) | 22,284 | **1** | **100.00%** |
| benign (`collection_benign_lnx_alerts.json`) | 209 | **1** | **100.00%** |

Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` — every
single one of 22,284 alerts. Benign: `curl/8.5.0` — every single one of
209 alerts. **Overlap: 0 shared values, 0% by construction.** This is
the cleanest and starkest instance of the hypothesis in the entire check
— exactly quantifying what Fig 3b/Fig 6 already documented qualitatively
("bare `curl/8.5.0` polling 3 fixed endpoints").

## Task 3 — Does the pattern extend beyond User-Agent?

**No — mixed, and in two cases (source IP, URL/path) the opposite
direction.** Tested wherever the field exists:

| population | field | attack distinct | benign distinct | shared | attack top-1 share | benign top-1 share |
|---|---|--:|--:|--:|--:|--:|
| Wazuh-native | srcip | 298 | **4,187** | 252 | 25.06% | 8.92% |
| Wazuh-native | url/path | **432,507** | 31 | 2 | ~0.00% | 57.39% |
| Suricata (86601) | srcip | 285 | 4,150 | 243 | 11.90% | 9.00% |
| AMiner | srcip | 20 | 74 | 14 | 24.37% | 5.96% |
| AMiner | path | **11,469** | 270 | 6 | 0.16% | 9.08% |

- **Source IP is not narrow — it is *more* diverse on the benign side in
  every population tested**, with substantial cross-class overlap
  (252/298 attack IPs also appear benign for Wazuh-native; 243/285 for
  Suricata). This directly contradicts the hypothesis for this field:
  the reason source-IP is a poor discriminator in this project (already
  known — the source-IP degeneracy in *our own* collections, see below)
  is a different phenomenon from AIT-ADS's source-IP diversity, and they
  should not be conflated.
- **URL/path is the opposite of narrow on the attack side** —
  432,507 distinct URLs for Wazuh-native attack alone (dirb/wpscan
  enumerate huge numbers of candidate paths), vastly more diverse than
  benign's 31. AMiner shows the same shape (11,469 vs. 270). **This is
  the clearest anti-hypothesis result in this check**: the tool's target
  breadth is high-diversity even as its self-identification (UA) is
  low-diversity — separability here comes from *volume/breadth of
  targeting*, not from a narrow identifying value, which is a materially
  different mechanism than UA's.

**Our own collections — srcip (previously established, not new):**
Linux attack `srcip` distinct = **1** (`127.0.0.1`, `ew_phase0_inventory.md`,
already on record). This is a genuinely different, and much more
degenerate, situation than AIT-ADS's srcip finding above — our own
testbed's srcip narrowness is an artifact of how the collection was run
(single collector vantage point), not evidence for or against the UADIV
hypothesis about tool-generated traffic; flagged as previously
established per instruction, not re-claimed as new support here.

**Windows process/account fields (`image`, `parent_image`,
`target_user`) — partial overlap, not disjoint:**

| field | attack distinct | benign distinct | shared values |
|---|--:|--:|--:|
| `image` | 6 | 6 | 2 (`cmd.exe`, `dsregcmd.exe`) |
| `parent_image` | 4 | 2 | 2 (`svchost.exe`, `powershell.exe`) |
| `target_user` | 22 | 4 | 2 (`SYSTEM`, `lab-user-1`) |

Windows shows **meaningful, non-trivial overlap** on every process/account
field checked — `cmd.exe` is common to both attack (88 alerts) and
benign (80 alerts) traffic, `SYSTEM` appears as the acting user on both
sides. This is a third, distinct outcome from UA (near-zero overlap) and
from srcip/url (high diversity, direction reversed) — process/account
identity in a Windows admin/attacker context is genuinely **shared
infrastructure** (the same built-in tools and system accounts do
legitimate and malicious things), which is a believable, different
mechanism again.

## Task 4 — Verdict and manuscript impact

### 4a. Verdict: **Partially supported**

The precise boundary, stated per instruction:

- **Holds strongly**: User-Agent, specifically, in every population with
  meaningful UA coverage (Wazuh-native, AMiner, our own Linux collection)
  — near-zero within-class diversity (top-1 share 68-100%, normalized
  entropy as low as 0.04), near-zero cross-class volume overlap on the
  dominant (attack) side in every case.
- **Explains, rather than contradicts, the one detector that failed to
  separate**: Suricata's much lower UA coverage (1.17%) and much higher
  UA overlap (21%/61% of volume in one shared value) than the other
  detectors is independently consistent with, and adds a second
  mechanism to, B1's already-established weak-Suricata-signal finding.
- **Does not hold, and reverses direction, for source IP** (more
  diverse on the benign side, substantial overlap in every AIT-ADS
  population tested) and **for URL/path** (dramatically more diverse on
  the attack side — hundreds of thousands of distinct paths, the
  opposite of the hypothesized pattern).
- **A third, different pattern for Windows process/account fields**:
  meaningful overlap on every field (shared binaries, shared system
  accounts), not near-zero as UA showed, not reversed as srcip/url
  showed — a genuinely distinct mechanism (shared legitimate
  infrastructure), not further evidence for or against the UA-specific
  claim.

**The mechanism that actually holds up is narrower and more precise than
the original hypothesis**: it is not "identifying fields are narrow" in
general — it is specifically that **a scanning/exploitation tool's own
self-announced client-identity string (User-Agent) tends to be constant
across an entire run and disjoint from ambient benign traffic's
client-identity strings, while the same tool's *targeting* behavior
(URLs probed, source addresses used) is often highly varied.** This is a
real, useful, well-evidenced mechanism — just not the single unifying
explanation for all of this project's separability findings that the
hypothesis proposed.

### 4b. Limitation (stated regardless of verdict, per instruction)

**We cannot measure identifying-field diversity in production traffic —
only in these corpora.** Every number in this document describes the
AIT-ADS synthetic testbed and our own small, purpose-built collections
(Linux attack n=22,769, Linux benign n=267, Windows n=336/201). We have
no production SOC alert stream to compare against, and this check does
not attempt to construct one (no new collection, per standing rules).
**The claim available is "these corpora' attack rounds carry a single
(or near-single) User-Agent value, disjoint from these corpora's benign
rounds" — not "real attacker traffic is generally less User-Agent-diverse
than real benign traffic in production."** The latter is a plausible
hypothesis this check cannot test and the manuscript must not imply it
was tested.

### 4c. Manuscript claims affected

- **Fig 3b's Tier A caption ("defeated by one HTTP header")** — **strengthen,
  do not change the substance.** UADIV independently confirms and
  quantifies exactly this: Linux attack-round UA distinct count = 1,
  Linux benign-round UA distinct count = 1, zero overlap, AIT-ADS
  Wazuh-native attack UA entropy 0.043 (near-zero). Recommend adding one
  sentence with these exact numbers to Fig 3b's caption/caveats as
  corroborating evidence, not a new claim.
- **Fig 9's AMiner caveat (WPScan UA fingerprint)** — **strengthen with
  exact figures.** UADIV's AMiner UA table (67.52% of AMiner attack UA
  volume is the WPScan string, 0.17% attack-side overlap with benign)
  gives Fig 9's caveat precise numbers to cite instead of describing the
  finding only qualitatively; consistent with, not contradicting,
  `xdet_aminer_signature_check.md`.
- **Benign-realism threats item — elevate with a hard number.** The
  existing benign-realism caveat (Fig 6: "the Linux benign corpus is
  machine-generated daemon traffic almost end to end") can now state
  plainly: **the entire Linux benign collection round used exactly one
  HTTP client (`curl/8.5.0`) for its entire duration** — this is a
  stronger, more concrete statement of the same limitation and should be
  added to the threats-to-validity list verbatim.
- **Does this become a headline claim or stay a discussion point?**
  **Stays a discussion point / supporting-mechanism explanation**, not a
  headline unifying claim. Task 3's srcip/url reversal and the Windows
  overlap findings mean "identifying-field diversity" cannot be presented
  as one clean mechanism unifying attack-side separability, our benign
  corpus's narrowness, and the rule-identity correlation — it is real and
  useful specifically for User-Agent/tool-identity strings, and should be
  scoped to that when used (best placed alongside Fig 3b and Fig 9's
  caveats, not as a new headline figure).

---
**CHECKPOINT — UADIV complete. Verdict: Partially supported (User-Agent:
yes; source IP and URL/path: no, reversed; Windows process/account
fields: partial overlap, different mechanism). STOP.**
