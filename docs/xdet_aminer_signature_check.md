# XDET-V Task 1 — AMiner's dominant signature: memorization or genuine detection?

Script: `newCol/xdet_aminer_signature_check.py`. Data:
`newCol/xdet_aminer_dominant_sig_records.csv` (27,342 rows, one per
alert). No model trained; distributions reported directly given the
small benign n. Same labelling discipline as the rest of this audit
(`labels.csv` time-window / `merge_asof`).

**Bottom line, stated up front:** the signature **is** distinguishable
on non-identity features — this is not "unmeasurable" and not a
per-alert-indistinguishable labelling artefact in the strict sense rule
31101 was shown to be. But the entire separation is carried by **one
exact, single User-Agent string** (a penetration-testing tool
self-announcing its own name), which is structurally the same
phenomenon this project already established for Wazuh rule 31101's
**Tier A** result and explicitly did **not** credit as "detection":
*"the same disease as rule-ID memorization at finer grain, not
detection... trivially evadable by setting one HTTP header"*
(`newCol/fr_31101_report.md`). **Verdict: genuine detector (technically
distinguishable), but the XDET Fig 9 / Task 4 claim must be narrowed as
instructed — not "memorization replicates on an anomaly-based
detector," and not "AMiner performs genuine, robust security
detection" either.**

---

## a. Signature identification

- Field: `AnalysisComponent.AnalysisComponentName ==
  "AMiner: New request method in Apache Access log."` (AMiner detector
  type `NewMatchPathValueDetector`, watching
  `/model/fm/request/method`).
- Total alert count: **27,342** across all 8 scenarios.
- Attack count: **27,269**. Benign count: **73**.
- Exact ratio: **373.55:1** — confirms the "373:1" figure carried
  forward from B3 was correct, recomputed independently here from raw
  files rather than assumed.

## b. Benign denominator

**Benign n = 73.** Small, but not so small that no test is possible —
reported as distributions, per instruction, not classifier metrics (no
model fit). Section e below shows this n=73 is itself further
concentrated in AMiner's own documented training-phase noise, which
matters for how to read it.

## c. Non-identity fields available for AMiner alerts

AIT-ADS has no common schema across detectors (Task 0), so the
26-feature Wazuh pipeline's fields (rule level, MITRE tactic, agent
criticality, etc.) do not exist here. What AMiner alerts of this type
actually carry:

- **From `LogData.RawLogData`**: the full embedded Apache combined-log
  line — client IP, timestamp, HTTP method, path, protocol, status
  code, response size, referrer, **user-agent**. All 27,342 lines parsed
  cleanly with a standard combined-log-format regex (0 parse failures).
- **From the AMiner envelope**: `DetectionTimestamp`, a `TrainingMode`
  boolean, `AMiner.ID` (monitored host), `LogResources` (source log
  file path).
- **Not available**: anything resembling Wazuh's rule metadata,
  severity, or MITRE mapping.

The Apache log line's fields (method, path, status, size, user-agent)
are the usable non-identity features — directly analogous to what
`fr_31101_report.md`'s Tier A/B study used for rule 31101.

## d. Distinguishability (attack n=27,269, benign n=73)

| feature | attack | benign |
|---|---|---|
| HTTP method | **100% `HEAD`** (27,269/27,269) | `MKCOL`=17, `GET`=8, `POST`=8, `OPTIONS`=8, `PROPFIND`=8, ... (0 `HEAD`) |
| status code | mean 403.4, median 404 | mean 213.3, median 201 |
| response size | mean 188.5, median 146 | mean 2,029.8, median 870 |
| user-agent length | mean 62.0 (constant) | mean 91.6, median 76 |
| distinct user-agents | **1** | 8 |
| user-agents shared between classes | **0** | — |
| distinct paths | 8,202 | 48 |

**The attack side is not merely method-skewed — it is a single,
literal tool fingerprint.** All 27,269 attack-labelled alerts of this
signature carry the exact same User-Agent string:

```
WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)
```

Sample raw lines (attack-labelled):
```
HEAD / HTTP/1.1" 200 223 ... "WPScan v3.8.20 (...)"
HEAD /robots.txt HTTP/1.1" 404 146 ... "WPScan v3.8.20 (...)"
HEAD /fantastico_fileslist.txt HTTP/1.1" 404 146 ... "WPScan v3.8.20 (...)"
```

WPScan (a real, publicly-available WordPress vulnerability scanner) is
**identifying itself by name in its own default User-Agent header**,
and issuing `HEAD` requests against thousands of candidate plugin/theme
paths (hence 8,202 distinct paths, mostly 404s). The classes are
perfectly separable — but by the exact same mechanism `fr_31101_report.md`
already found for Wazuh's rule 31101 Tier A: one exact string, zero
generalization, trivially evaded by changing a single header
(`User-Agent: Mozilla/5.0 ...` would defeat this signature exactly as
completely as it defeats 31101 Tier A).

## e. Training-phase check

`landauer_introducing_2024` documents that AMiner reports many false
positives in the first half of the first day of each scenario, from
still-incomplete training. Checked directly against this signature's
73 benign alerts:

- **60 / 73 (82.2%)** fall in the first 12 hours of their scenario.
- **63 / 73 (86.3%)** have AMiner's own `TrainingMode=True` flag set
  directly in the alert record (a stronger, detector-native signal than
  our external 12h window — and confirms 0 of the 27,269 *attack*
  alerts carry `TrainingMode=True`, consistent with attacks starting
  well after training completes in every scenario).
- **Excluding the training-phase window, benign n drops to 13**, and
  those 13 are **100% `MKCOL`** requests (WebDAV resource-creation,
  status 201) — a third, narrower and *different* legitimate-traffic
  population (cloud-share WebDAV admin activity), still with zero
  User-Agent overlap against WPScan.

**This matters beyond just confirming the documented caveat**: it means
the already-small n=73 benign comparison population is itself mostly
AMiner's own startup noise, not steady-state benign HTTP traffic. The
"real" non-training-phase benign comparison is n=13, entirely one
narrow WebDAV traffic pattern — not a representative sample of what
"normal" web traffic looks like against this signature at all. Reported
both ways per instruction; neither changes the qualitative separability
finding (User-Agent has zero overlap either way), but it weakens how
much should be read into "benign traffic never triggers this."

## f. Verdict

**Genuine detector, technically — the classes are clearly distinguishable
on non-identity features (User-Agent, method, status, size all
separate cleanly).** This is **not** "unmeasurable" (features exist and
are informative) and **not** the strict per-alert-indistinguishable
"labelling artefact" outcome established for rule 31101 as a whole.

**But per the task's own instruction to narrow rather than inflate:**
the mechanism is a single, exact tool-identity string — the same kind
of narrow, evadable separability this project already found for 31101's
Tier A and explicitly declined to call "detection." **The XDET
manuscript claim must be narrowed accordingly**: not *"memorization
replicates on an anomaly-based detector"* (this signature does carry
real, if narrow and fragile, discriminative signal — it is not a pure
labelling proxy) — instead: ***"signature identity is near-perfectly
predictive in AMiner's alert stream too, but where checked directly,
that separability traces to the same class of narrow, single-string,
trivially-evadable identity match already documented for Wazuh's rule
31101, not to demonstrated generalizable behavioral detection."*** The
paper should not cite this signature as evidence AMiner "detects
WPScan" in any robust sense — it detects WPScan's default banner, which
any attacker changes with one flag.

**Consequence for Fig 9 / Task 4's verdict**, addressed in the
follow-up corrections to `xdet_results.md` and Fig 9's caption/sources
(see below): AMiner's headline 99.4% lookup-table recall (Task 1) and
this dominant signature's 373:1 ratio (B3) can no longer be cited as
open/unverified support for "memorization replicates on an anomaly-based
detector" — it is now a **verified instance of the narrower,
fingerprint-matching phenomenon**, parallel to but not identical to
31101's case (31101 was shown per-alert *indistinguishable* even with
full information; this AMiner signature *is* distinguishable, just not
by anything that generalizes).
