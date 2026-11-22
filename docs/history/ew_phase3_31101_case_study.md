# Phase 3 — The 31101 case study

Same alerts, same labels, same model class as the frozen pipeline — only the
unit of context changes. Script: `newCol/ew_phase3_31101_case_study.py`.
Figure: `newCol/ew_fig_31101_before_after.png` (producing notebook:
`newCol/ew_phase3_figure.ipynb`). Data: `ew_phase3_31101_per_alert_combined.csv`,
`ew_phase3_31101_per_alert_inherited.csv`.

## 3a. Per-alert baseline (reproduced, not recomputed ad hoc)

Reproduced via the exact frozen methodology in `newCol/f1_phaseA_diag_l2.py`
(v5 OC-SVM, `theta_ocsvm=-0.33500`, `models_v2/ocsvm_nu05.pkl`,
scaler/imputer from `combined_decision_v6.load_production_models()`):

| | n | median score | outcome |
|---|--:|--:|---|
| attack-31101 | 20,665 | −2.2929 | recall = 2.25% |
| benign-31101 | 209 | −2.1589 | FPR = 4.78% |

Attack IQR `[-2.293, -2.157]`, benign IQR `[-2.225, -2.032]` — heavily
overlapping, and the benign FPR (4.78%) is actually *higher* than the attack
recall (2.25%): per-alert, this feature set is not merely undecidable, it's
worse than a coin flip in the direction that matters. Matches the frozen
finding exactly (median in the −1.7 to −2.3 range vs θ=−0.335, cited in
`f1_final_summary.md`).

## 3b. Entity-window separation, same alerts

| feature (GLOBAL, trail60m) | attack median | benign median | ratio |
|---|--:|--:|--:|
| `alert_count` | 11,006 | 134 | 82× |
| `distinct_url_count` | 4,557 | 3 | 1,519× |
| `mean_interarrival_s` | 0.089s | 16.018s | 180× |
| `path_repetition_ratio` | 0.570 | 0.971 | (inverted — see Phase 2 note below) |

See `ew_fig_31101_before_after.png` for the paired figure: per-alert score
histograms (left, complete overlap) against entity-window `alert_count` at
the 10-minute grid level (right, log scale, 3–4 orders of magnitude apart,
zero overlap across all 10 windows that contain any 31101 activity).

**This is the same finding Phase 2's testbed-artifact check (2e) already
flagged for Linux.** The separation shown here is real and reproducible, but
Phase 2 established that the Linux benign collection never reaches anywhere
close to the attack round's peak alert rate (0.1% of peak) — so this figure
should be read as "entity-window features make a per-alert-undecidable
signal visible," not as "this specific magnitude of separation would hold in
a busier benign environment." Both things are true at once and both are
stated here, not just one of them.

## 3c. Minimal classifier — two runs, both reported

Only 10 grid-windows contain any 31101 activity at all (3 attack, 7 benign —
see Phase 2 addendum's 31101-window count). Provisional temporal-disjoint
split (train=earlier windows per collection, test=later; **not** the frozen
Phase 4a/5a split, which hasn't run yet): train n=7 (2 attack, 5 benign),
test n=3 (1 attack, 2 benign).

**Run A — XGBoost with default hyperparameters:** produced a degenerate
constant-output model. Feature importance was exactly zero for all 22
features; every test prediction equaled the training base rate (2/7 =
0.2857) regardless of input. The held-out attack window was misclassified
as benign. Per-alert-inherited accuracy: **1.00%** overall (0/20,665 attack
alerts inherited an attack verdict; 209/209 benign alerts correctly
inherited benign).

**Run B — diagnostic, `reg_lambda=0`/`min_child_weight=0`, otherwise
identical:** recovered perfect separation, driven almost entirely by one
feature (`ew_alert_count`, importance=1.000). Per-alert-inherited accuracy:
**100.00%**.

**What this means, reported plainly rather than picking the flattering run:**
Run A's failure traces to a specific, verifiable mechanism — L2
regularization (`reg_lambda=1`, XGBoost's default) dominates the split-gain
calculation when per-leaf Hessian sums are this small (n=7 training rows),
so the model found no split "worth" the regularization penalty anywhere,
despite an 82–1,519× raw separation in the underlying values. Run B confirms
this was a classifier-configuration artifact of tiny n, not a feature
failure. **But Run A is not a null result to explain away**: an entirely
ordinary, unremarkable hyperparameter choice (defaults) was sufficient to
produce total failure at this sample size. Anyone reproducing "the 31101
result" with an off-the-shelf XGBoost call and no awareness of this will get
Run A's number, not Run B's. Both are reported here at equal prominence.

## 3d. Honest caveat

With 3 attack-side windows total (all from the same 30-minute dense scan
burst on 2026-07-08, one attacker source, one host) and only one held out
for testing, this demonstrates **mechanism** — entity-window aggregation
makes a real rate/path signal visible where per-alert features cannot see
one at all — and nothing about **deployment-grade generalization**. There
are not enough distinct attacker entities, attack sessions, or benign
capture rounds in this testbed to show the signal survives across
attackers, across time, or across a benign environment with genuinely
comparable traffic volume (Phase 2's finding that Linux benign never
approaches attack-round density). This is the same downgrade pre-registered
in Phase 1/2 before this case study ran — restated here because it was
confirmed, not merely repeated by rote.

## 3e. Further caveat, requested as a side task ahead of manuscript writing: both sides of the per-alert 31101 undecidability comparison are tool-generated HTTP traffic, not attack-vs-organic

Checked directly against `newCol/collection_lnx_alerts.json` (attack) and
`newCol/collection_benign_lnx_alerts.json` (benign) — no script or runbook
in this repository documents how the benign session's rule-31101 traffic
was produced (there is no `collect_lnx.sh` or equivalent in this repo, per
`newCol/benign_fim_collection_runbook.md`'s own note; the benign session's
marker file, `newCol/benign_markers_lnx.txt`, records only `CYCLE N`
timestamps, no command detail). The finding below is read directly off the
alert data's own `full_log`/`data` fields, not inferred from an
unavailable script:

| | attack-side 31101 (n=20,665) | benign-side 31101 (n=209) |
|---|---|---|
| User-Agent | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` — dirb's own default masquerade string, 100% of alerts | `curl/8.5.0`, 100% of alerts, explicit (no masquerade) |
| requested paths | wordlist-style, high cardinality (`/randomfile1`, `/frand2`, `/.bash_history`, `/.bashrc`, `/.config`, ...) | 3 distinct paths only, repeated: `/api/status` (77), `/contact` (66), `/about` (66) |
| pattern | one dense scan burst (T1595.003/dirb) | fixed 3-endpoint rotation recurring roughly once per `CYCLE` across the ~60-minute benign session |

**Both sides are confirmed tool-generated, neither is a human browsing a
real site — this is a genuine caveat and is added, not dismissed.** But
the two tools are not the same tool doing the same thing: the attack side
is a wordlist-based content-discovery scan (`dirb`, disguising itself as
an old MSIE client, guessing hundreds of distinct nonexistent paths at
high rate) and the benign side is a small, fixed health-check-style probe
loop (bare `curl`, no masquerade, cycling through 3 endpoints that look
like a real minimal API/site surface, at a pace of roughly one request per
few minutes per endpoint). The undecidability finding (2.25% recall vs.
4.78–4.8% benign FPR on this rule) should therefore be read as: **the
model cannot separate a wordlist-scanning tool from a low-rate
fixed-endpoint polling tool on this feature set** — not as "the model
cannot separate an attacker from a human," which this data was never in a
position to test on either side of this specific rule. This does not
change the 2.25%/4.78% figures or the conclusion that this rule sits at or
below chance for anomaly detection; it sharpens what "chance" is being
computed over.

## 3f. FR-31101 closes the question 3e opened: discarded URL/UA fields do not recover generalizable per-alert separability

Full report: `newCol/fr_31101_report.md`; features:
`newCol/fr_31101_features.csv`; script: `newCol/fr_31101_feature_recovery.py`.

3e established that the 26-feature representation discards URL path and
User-Agent, and that both rule-31101 populations are tool-generated. That
raised a live question: was the discarded URL/UA data actually carrying
discriminating information, making the 2.25%/4.78% undecidability result
an artifact of feature engineering rather than a genuine information-
theoretic finding? Tested directly, with URL/UA rebuilt into two
strictly disjoint feature tiers (identity/memorization vs. structural)
and evaluated separately, temporal split, round-6-held-out:

- **Tier A (exact UA/path identity):** recall=100.00%, FPR=0.00% —
  perfect separation, **carried 100% by one field** (`A_ua_id`; every
  other Tier A feature scored zero importance). This is identity-class
  memorization at finer grain than rule ID, not a behavioral finding, and
  is trivially defeated by an attacker setting `User-Agent: curl/8.5.0`.
- **Tier B (path depth/length/entropy/extension-class/dotfile/query/status/method
  — properties that do not require memorizing a specific path or tool):**
  recall=100.00%, FPR=**66.67%** — far short of separation (the trivial
  "flag everything as attack" baseline already scores FPR=100%/F1=0.9940
  on this same test set; Tier B's F1=0.9960 is barely above it). The
  nominal top-ranked feature (`B_path_length` or `B_path_depth`,
  depending on regularization — the two disagree on ranking but produce
  identical predictions) does **not** survive a causal swap-to-benign-typical
  test: recall stays 100.00% either way. The one real mechanism found —
  `path_depth` correctly flagging the single nested benign endpoint
  (`/api/status`) while completely failing on the two flat ones
  (`/about`, `/contact`, 100% misclassified) — is a coincidence of this
  collection's 3-endpoint benign design, not a validated general
  signature, and is explicitly untested/untestable beyond this data
  (Task 4d).

**Verdict: Task 3c's scenario, not Task 3b's.** The discriminating
information present in the raw alert is identity-class only. §3e's
undecidability finding, and the 2.25%/4.78% per-alert figures, are
**restored in properly-scoped form** — not weakened by this check, and
not an artifact of the 26-feature representation discarding a recoverable
behavioral signal. This also bears on P1 (rule-ID memorization): if
behavior had been engineered away and were latent in URL/UA, Tier B
should have recovered it and did not — the same identity-only shape of
result recurs at a completely different representation level (raw UA
string vs. rule ID), which strengthens rather than reinterprets the
original memorization finding.
