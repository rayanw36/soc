# Final F1 / FPR — fresh matched-benign collection

All numbers below are computed from data actually scored in this session; every
table has a corresponding row in [`f1_final.csv`](f1_final.csv). Benign (Linux
n=267, agent 003; Windows n=201, WIN-CL1) and attack now come from the **same
testbed session**, removing the provenance mismatch that discarded the earlier
F1. Benign n is still small — these are estimates, not definitive rates.

---

## The three things that matter

### 1. The 31101 "memorization" proof

Rule 31101 (web-scan) is 92% of all discriminative Linux attack alerts (20,665 of
22,556). Layer-1 XGBoost detects it at **99.96% recall** — but that number is a
mirage. `rule_id_encoded` is a raw input feature to L1, so a rule that fires
(almost) exclusively during attacks in training becomes a lookup table entry:
"rule_id==31101 → attack." It is not behavioral generalization.

Proof: force detection through the **anomaly-only path** (defer 31101 to L2,
strip out the rule-identity shortcut). Recall collapses:

| | 31101 recall |
|---|--:|
| RAW L1 (rule identity available) | 99.96% |
| Defer-to-L2, v6 OC-SVM | 1.03% |
| Defer-to-L2, v5 OC-SVM | 2.25% |

**Same collapse regardless of which OC-SVM sits behind the defer** — this is
not an L2-retraining artifact. Real 31101 attack traffic and real 31101 benign
traffic are statistically indistinguishable to an anomaly detector on this
feature set (median OC-SVM score for genuine 31101 attacks is deep in the
"normal" region, e.g. −1.7 to −2.3 vs. θ=−0.335). L1's headline number was
memorizing which rule ID means "attack," not learning what an attack looks
like.

### 2. v6-vs-v5 OC-SVM: revert recommended

The v6 OC-SVM retraining (up-weighting 31151/5710 into the benign baseline) was
meant to cut false positives. On this fresh, matched benign collection it
**bought zero measurable FPR improvement** — v5 and v6 give byte-identical
per-rule FPR on every rule present in the benign set (31101: 4.8% both; 5501:
4.5% both; 550: 50.0% both; etc. — full table in `f1_final.csv`). What it did
buy was a severe, previously undocumented recall collapse on exactly the rules
it up-weighted:

| rule | attacks (n) | v6 recall | v5 recall | FPR cost of reverting |
|---|--:|--:|--:|--:|
| 31151 | 1,585 | 2.27% | **98.49%** | **0.0 pp** (identical) |
| 5710 | 113 | 18.58% | **76.11%** | **0.0 pp** (identical) |
| 31101 | 20,665 | 1.03% | 2.25% | — (see finding #1: neither version can catch it) |

With defer retained and L2 reverted to v5, PRODUCTION NOVEL F1 rises
0.6990 → **0.8702** and PRODUCTION KNOWN F1 rises 0.0220 → **0.1667**, at the
*same* combined FPR (10.86%, known subset) as v6. Benign n for 31151/5710
specifically is 0 in this collection, so the FPR side for those two rules can't
be independently re-verified here — but every rule that *is* present shows no
FPR difference, and the recall recovery is large and consistent across two
independent rules. **Recommendation for the production config: keep defer,
revert L2 to `ocsvm_nu05.pkl` (v5).** These v5-defer numbers are the ones that
should go in the paper as the Linux production result, not the v6 numbers.

### 3. Windows: two different numbers, only one is "cross-platform"

Two Windows pipelines were run and they answer different questions:

- **Un-normalized (Linux-trained 26-feature model, `xgb_model.pkl` /
  `ocsvm_nu05_v6.pkl`, applied directly to Windows alerts):** combined FPR
  **75.1%**, recall 100% (L2-driven). This is **not** a cross-platform result —
  it's a **transfer-failure measurement**. The 26-feature model's
  `agent_criticality` feature never learned a value for "WIN-CL1" (falls to
  0.0, an out-of-vocabulary input), and L1 can't generalize to Windows rule IDs
  it never saw (6.0% recall). L2 "succeeds" only by flagging 75% of *benign*
  Windows traffic as anomalous too — it's treating the whole Windows feature
  distribution as out-of-domain, not doing real detection.

- **Normalized 22-feature model (`xgb_normalized.pkl` / `ocsvm_normalized.pkl`,
  trained exclusively on Linux/AIT-ADS via `v6_to_normalized`, i.e. genuine
  train-Linux/test-Windows transfer) — this is the actual cross-platform
  result, and FPR is computable for the first time now that fresh Windows
  benign exists:**

  | layer | recall | FPR | F1 |
  |---|--:|--:|--:|
  | L1 (XGBoost) | 57.74% | 83.08% | 0.5231 |
  | L2 (OC-SVM) | 100.00% | **100.00%** | 0.7250 |
  | combined | 100.00% | 100.00% | 0.7250 |

  L2 is **fully saturated** on Windows — every alert, benign or attack, scores
  at the model's mathematical ceiling (~160.87, the exact same constant the
  decision function hits for the most extreme AIT-ADS outliers), because
  Windows alerts sit maximally far outside the RBF kernel's Linux-only support
  region. It provides **zero discriminative signal on Windows**, not "high
  recall" — 100%/100% is degenerate, not a detector working well. L1 alone is
  the only non-degenerate cross-platform signal: 57.7% recall at 83.1% FPR —
  real but weak partial transfer, far short of deployable.

  Threshold re-derivation was checked against the saved AIT-ADS validation
  number before use (reproduced F1=0.9686 exactly) to confirm the normalized
  pipeline reconstruction is faithful.

---

## Full tables

### PHASE A — Linux (RAW vs PRODUCTION-v6 vs PRODUCTION-v5defer)

θ_xgb=0.07538, θ_ocsvm=−0.33500. Confound-fix defers 31101/31151/5710/5501 to
L2 on lnx-dmz (agent_criticality==1.0) in both PRODUCTION variants.

| pipeline | subset | layer | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |
|---|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| RAW | known | combined | 22244 | 232 | 35 | 6 | 98.97% | 99.97% | 0.9947 | 86.89% | 0.03% |
| RAW | novel | combined | 272 | 232 | 35 | 34 | 53.97% | 88.89% | 0.6716 | 86.89% | 11.11% |
| RAW | blended* | combined | 22516 | 232 | 35 | 40 | 98.98% | 99.82% | 0.9940 | 86.89% | 0.18% |
| PRODUCTION (v6) | known | combined | 248 | 29 | 238 | 22002 | 89.53% | 1.11% | 0.0220 | 10.86% | 98.89% |
| PRODUCTION (v6) | novel | combined | 180 | 29 | 238 | 126 | 86.12% | 58.82% | 0.6990 | 10.86% | 41.18% |
| PRODUCTION (v6) | blended* | combined | 428 | 29 | 238 | 22128 | 93.65% | 1.90% | 0.0372 | 10.86% | 98.10% |
| **PRODUCTION (v5-defer, recommended)** | known | combined | 2026 | 29 | 238 | 20224 | 98.59% | 9.11% | 0.1667 | 10.86% | 90.89% |
| **PRODUCTION (v5-defer, recommended)** | novel | combined | 258 | 29 | 238 | 48 | 89.90% | 84.31% | **0.8702** | 10.86% | 15.69% |
| **PRODUCTION (v5-defer, recommended)** | blended* | combined | 2284 | 29 | 238 | 20272 | 98.75% | 10.13% | 0.1837 | 10.86% | 89.87% |

*blended is base-rate-inflated by 31101 volume (92% of attacks) — never cite
alone; the KNOWN/NOVEL split above it is the honest read. Full per-layer
(L1/L2) breakdown for every row is in `f1_final.csv`.

### PHASE B — Windows

No KNOWN-rule subset exists for Windows: `ait_ads_seen_rules.txt` (the AIT-ADS
training vocabulary) is Linux-only — no 60xxx/92xxx rule was ever in training.
NOVEL == blended for both Windows pipelines (265 discriminative attack alerts,
same set scored through both pipelines).

| pipeline | layer | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| un-normalized (transfer-failure measure) | L1 | 16 | 57 | 144 | 249 | 21.92% | 6.04% | 0.0947 | 28.36% | 93.96% |
| un-normalized (transfer-failure measure) | L2 | 265 | 151 | 50 | 0 | 63.70% | 100.00% | 0.7783 | 75.12% | 0.00% |
| un-normalized (transfer-failure measure) | combined | 265 | 151 | 50 | 0 | 63.70% | 100.00% | 0.7783 | **75.12%** | 0.00% |
| **normalized (real cross-platform)** | L1 | 153 | 167 | 34 | 112 | 47.81% | 57.74% | **0.5231** | 83.08% | 42.26% |
| **normalized (real cross-platform)** | L2 | 265 | 201 | 0 | 0 | 56.87% | 100.00% | 0.7250 | **100.00%** (saturated, not real detection) | 0.00% |
| **normalized (real cross-platform)** | combined | 265 | 201 | 0 | 0 | 56.87% | 100.00% | 0.7250 | 100.00% | 0.00% |

Un-normalized RAW == PRODUCTION exactly on Windows (verified by assertion in
the scoring script) — the confound-fix never fires there (no Windows rule id
is in `rule_confound_fixes_v5.json`, and `agent_criticality` for "WIN-CL1"
never equals 1.0 in the 26-feature extractor).

---

## Bottom line for the write-up

- **Linux production number to cite:** v5-defer config — NOVEL F1 = 0.8702 @
  10.86% FPR (n=267 benign). KNOWN F1 is low (0.1667) because 31101 cannot be
  caught by anomaly detection regardless of OC-SVM version (finding #1) — this
  is a real, inherent limitation of the defer approach for that specific rule,
  not a modeling bug.
- **Recommended config change:** revert L2 to v5 (`ocsvm_nu05.pkl`), keep the
  defer mechanism as-is.
- **Windows:** cite the **normalized** model as the cross-platform result
  (L1 F1=0.5231 is the only non-degenerate number; L2/combined are saturated
  and not meaningful). Cite the **un-normalized** 75% FPR only as evidence that
  the Linux-trained 26-feature model does not transfer to Windows without
  retraining — not as a deployable Windows FPR.
- All FPRs here rest on small benign samples (267 Linux, 201 Windows, single
  session each) — report as estimates with sample size stated, not definitive
  production rates.
