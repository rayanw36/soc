# XDET-V Task 2 — Labelled figures for the 86601 identity-collapse result

This result is being promoted into the main memorization results as the
project's only **causal** evidence for memorization (same alerts, same
labels, identity destroyed vs. preserved, performance measured on the
same eval split). Because it is now load-bearing, every number below is
labelled with its exact source, configuration, and denominator — no
number is to be copied out of this document without its label.

Source: `newCol/xdet_task1_lookup.py` output, `newCol/xdet_task1_results.json`
(`deployed_model_by_subset` key). Underlying split: the *exact* recovered
`models_v2/ait_split.npz` train/test partition
(`newCol/xdet_recover_wazuh_split.py`, verified byte-identical to the
deployed split before use — see Task 0/Addition A).

## a. The two numbers, fully labelled

There are **two distinct measurements** in play — a lookup table and a
model — each run on **two distinct populations**. Do not conflate the
lookup-table pair with the model pair; they are different experiments
using the same population split.

### Measurement 1: majority-label-per-signature lookup table

| population | n (eval) | TP | FP | TN | FN | **Recall** | **FPR** | Precision | F1 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Wazuh-native (rule.id != 86601, 30 signatures) | 458,517 | 339,634 | 59 | 116,143 | 2,681 | **0.9922** | **0.0005** | 0.9998 | 0.9960 |
| Suricata-via-Wazuh (rule.id == 86601, keyed on true `rule.description`, 29 signatures) | 61,536 | 33 | 0 | 60,346 | 1,157 | **0.0277** | **0.0000** | 1.0000 | 0.0540 |

- **Configuration**: pure lookup table (majority label per signature key,
  built on the training portion of the recovered split, scored on the
  eval portion). No model, no threshold — the "decision" is the majority
  vote itself.
- **Signature key**: `rule.id` (Wazuh-native) or the true, uncollapsed
  `rule.description` (Suricata-via-Wazuh) — i.e., this row uses identity
  that IS available at the raw-alert level, before the deployed
  pipeline's encoding collapses it.

### Measurement 2: full-feature model (audit-time retrain)

| population | n (eval) | TP | FP | TN | FN | **Recall** | **FPR** | Precision | F1 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Wazuh-native (rule.id != 86601) | 458,517 | 339,718 | 5 | 116,197 | 2,597 | **0.9924** | **0.00004** | 1.0000 | 0.9962 |
| Suricata-via-Wazuh (rule.id == 86601) | 61,536 | 51 | 1 | 60,345 | 1,139 | **0.0429** | **0.00002** | 0.9808 | 0.0821 |

- **Configuration**: `XGBClassifier(n_estimators=50, max_depth=5,
  subsample=0.5, learning_rate=0.1, eval_metric="logloss",
  random_state=42, n_jobs=-1)` — the **exact hyperparameters and feature
  set of `exp4_ablation.py`'s "full" (26-feature) variant** — fit on
  `X_train`/`y_train` from `ait_split.npz` (the deployed 26-feature
  vectors, in which `rule_id_encoded=86601.0` for every Suricata-via-Wazuh
  row — identity **is** collapsed here, unlike Measurement 1's Suricata
  row). Scored on `X_test`/`y_test` from the same file, decision
  threshold = **0.37981**, chosen by maximizing F1 directly on this eval
  split (`find_best_theta`, same method as `exp4_ablation.py`).
- **This is an audit-time retrain, not the deployed model**
  (`models_v2/xgb_model.pkl`). Confirmed directly, stated per instruction
  (d) — see below.
- **Threshold source**: audit-only, eval-split-calibrated (0.37981).
  **Not** `theta_xgb=0.07538` from `models_v2/thresholds_production_v3.json`
  — that pickle produces degenerate scores in this environment (predicted
  probabilities capped at 0.059, entirely below its own deployed
  threshold) and could not be used at all, for either population.

## b. The 29→1 collapse count, and how it was established

- **29** confirmed three independent ways, not assumed:
  1. Direct count of distinct `rule.description` values among raw
     `*_wazuh.json` records where `rule.id=="86601"` (`jq` over all 8
     scenario files) → 29.
  2. Cross-checked against `data/ait_ads/AIT_alerts/AIT_alerts.csv` (a
     separately-held, independently-built artifact) — its `Suricata`-prefixed
     rows have 29 distinct `name` values, exact same count.
  3. Cross-checked against `landauer_introducing_2024` Table 1
     (independently retrieved and read in full) — 29 documented Suricata
     detector signatures, and this audit's B2 check found **zero**
     discrepancy: our reconstructed set of 29 description texts matches
     the paper's documented list exactly, signature-for-signature, with
     an exact total-volume match (306,635 = 306,635).
- **1**: `shared_features.py:_rule_id_encoded` = `float(rule.id)`. Since
  `rule.id` is the same string (`"86601"`) for all 29 underlying
  signatures, every one of the 306,635 alerts encodes to the identical
  feature value `86601.0` in the deployed 26-feature vector. This is a
  direct read of the feature-extraction source code, not inferred.

## c. FPR alongside each recall

Included in both tables above — **fully measurable in both
configurations**, no caveat needed. FPR is near-zero on both sides of
both measurements (0.00-0.05%), so the recall contrast is not a
precision/recall trade-off artifact — the models/lookup tables essentially
never fire false positives on either population; they differ almost
entirely in how often they fire true positives.

## d. Is this an audit-time retrain result? State plainly.

**Yes, for Measurement 2 (the model comparison) — this must be flagged
at the point of use, not in an appendix, per instruction.** The deployed
`models_v2/xgb_model.pkl` was tested directly and found non-functional in
this environment (`predict_proba` on `ait_split.npz`'s `X_test` produces
scores topping out at 0.059, entirely below the deployed threshold
0.0754 — every prediction is negative, TP=0 on any subset). This is not
a new finding of this task — it was already diagnosed by prior work
(`newCol/figures_ms/fig1_lookup_vs_model.py`'s docstring; `exp4_ablation.py`'s
own docstring) and independently re-confirmed here.

**Measurement 1 (the lookup table) is not a retrain of anything** — it
is a majority vote, no model involved, and does not carry this caveat.

**Recommended manuscript phrasing, to use verbatim or adapt:** *"Recall
falls from 99.2% (lookup table) / 99.2% (an audit-time 26-feature model
retrain, since the deployed model checkpoint is non-functional in the
current environment) on Wazuh-native alerts, to 2.8% (lookup table) /
4.3% (same audit-time retrain) on the population whose true 29-signature
identity is collapsed to a single value by the deployed feature
encoding."*

## e. Caveats that weaken the "clean ablation" framing

**This is not a controlled within-subject ablation, and should not be
described as one without this caveat attached.** A clean ablation would
take the *same* alerts and compare "with identity" vs. "without
identity." What we actually have is a **between-population comparison**:
Wazuh-native alerts (30 native signatures) vs. Suricata-via-Wazuh alerts
(29 different signatures, from a different detector, with a different
underlying content distribution) — and *only the second population*
happens to have had its identity collapsed by the encoding. Two things
differ between the "before" and "after" groups, not one:

1. **Identity availability** (the variable of interest): Wazuh-native
   rows carry a distinguishing `rule_id_encoded` value per signature;
   Suricata-via-Wazuh rows all carry the same value.
2. **Population content** (a confound): B1 (this audit's pre-verdict
   check) established the Suricata-via-Wazuh population is intrinsically
   different — 24 of its 29 signatures are majority-benign by ~43:1,
   carrying 99.9% of that population's volume, i.e., this population is
   dominated by low-signal protocol/background-noise alert types
   (TLS handshake oddities, generic DNS queries) that are not
   attack-correlated even before considering identity collapse at all.
   Wazuh-native, by contrast, is anchored by rule 31101 (6,137:1 ratio,
   68.5% of its volume) — an intrinsically much more attack-skewed
   population, independent of whether identity is encoded.

**Consequence**: the 99.2%→4.3% contrast cannot be attributed to
identity collapse alone with full confidence. Some — possibly most — of
the gap may be explained by the Suricata-via-Wazuh population being
inherently harder (weak signal even with full identity, as Measurement 1
already shows: the lookup table, which retains true identity, still only
reaches 2.8% recall on this population) rather than by identity removal
specifically. **What the identity-preserved lookup table (Measurement 1)
does establish cleanly**: recovering true signature identity for the
Suricata-via-Wazuh population raises recall only from 4.3% (model,
identity collapsed) to 2.8% (lookup table, identity preserved) — i.e.,
restoring identity does **not** recover the Wazuh-native-level
performance, which is the strongest evidence that population content
(not identity collapse) is the dominant factor. **This significantly
qualifies the "accidental ablation" framing used in Addition A**: identity
collapse is real and measurable, but it is not shown to be the primary
cause of the recall gap — the population itself is the more likely
primary cause, per B1.

**Recommended correction to the manuscript claim**: do not present the
99.2%→4.3% contrast as clean causal proof that "identity collapse causes
detection failure." Present it as: (i) identity is in fact collapsed for
this population in the deployed pipeline (verified, Task 0/b above);
(ii) recall is in fact far lower on this population (verified, both
measurements); but (iii) recovering identity via a lookup table does not
close the gap (2.8% vs. 99.2%), which points to the population's own weak
signal (B1) as the larger factor, with identity collapse as a compounding
but secondary defect on top of it.

---
**This document supersedes/qualifies Addition A's "causal, not
correlational" framing in `newCol/xdet_results.md`** — see the
correction appended there.
