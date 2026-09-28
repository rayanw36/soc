# REV-C Task 4 — Model configuration

All values below are read directly from artifacts and training scripts on
disk (`phase1_xgboost.py`, `anomaly_model_comparison.py`,
`finalize_ocsvm_threshold.py`, `shared_constants.py`, `shared_features.py`,
`results_v2/phase1_run.log`, `models_v2/thresholds_*.json`), or produced
by this task's own reruns — nothing here is a remembered/assumed default.

## a. XGBoost (L1)

Two distinct configurations exist and are both reported, labeled, because
they are used for different purposes in this response:

| hyperparameter | **Deployed** (`models_v2/xgb_model.pkl`, `phase1_xgboost.py` §4) | **Audit-time retrain** (used in Tasks 1 & 3, `results/rule_memorization_audit/exp4_ablation.py` "full" variant methodology) |
|---|---|---|
| n_estimators | 500 | 50 |
| max_depth | 6 | 5 |
| learning_rate | 0.05 | 0.1 |
| subsample | 0.8 | 0.5 |
| colsample_bytree | 0.8 | 1.0 (default, not set) |
| min_child_weight | 5 | 1 (default, not set) |
| gamma | 1 | 0 (default, not set) |
| reg_alpha | 0.1 | 0 (default, not set) |
| reg_lambda | 1.0 | 1.0 (default) |
| scale_pos_weight | 0.5140 (= 706,191 benign-train / 1,374,019 attack-train, computed at train time) | not set (1.0 / unweighted) |
| objective | `binary:logistic` (XGBClassifier default; not overridden) | `binary:logistic` (default) |
| eval_metric | `auc` | `logloss` |
| early_stopping_rounds | 30 (best_iteration = 219, from `results_v2/phase1_run.log`) | none |
| random_state | 42 | 42 (Tasks 1a/1c); swept 0–9 in Task 3's multiseed reruns |
| tree_method | `hist` | default (`hist` in xgboost 3.2.0) |
| n_jobs | -1 | -1 |

**Decision threshold, deployed:** `theta_xgb = 0.07537688442211056`
(`models_v2/thresholds_production_v3.json`). **Selection procedure**
(traced to `finalize_ocsvm_threshold.py:83`, which reads it from
`models_v2/thresholds_v2.json`'s `theta_global`, itself produced by
`phase1_xgboost.py` §5): a grid search over 200 thresholds in `[0,1]`
minimizing `cost = 1·FP + FN_FP_COST_RATIO·FN` with
`FN_FP_COST_RATIO = 10` (`shared_constants.py`) on the AIT-ADS held-out
test split — i.e. a **cost-sensitive**, recall-favoring threshold, not a
max-F1 threshold.

**Decision threshold, audit-time retrain:** calibrated per-run by a
300-point max-F1 grid search directly on the eval/test split the F1 is
then reported on (same procedure `exp4_ablation.py`/`exp3_lookup_table.py`
use). This is a real, disclosed limitation shared by every "model F1"
number in this response: the audit threshold is chosen on the same data
it is scored on, which is mildly optimistic. It was not corrected because
(a) it is symmetric between the model and nothing analogous exists for
the lookup table (which has no threshold to tune — it is a majority vote),
so the model-vs-lookup **gap** comparison is not biased by it, and (b) at
F1 ≈ 0.99 with a 300-point grid, the achievable optimistic bias is small
relative to the ~0.0003–0.0005 gaps being measured, but it is not zero and
should not be presented as a held-out-calibrated number.

## b. One-Class SVM (L2)

**Deployed:** `models_v2/ocsvm_nu05.pkl`. `sklearn.svm.OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)` (`anomaly_model_comparison.py:87`). `sklearn.svm.OneClassSVM` has **no `random_state` parameter** — its libsvm QP solve is deterministic given fixed data and hyperparameters, confirmed by inspecting the sklearn 1.9.0 API (not assumed). This is why Task 3 does **not** multiseed the OC-SVM: refitting it on identical data produces a byte-identical model every time; there is no seed to vary.

**Feature scaling:** `models_v2/scaler_v2.pkl` (`StandardScaler`) +
`models_v2/imputer_v2.pkl` (`SimpleImputer(strategy="median")`) — the
*same* scaler/imputer object L1 uses, loaded and reused, not refit
(`anomaly_model_comparison.py:52-53`).

**Training data — important and easy to get wrong:** unlike L1, the
deployed OC-SVM is **not** trained on AIT-ADS. `anomaly_model_comparison.py`
explicitly notes OC-SVM is O(n²) and cannot scale to AIT-ADS's 706k-row
benign training set; it trains instead on 80% of
`results_v2/benign_baseline_clean.csv` — an in-domain, separately
collected, cleaned live lnx-dmz benign baseline — with the other 20% held
out for its own FPR evaluation (`RandomState(SEED)` permutation split).

**Threshold:** `theta_ocsvm = -0.3349956708403319`
(`models_v2/thresholds_production_v3.json`). **Selection procedure**
(`finalize_ocsvm_threshold.py` §1, sourcing `results_v2/anomaly_model_comparison.csv`): among `nu ∈ {0.05, 0.10, 0.15}`, each thresholded by a
max-F1 grid search over unique scores on (held-out benign, 43-alert novel-attack) — `anomaly_model_comparison.py`'s `best_f1()` — `nu=0.05` was
selected for having the best F1 (0.608) and the most *stable* recall
across both the 5%-FPR and 10%-FPR budgets (72.1% at both), not simply
the highest single-point recall (nu=0.10/0.15 score higher recall at one
budget but are documented as less stable). The locked threshold was then
**independently re-verified** by `finalize_ocsvm_threshold.py` on the same
held-out split with a hard 2-percentage-point reproducibility gate before
being written to `thresholds_production_v3.json` (script raises
`SystemExit(1)` if exceeded — confirms this was an enforced check, not
just a comment).

## c. The 26 features, with bucket assignment

Source: `shared_constants.py:FEATURE_COLS_V2`, descriptions from
`shared_features.py`, buckets from `results/rule_memorization_audit/exp4_ablation.py`'s `RULE_IDENTITY` / `RULE_CORRELATED` / `BEHAVIORAL`
partition (the "corrected taxonomy" — RULE_IDENTITY is deliberately
narrow: only fields that encode which *rule* fired, not fields correlated
with rule identity through repeated co-occurrence).

| # | feature | bucket | description |
|--:|---|---|---|
| 1 | `desc_len` | RULE_IDENTITY | character length of `rule.description` |
| 2 | `rule_level` | RULE_IDENTITY | Wazuh's static per-rule severity integer |
| 3 | `kw_scan` | RULE_CORRELATED | 1 if "scan" appears in the combined alert text |
| 4 | `kw_brute` | RULE_CORRELATED | 1 if "brute" appears in the combined alert text |
| 5 | `kw_password` | RULE_CORRELATED | 1 if "password" appears in the combined alert text |
| 6 | `kw_denied` | RULE_CORRELATED | 1 if "denied" appears in the combined alert text |
| 7 | `kw_root` | RULE_CORRELATED | 1 if "root" appears in the combined alert text |
| 8 | `kw_privilege` | RULE_CORRELATED | 1 if "privilege" appears in the combined alert text |
| 9 | `kw_sql` | RULE_CORRELATED | 1 if "sql" appears in the combined alert text |
| 10 | `kw_shell` | RULE_CORRELATED | 1 if "shell" appears in the combined alert text |
| 11 | `kw_trojan` | RULE_CORRELATED | 1 if "trojan" appears in the combined alert text |
| 12 | `kw_virus` | RULE_CORRELATED | 1 if "virus" appears in the combined alert text |
| 13 | `mitre_tactic_id` | RULE_CORRELATED | integer id of the first mapped MITRE ATT&CK tactic, else −1 |
| 14 | `is_auth_failure` | RULE_CORRELATED | 1 if `rule.groups` intersects the auth-failure vocabulary |
| 15 | `is_web_attack` | RULE_CORRELATED | 1 if `rule.groups`/description indicates a web attack |
| 16 | `rule_id_encoded` | RULE_IDENTITY | `float(rule.id)` — the raw Wazuh rule identifier |
| 17 | `agent_criticality` | RULE_CORRELATED | 0–3 weight from an agent-name substring match |
| 18 | `alert_rate_1min` | BEHAVIORAL | # of this agent's alerts in the preceding 60s |
| 19 | `failed_login_5min` | RULE_CORRELATED | # of this agent's auth-failure alerts in the preceding 300s |
| 20 | `unique_src_ip_10min` | BEHAVIORAL | # distinct source IPs from this agent in the preceding 600s |
| 21 | `high_sev_ratio_20` | RULE_CORRELATED | fraction of the agent's last 20 alerts with `rule.level ≥ 8` |
| 22 | `rule_diversity_10min` | RULE_CORRELATED | # distinct rule IDs from this agent in the preceding 600s |
| 23 | `time_since_last_high` | BEHAVIORAL | seconds since this agent's last `rule.level ≥ 10` alert (999 sentinel) |
| 24 | `scan_preceded` | RULE_CORRELATED | 1 if a scan-keyword alert occurred from this agent in the preceding 600s |
| 25 | `brute_preceded` | RULE_CORRELATED | 1 if a brute-keyword alert occurred from this agent in the preceding 600s |
| 26 | `kill_chain_stage` | RULE_CORRELATED | coarse 0–4 kill-chain stage, a fixed function of `mitre_tactic_id` |

Bucket sizes: RULE_IDENTITY = 3, RULE_CORRELATED = 20, BEHAVIORAL = 3
(sums to 26; matches `exp4_ablation.py`'s asserted variant sizes 26/23/3).

## d. Library versions, and the corrected serialization-mismatch note

| | deployed-model training (`results_v2/phase1_run.log`) | this audit's retrain (Tasks 1 & 3, this session) |
|---|---|---|
| python | 3.12.3 | 3.11.9 |
| numpy | 2.4.6 | 2.4.6 |
| pandas | 3.0.3 | 2.3.3 |
| scikit-learn | 1.9.0 | 1.9.0 |
| xgboost | 3.2.0 | 3.2.0 |
| shap | 0.52.0 | not used |

numpy, scikit-learn, and xgboost — the three packages that actually touch
model fitting/scoring in this pipeline — match exactly between the
original training environment and this audit's environment. python and
pandas differ, but pandas is not in the `fit`/`predict_proba` path for
either L1 or L2 here (both are called with raw numpy arrays).

**Correction to a claim inherited from prior work.** Several existing
scripts (`newCol/xdet_task1_lookup.py`'s docstring;
`newCol/figures_ms/fig1_lookup_vs_model.py`'s docstring;
`results/rule_memorization_audit/exp4_ablation.py`'s docstring) assert
that `models_v2/xgb_model.pkl` is unusable in this environment because of
an XGBoost "serialization-version mismatch," citing `predict_proba`
topping out at 0.059 (mean 0.004), entirely below `theta_xgb = 0.0754`.
**This task re-tested that claim directly rather than repeating it, and
it does not hold.** Loading `xgb_model.pkl` and calling `predict_proba`
on `ait_split.npz`'s raw `X_test` does reproduce the degenerate
0.001–0.059 range — but this is because `phase1_xgboost.py` §3–4 trains
and evaluates the deployed model exclusively on
**`StandardScaler`-transformed** features (`X_te_sc`), while
`ait_split.npz` deliberately stores the **unscaled** split for other
downstream consumers (its own in-code comment: "raw (unscaled) split for
phase2"). Passing the same `X_test` through the already-saved
`models_v2/scaler_v2.pkl` + `models_v2/imputer_v2.pkl` before
`predict_proba` gives a probability range of 0.0007–0.9999 (mean 0.655)
and **F1 = 0.9945** at `theta_xgb = 0.07538` — matching this audit's
independent retrain to 4 decimal places, with TP=339,799 FP=51 TN=176,497
FN=3,706. This was a **scaling-pipeline bug in the scripts that made the
claim**, not a real version incompatibility, and not a property of the
model. It should be corrected wherever cited going forward; it does not
change any F1/gap number already reported in this response (both routes
now independently agree).

## e. Summary — deployed vs. audit-time retrain, explicitly labeled

| | L1 deployed | L1 audit-retrain | L2 deployed |
|---|---|---|---|
| Trained on | AIT-ADS train split (upsampled 1:1, scaled) | AIT-ADS train split (raw, unscaled, not upsampled) | in-domain live-lnx benign only (not AIT-ADS; O(n²) constraint) |
| Usable as-shipped? | Yes — **contrary to the prior "version mismatch" claim**, correctly reproduces F1=0.9945 when scored through its own scaler/imputer | N/A (retrained fresh each run) | Yes, no known issue |
| Why the audit retrain exists at all | Convenience/precedent inherited from prior sessions that (incorrectly) believed the pickle was unscoreable; still useful for the per-subset (rule-86601 vs. native) and per-seed breakdowns the deployed pickle's own artifacts don't provide | — | Not retrained in this response; used as-is |

---
**CHECKPOINT — deliverable for Tasks 2–4 batch, see also
`newCol/rev_dataset_characterisation.csv`, `newCol/rev_dataset_table.tex`,
`newCol/rev_multiseed.md`.**
