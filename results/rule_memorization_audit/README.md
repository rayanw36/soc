# Rule-identity audit (`results/rule_memorization_audit/`)

The experiments behind Figs 1-3 of the paper. The directory keeps its original name (it predates the paper's
final title and is referenced by the figure scripts and the claims map); "rule-identity shortcut" is the term
the paper uses for what these experiments measure.

| script | output | what it does |
|---|---|---|
| `exp1_feature_classification.py` | `exp1_feature_classification.csv` | assigns each of the 26 features to rule-identity, rule-correlated or behavioral |
| `exp2_feature_importance.py` | `exp2_importance_gain.csv`, `exp2_shap_top20.csv` | XGBoost gain and SHAP importance |
| `exp3_lookup_table.py` | `exp3_lookup_results.csv` | majority-label-per-rule-id lookup table on the AIT-ADS evaluation split |
| `exp4_ablation.py` | `exp4_ablation_main.csv`, `exp4_ablation_per_technique.csv` | retrains XGBoost with feature groups removed |

All four read the committed `models_v2/ait_split.npz`; none needs the raw AIT-ADS download.

## One row in `exp3_lookup_results.csv` is a known-broken measurement

`exp3_lookup_results.csv` contains `XGBoost F1 (published),0.0000` and `Gap (XGB - lookup),-0.9942`. These come
from scoring the deployed `models_v2/xgb_model.pkl` on raw, unscaled features, although it was trained on scaled
ones: a scaling error in the scoring step (not a serialization-version mismatch, as earlier drafts said). Scored
through its own scaler and imputer the deployed model gives F1 = 0.9945. Do not use the 0.0000 row or the gap
derived from it. The values used in the paper are:

- lookup table F1 0.9942: `exp3_lookup_results.csv`, row `Lookup-table F1 (rule_id only)`;
- XGBoost F1 0.9945 (an audit-time retrain, threshold chosen by maximising F1 on the same split): the `full` row
  of `exp4_ablation_main.csv`; gap +0.0003.

`exp3_lookup_table.py` still writes the 0.0000 row each time it runs, so the file is regenerated unchanged.
