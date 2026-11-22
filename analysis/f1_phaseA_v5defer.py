"""
f1_phaseA_v5defer.py -- candidate production config: DEFER retained, L2 reverted to v5
=======================================================================================
Diagnostic from f1_phaseA_diag_l2.py showed the v6 OC-SVM retraining bought no
measurable benign-FPR improvement on this fresh collection (v5 and v6 give
IDENTICAL per-rule FPR everywhere), while collapsing true-attack recall on 31151
(98.5%->2.3%) and 5710 (76.1%->18.6%) -- the two rules it up-weighted.

This script re-scores the full PRODUCTION pipeline (defer mechanism retained,
same thresholds) with L2 reverted to ocsvm_nu05.pkl (v5), to confirm: does
31151/5710 recall come back, and at what (if any) FPR cost?
"""
import sys
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from f1_phaseA_lnx import (
    extract_attack_features, extract_benign_features,
    KNOWN_RULES, NOVEL_RULES, DISCRIMINATIVE_RULES,
    confusion, print_cm,
)
from combined_decision_v6 import load_production_models, score_alert
from shared_constants_v2 import FEATURE_COLS_V2

models = load_production_models()
TXG, TOC = float(models["theta_xgb"]), float(models["theta_ocsvm"])

oc_v5 = joblib.load("models_v2/ocsvm_nu05.pkl")
models_v5 = dict(models)
models_v5["ocsvm"] = oc_v5
models_v5["ocsvm_version"] = "v5_reverted (defer mechanism retained, thresholds unchanged)"

print(f"theta_xgb={TXG:.5f}  theta_ocsvm={TOC:.5f}  L2={models_v5['ocsvm_version']}")
print(f"confound-fix rules (defer, unchanged): "
      f"{[r for r, s in models['rule_fixes'].items() if s['mech']=='defer']}\n")

Xa = extract_attack_features()
Xb = extract_benign_features()

disc = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(DISCRIMINATIVE_RULES))].copy()
known = disc[disc.rule_id.isin(KNOWN_RULES)]
novel = disc[disc.rule_id.isin(NOVEL_RULES)]


def production_decisions(df, m):
    l1, l2, comb = [], [], []
    for _, row in df.iterrows():
        fv = row[FEATURE_COLS_V2].values.astype(float)
        r = score_alert(fv, m)
        l1.append(r["category"] == "known_attack")
        l2.append(r["ocsvm_anomaly_score"] >= m["theta_ocsvm"])
        comb.append(r["decision"] != "P4_suppress")
    return np.array(l1, bool), np.array(l2, bool), np.array(comb, bool)


b_l1, b_l2, b_comb = production_decisions(Xb, models_v5)
k_l1, k_l2, k_comb = production_decisions(known, models_v5)
n_l1, n_l2, n_comb = production_decisions(novel, models_v5)
d_l1, d_l2, d_comb = production_decisions(disc, models_v5)


def eval_subset(name, a_l1, a_l2, a_comb, b_l1, b_l2, b_comb):
    y = np.array([True] * len(a_l1) + [False] * len(b_l1))
    out = {}
    for tag, a, b in (("L1", a_l1, b_l1), ("L2", a_l2, b_l2), ("combined", a_comb, b_comb)):
        pred = np.concatenate([a, b])
        cm = confusion(y, pred)
        print_cm(f"{name} / {tag}", cm)
        out[tag] = cm
    return out


print("=" * 90)
print("CANDIDATE CONFIG: PRODUCTION with DEFER + L2=v5 (reverted)")
print("=" * 90)

print("\n-- KNOWN (31101/31151) vs benign --")
v5d_known = eval_subset("V5DEFER KNOWN", k_l1, k_l2, k_comb, b_l1, b_l2, b_comb)

print("\n-- NOVEL vs benign --")
v5d_novel = eval_subset("V5DEFER NOVEL", n_l1, n_l2, n_comb, b_l1, b_l2, b_comb)

print("\n-- BLENDED vs benign -- WARNING: base-rate inflated by web-scan (31101) volume --")
v5d_blended = eval_subset("V5DEFER BLENDED", d_l1, d_l2, d_comb, b_l1, b_l2, b_comb)

print("\n-- direct answer: does 31151/5710 recall come back, at what FPR cost? --")
for rid in ("31101", "31151"):
    m = (known.rule_id == rid).values
    if not m.any():
        continue
    print(f"    rule {rid:<8} n={int(m.sum()):<6} PRODUCTION-v5defer-combined-recall={float(k_comb[m].mean())*100:6.2f}%")
for rid in ("5710",):
    m = (novel.rule_id == rid).values
    if not m.any():
        continue
    print(f"    rule {rid:<8} n={int(m.sum()):<6} PRODUCTION-v5defer-combined-recall={float(n_comb[m].mean())*100:6.2f}%")
print()
for rid, cnt in Xb.rule_id.value_counts().items():
    m = (Xb.rule_id == rid).values
    print(f"    rule {rid:<8} n={cnt:<4} PRODUCTION-v5defer-combined-FPR={float(b_comb[m].mean())*100:6.1f}%")

# ---------------------------------------------------------------------------
rows = []
def stash(subset, layer, cm):
    rows.append(dict(platform="linux", pipeline="PRODUCTION_v5defer", subset=subset, layer=layer, **cm))
for tag, cm in v5d_known.items():
    stash("known", tag, cm)
for tag, cm in v5d_novel.items():
    stash("novel", tag, cm)
for tag, cm in v5d_blended.items():
    stash("blended", tag, cm)
pd.DataFrame(rows).to_csv("analysis/phaseA_lnx_v5defer_results.csv", index=False)
print("\nwrote newCol/phaseA_lnx_v5defer_results.csv")
