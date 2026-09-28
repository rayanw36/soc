"""
f1_phaseA_diag_l2.py -- diagnostic: is the KNOWN-rule recall collapse caused by the
v6 OC-SVM retraining (up-weighting 31151/5710 benign), or was L2 already blind to
real 31101/31151 attacks even in v5 -- i.e. is "defer" itself the problem regardless
of which OC-SVM sits behind it?

Compares ocsvm_nu05.pkl (v5) vs ocsvm_nu05_v6.pkl (v6, currently in production) on
the SAME fresh KNOWN attacks (31101/31151) and the SAME fresh benign collection,
at the identical production threshold theta_ocsvm.
"""
import sys
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, ".")
from f1_phaseA_lnx import extract_attack_features, extract_benign_features, KNOWN_RULES, NOVEL_RULES
from combined_decision_v6 import load_production_models, ocsvm_anomaly_score
from shared_constants_v2 import FEATURE_COLS_V2

models = load_production_models()
TOC = float(models["theta_ocsvm"])
print(f"theta_ocsvm = {TOC:.5f}\n")

oc_v6 = models["ocsvm"]
oc_v5 = joblib.load("models_v2/ocsvm_nu05.pkl")

Xa = extract_attack_features()
Xb = extract_benign_features()

known = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(KNOWN_RULES))]
novel = Xa[(Xa.label == "attack") & (Xa.rule_id.isin(NOVEL_RULES))]


def sc(df):
    return models["scaler"].transform(models["imputer"].transform(df[FEATURE_COLS_V2].values.astype(float)))


def scores(df, oc):
    if not len(df):
        return np.zeros(0)
    return ocsvm_anomaly_score(oc, sc(df))


print("=" * 90)
print("L2 RECALL on KNOWN attacks (31101/31151), v5 vs v6 OC-SVM, same theta_ocsvm")
print("=" * 90)
for rid in sorted(KNOWN_RULES):
    sub = known[known.rule_id == rid]
    if not len(sub):
        continue
    s5, s6 = scores(sub, oc_v5), scores(sub, oc_v6)
    r5, r6 = float((s5 >= TOC).mean()) * 100, float((s6 >= TOC).mean()) * 100
    print(f"  rule {rid:<8} n={len(sub):<6} v5-recall={r5:6.2f}%  v6-recall={r6:6.2f}%  "
          f"v5-median-score={np.median(s5):8.4f}  v6-median-score={np.median(s6):8.4f}  "
          f"(theta={TOC:.4f})")

print("\n" + "=" * 90)
print("L2 RECALL on NOVEL attacks (sanity: v6 was retrained to catch 5710 specifically)")
print("=" * 90)
for rid in sorted(NOVEL_RULES):
    sub = novel[novel.rule_id == rid]
    if not len(sub):
        continue
    s5, s6 = scores(sub, oc_v5), scores(sub, oc_v6)
    r5, r6 = float((s5 >= TOC).mean()) * 100, float((s6 >= TOC).mean()) * 100
    print(f"  rule {rid:<8} n={len(sub):<6} v5-recall={r5:6.2f}%  v6-recall={r6:6.2f}%")

print("\n" + "=" * 90)
print("L2 FPR on fresh benign, v5 vs v6 OC-SVM, per rule")
print("=" * 90)
for rid, cnt in Xb.rule_id.value_counts().items():
    sub = Xb[Xb.rule_id == rid]
    s5, s6 = scores(sub, oc_v5), scores(sub, oc_v6)
    f5, f6 = float((s5 >= TOC).mean()) * 100, float((s6 >= TOC).mean()) * 100
    print(f"  rule {rid:<8} n={cnt:<4} v5-FPR={f5:6.1f}%  v6-FPR={f6:6.1f}%")

print("\n" + "=" * 90)
print("SUMMARY -- aggregate KNOWN (31101+31151)")
print("=" * 90)
s5k, s6k = scores(known, oc_v5), scores(known, oc_v6)
print(f"  KNOWN attacks (n={len(known)}): v5 L2 recall={float((s5k>=TOC).mean())*100:.2f}%  "
      f"v6 L2 recall={float((s6k>=TOC).mean())*100:.2f}%")
b31101 = Xb[Xb.rule_id == "31101"]
if len(b31101):
    sb5, sb6 = scores(b31101, oc_v5), scores(b31101, oc_v6)
    print(f"  benign rule-31101 (n={len(b31101)}): v5 L2 FPR={float((sb5>=TOC).mean())*100:.2f}%  "
          f"v6 L2 FPR={float((sb6>=TOC).mean())*100:.2f}%")
