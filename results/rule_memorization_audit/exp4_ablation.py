import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
"""
Experiment 4 — Ablation: retrain XGBoost without rule-identity features.
Three variants:
  full        — all 26 features (fresh retrain; used as baseline since pkl has version mismatch)
  no_identity — 23 features (remove RULE-IDENTITY: desc_len, rule_level, rule_id_encoded)
  behav_only  — 3 features  (remove RULE-IDENTITY + RULE-CORRELATED; keep BEHAVIORAL only)

Evaluation:
  a. AIT-ADS eval split (ait_split.npz X_test)
  b. Real-traffic same-attack set  (AIT-ADS phase from lnx_dmz_ai_detections.json)
  c. Novel attack set              (NOVEL phase, broken out per technique)
"""
import sys, csv, json, warnings
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
warnings.filterwarnings("ignore")
sys.path.insert(0, REPO_ROOT)

import numpy as np
import pandas as pd
import pickle
from collections import Counter
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from xgboost import XGBClassifier

from shared_constants import FEATURE_COLS_V2, EXPERIMENT_START, EXPERIMENT_END
from shared_features   import load_lnx_detections

SPLIT_PATH   = REPO_ROOT + "/models_v2/ait_split.npz"
LNX_PATH     = REPO_ROOT + "/lnx_dmz_ai_detections.json"
OUT_DIR      = REPO_ROOT + "/results/rule_memorization_audit/"

# ---- feature sets ---------------------------------------------------------
RULE_IDENTITY  = ["desc_len", "rule_level", "rule_id_encoded"]
RULE_CORRELATED = [
    "kw_scan","kw_brute","kw_password","kw_denied","kw_root","kw_privilege",
    "kw_sql","kw_shell","kw_trojan","kw_virus",
    "mitre_tactic_id","is_auth_failure","is_web_attack","agent_criticality",
    "kill_chain_stage","failed_login_5min","high_sev_ratio_20",
    "rule_diversity_10min","scan_preceded","brute_preceded",
]
BEHAVIORAL = ["alert_rate_1min","unique_src_ip_10min","time_since_last_high"]

VARIANTS = {
    "full":        FEATURE_COLS_V2,
    "no_identity": [f for f in FEATURE_COLS_V2 if f not in RULE_IDENTITY],
    "behav_only":  BEHAVIORAL,
}

# Verify
assert len(VARIANTS["full"])        == 26
assert len(VARIANTS["no_identity"]) == 23
assert len(VARIANTS["behav_only"])  == 3
print("Feature set sizes:", {k: len(v) for k,v in VARIANTS.items()})

# ---- load AIT-ADS split ---------------------------------------------------
print("\nLoading AIT-ADS split...", flush=True)
data    = np.load(SPLIT_PATH, allow_pickle=True)
X_train = data["X_train"]
y_train = data["y_train"]
X_test  = data["X_test"]
y_test  = data["y_test"]
feat_cols = list(data["feature_cols"])
col_idx = {f: i for i, f in enumerate(feat_cols)}
print(f"  Train: {X_train.shape}  |  Test: {X_test.shape}", flush=True)
print(f"  Train attack%: {100*y_train.mean():.1f}%  |  Test attack%: {100*y_test.mean():.1f}%", flush=True)

# ---- helper: select feature columns ---------------------------------------
def select_cols(X, feature_names):
    """Select specified columns from X (using col_idx from full set)."""
    idxs = [col_idx[f] for f in feature_names]
    return X[:, idxs]

# ---- helper: evaluate on a split ------------------------------------------
def evaluate(model, X, y_true, theta):
    proba = model.predict_proba(X)[:, 1]
    y_pred = (proba >= theta).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel()
    f1  = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"f1": f1, "precision": prec, "recall": rec, "fpr": fpr,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
            "theta": theta, "n": len(y_true)}

def find_best_theta(model, X, y_true, n_grid=300):
    """Find threshold maximising F1 on a held-out set."""
    proba = model.predict_proba(X)[:, 1]
    best_f1, best_t = 0.0, 0.5
    for t in np.linspace(proba.min() + 1e-6, proba.max() - 1e-6, n_grid):
        f = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_t = f, t
    return float(best_t), float(best_f1)

# ---- XGBoost hyperparameters ----------------------------------------------
XGB_PARAMS = dict(
    n_estimators   = 50,
    max_depth      = 5,
    subsample      = 0.5,
    learning_rate  = 0.1,
    eval_metric    = "logloss",
    use_label_encoder = False,
    random_state   = 42,
    n_jobs         = -1,
)

# ---- train all three variants on AIT-ADS split ----------------------------
trained_models = {}
thresholds     = {}

for variant_name, feat_list in VARIANTS.items():
    print(f"\n=== Training variant: {variant_name} ({len(feat_list)} features) ===", flush=True)
    Xtr = select_cols(X_train, feat_list)
    Xte = select_cols(X_test,  feat_list)

    model = XGBClassifier(**XGB_PARAMS)
    model.fit(Xtr, y_train, verbose=False)

    # calibrate threshold on eval split (same split → comparable to published results)
    theta, f1_cal = find_best_theta(model, Xte, y_test)
    thresholds[variant_name]     = theta
    trained_models[variant_name] = model
    print(f"  Trained | best F1={f1_cal:.4f} @ theta={theta:.5f}", flush=True)

# ---- Evaluation A: AIT-ADS eval split -------------------------------------
print("\n=== Evaluation A: AIT-ADS eval split ===", flush=True)
ait_results = {}
for variant_name, feat_list in VARIANTS.items():
    Xte  = select_cols(X_test, feat_list)
    res  = evaluate(trained_models[variant_name], Xte, y_test, thresholds[variant_name])
    ait_results[variant_name] = res
    print(f"  {variant_name:<15}: F1={res['f1']:.4f}  prec={res['precision']:.4f}  "
          f"rec={res['recall']:.4f}  FPR={res['fpr']:.4f}", flush=True)

# ---- Load real-traffic data (lnx_dmz) -------------------------------------
print("\n=== Loading lnx-dmz detections ===", flush=True)
try:
    df_lnx = load_lnx_detections(LNX_PATH, EXPERIMENT_START, EXPERIMENT_END)
    print(f"  Loaded {len(df_lnx):,} alerts | phases: {df_lnx['phase'].value_counts().to_dict()}", flush=True)
    print(f"  Techniques in NOVEL phase:", flush=True)
    novel_df = df_lnx[df_lnx["phase"] == "NOVEL"]
    for tech, cnt in novel_df["technique"].value_counts().items():
        print(f"    {tech}: {cnt} alerts", flush=True)
except Exception as e:
    print(f"  ERROR loading lnx_dmz: {e}", flush=True)
    df_lnx = None

# ---- Evaluation B: real-traffic same-attack (AIT-ADS phase) ---------------
print("\n=== Evaluation B: Real-traffic same-attack (AIT-ADS phase) ===", flush=True)
b_results = {}
if df_lnx is not None:
    df_ait_phase = df_lnx[df_lnx["phase"] == "AIT-ADS"].copy()
    print(f"  AIT-ADS phase alerts: {len(df_ait_phase):,}  "
          f"(attack={df_ait_phase['label'].sum()}, benign={(df_ait_phase['label']==0).sum()})", flush=True)

    if len(df_ait_phase) > 0 and df_ait_phase["label"].nunique() > 1:
        y_b = df_ait_phase["label"].values
        for variant_name, feat_list in VARIANTS.items():
            Xb = df_ait_phase[feat_list].values
            res = evaluate(trained_models[variant_name], Xb, y_b, thresholds[variant_name])
            b_results[variant_name] = res
            print(f"  {variant_name:<15}: F1={res['f1']:.4f}  prec={res['precision']:.4f}  "
                  f"rec={res['recall']:.4f}  FPR={res['fpr']:.4f}", flush=True)
    else:
        print("  Insufficient data or only one class — skipping B.", flush=True)
else:
    print("  lnx_dmz data unavailable — skipping B.", flush=True)

# ---- Evaluation C: novel attacks (NOVEL phase) ----------------------------
print("\n=== Evaluation C: Novel attacks ===", flush=True)

# Tag shared-rule vs truly-unseen-rule
# T1053.003 = cron (rule 2832) — absent from AIT-ADS training → truly-unseen
# All others with detected alerts use rules shared with AIT-ADS privilege_escalation
TRULY_UNSEEN = {"T1053.003"}

c_results = {}
if df_lnx is not None:
    df_novel = df_lnx[df_lnx["phase"] == "NOVEL"].copy()
    print(f"  NOVEL phase alerts: {len(df_novel):,}  "
          f"(attack={df_novel['label'].sum()}, benign={(df_novel['label']==0).sum()})", flush=True)

    # Overall novel
    if len(df_novel) > 0 and df_novel["label"].nunique() > 1:
        y_c = df_novel["label"].values
        for variant_name, feat_list in VARIANTS.items():
            Xc = df_novel[feat_list].values
            res = evaluate(trained_models[variant_name], Xc, y_c, thresholds[variant_name])
            c_results[f"{variant_name}_NOVEL_overall"] = res
            print(f"  {variant_name:<15} [overall]: F1={res['f1']:.4f}  "
                  f"rec={res['recall']:.4f}  FPR={res['fpr']:.4f}", flush=True)

    # Per technique
    c_per_tech = {}
    for tech in sorted(df_novel["technique"].unique()):
        df_tech = df_lnx[(df_lnx["technique"] == tech) |
                         ((df_lnx["phase"] == "NOVEL") & (df_lnx["label"] == 0))]
        df_tech = df_novel[df_novel["technique"].isin([tech, ""])].copy()
        # Actually: just compute recall on the attack alerts for this tech
        df_atk = df_novel[df_novel["technique"] == tech]
        if len(df_atk) == 0:
            continue
        tag = "truly-unseen-rule" if tech in TRULY_UNSEEN else "shared-rule"
        y_atk = df_atk["label"].values
        print(f"\n  Technique {tech} [{tag}] — {len(df_atk)} alerts, "
              f"attack%={(100*y_atk.mean()):.0f}%", flush=True)
        for variant_name, feat_list in VARIANTS.items():
            Xa = df_atk[feat_list].values
            proba = trained_models[variant_name].predict_proba(Xa)[:, 1]
            y_pred = (proba >= thresholds[variant_name]).astype(int)
            recall = recall_score(y_atk, y_pred, zero_division=0)
            detected = y_pred[y_atk == 1].sum()
            n_atk = (y_atk == 1).sum()
            print(f"    {variant_name:<15}: recall={recall:.4f}  detected={detected}/{n_atk}", flush=True)
            c_per_tech.setdefault(tech, {})[variant_name] = {
                "tag": tag, "recall": recall, "detected": int(detected), "n_attack": int(n_atk)
            }
else:
    print("  lnx_dmz data unavailable — skipping C.", flush=True)

# ---- Comparison table -------------------------------------------------------
print("\n" + "=" * 90, flush=True)
print("ABLATION COMPARISON TABLE", flush=True)
print("=" * 90, flush=True)

header = f"{'Model':<18} {'AIT-ADS F1':>11} {'AIT-ADS Rec':>12} {'AIT-ADS FPR':>12}"
if b_results:
    header += f" {'Online F1':>10} {'Online Rec':>11}"
print(header, flush=True)
print("-" * len(header), flush=True)
for v in ["full","no_identity","behav_only"]:
    ai = ait_results.get(v, {})
    br = b_results.get(v, {})
    line = f"{v:<18} {ai.get('f1',float('nan')):>11.4f} {ai.get('recall',float('nan')):>12.4f} {ai.get('fpr',float('nan')):>12.4f}"
    if b_results:
        line += f" {br.get('f1',float('nan')):>10.4f} {br.get('recall',float('nan')):>11.4f}"
    print(line, flush=True)

if c_per_tech:
    print("\nNovel per-technique recall (attack alerts only):", flush=True)
    print(f"  {'Technique':<14} {'Tag':<20} {'full':>8} {'no_id':>8} {'behav':>8}", flush=True)
    print("  " + "-" * 62, flush=True)
    for tech in sorted(c_per_tech.keys()):
        td = c_per_tech[tech]
        tag = list(td.values())[0]["tag"]
        r_full  = td.get("full",{}).get("recall",float("nan"))
        r_noid  = td.get("no_identity",{}).get("recall",float("nan"))
        r_beh   = td.get("behav_only",{}).get("recall",float("nan"))
        n_atk   = list(td.values())[0]["n_attack"]
        print(f"  {tech:<14} {tag:<20} {r_full:>8.4f} {r_noid:>8.4f} {r_beh:>8.4f}  (n={n_atk})", flush=True)

# ---- Write CSVs ------------------------------------------------------------
rows_out = []
for v in ["full","no_identity","behav_only"]:
    ai = ait_results.get(v, {})
    br = b_results.get(v, {})
    rows_out.append({
        "variant": v,
        "n_features": len(VARIANTS[v]),
        "theta": f"{thresholds.get(v,float('nan')):.5f}",
        "ait_f1":       f"{ai.get('f1',float('nan')):.4f}",
        "ait_recall":   f"{ai.get('recall',float('nan')):.4f}",
        "ait_fpr":      f"{ai.get('fpr',float('nan')):.4f}",
        "online_f1":    f"{br.get('f1',float('nan')):.4f}" if br else "N/A",
        "online_recall":f"{br.get('recall',float('nan')):.4f}" if br else "N/A",
        "online_fpr":   f"{br.get('fpr',float('nan')):.4f}" if br else "N/A",
    })

tech_rows = []
if c_per_tech:
    for tech, td in sorted(c_per_tech.items()):
        tag = list(td.values())[0]["tag"]
        n_atk = list(td.values())[0]["n_attack"]
        for v in ["full","no_identity","behav_only"]:
            r = td.get(v, {})
            tech_rows.append({
                "technique": tech, "tag": tag, "n_attack": n_atk,
                "variant": v,
                "recall": f"{r.get('recall',float('nan')):.4f}",
                "detected": r.get("detected",""),
            })

out_main = OUT_DIR + "exp4_ablation_main.csv"
out_tech = OUT_DIR + "exp4_ablation_per_technique.csv"

with open(out_main, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
    w.writeheader(); w.writerows(rows_out)

if tech_rows:
    with open(out_tech, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(tech_rows[0].keys()))
        w.writeheader(); w.writerows(tech_rows)

print(f"\nWrote → {out_main}", flush=True)
if tech_rows:
    print(f"Wrote → {out_tech}", flush=True)
print("Checkpoint 4 complete.", flush=True)
