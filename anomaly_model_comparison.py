"""
anomaly_model_comparison.py
===========================
TASKS 2-4 of the anomaly-model diagnostic.

Trains Isolation Forest and One-Class SVM (nu in {0.05,0.10,0.15}) on EXACTLY
the same cleaned benign data MemAE-v2 used, then compares all five models
(MemAE-v2, IsoForest, OCSVM x3) on the same held-out benign + 43 novel alerts,
both aggregate and per technique.

Score convention: higher = more anomalous for every model
  MemAE  -> reconstruction error
  IsoF   -> -score_samples
  OCSVM  -> -decision_function

Run:  ~/soc_project/.venv/bin/python anomaly_model_comparison.py
"""

import json

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2, FEATURE_COLS_V2, SEED, EXPERIMENT_START, EXPERIMENT_END
import shared_features
shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import load_lnx_detections

MODELS, PLOTS, RESULTS = "models_v2", "plots_v2", "results_v2"
LNX_FILE = "lnx_dmz_ai_detections.json"


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


# ---------------------------------------------------------------------------
# Reproduce the EXACT data MemAE-v2 used
# ---------------------------------------------------------------------------
hr("SECTION 1: REPRODUCE MEMAE-v2 DATA SPLIT")
scaler = joblib.load(f"{MODELS}/scaler_v2.pkl")
imputer = joblib.load(f"{MODELS}/imputer_v2.pkl")
print(f"  reusing shared scaler ({type(scaler).__name__}) + imputer "
      f"(same pipeline MemAE/XGBoost use; OC-SVM scale requirement satisfied)")

clean_lnx = pd.read_csv(f"{RESULTS}/benign_baseline_clean.csv")[FEATURE_COLS_V2].values
perm = np.random.RandomState(SEED).permutation(len(clean_lnx))
n_hold = max(1, int(0.20 * len(clean_lnx)))
test_benign_raw = clean_lnx[perm[:n_hold]]       # held-out, never trained on
train_benign_raw = clean_lnx[perm[n_hold:]]      # 80% benign for training alt models
print(f"  clean benign total={len(clean_lnx)}  train={len(train_benign_raw)}  "
      f"held-out test={len(test_benign_raw)}")
print(f"  NOTE: MemAE-v2 additionally trained on 706k AIT-ADS benign; IsoForest/OC-SVM")
print(f"  are trained on the in-domain cleaned lnx benign only (OC-SVM is O(n^2) and")
print(f"  cannot scale to 706k). The TEST sets (held-out benign + 43 novel) are identical")
print(f"  across all models, so the comparison metrics are computed on identical data.")

Xtr = scaler.transform(imputer.transform(train_benign_raw)).astype(np.float64)
Xte_benign = scaler.transform(imputer.transform(test_benign_raw)).astype(np.float64)

lnx = load_lnx_detections(LNX_FILE, EXPERIMENT_START, EXPERIMENT_END)
nov = lnx[(lnx.phase == "NOVEL") & (lnx.label == 1)].copy().reset_index(drop=True)
Xte_novel = scaler.transform(imputer.transform(nov[FEATURE_COLS_V2].values)).astype(np.float64)
print(f"  novel test alerts={len(nov)}  techniques={sorted(nov.technique.unique())}")


# ---------------------------------------------------------------------------
# Train alternative models
# ---------------------------------------------------------------------------
hr("SECTION 2: TRAIN ISOLATION FOREST + ONE-CLASS SVM")
iso = IsolationForest(n_estimators=200, contamination="auto", max_samples="auto",
                      random_state=SEED, n_jobs=-1).fit(Xtr)
joblib.dump(iso, f"{MODELS}/isolation_forest.pkl")
print("  IsolationForest(n_estimators=200) trained.")

ocsvms = {}
for nu in (0.05, 0.10, 0.15):
    m = OneClassSVM(kernel="rbf", gamma="scale", nu=nu).fit(Xtr)
    tag = f"nu{int(nu*100):02d}"
    joblib.dump(m, f"{MODELS}/ocsvm_{tag}.pkl")
    ocsvms[nu] = m
    print(f"  OneClassSVM(nu={nu}) trained -> ocsvm_{tag}.pkl")


# ---------------------------------------------------------------------------
# MemAE-v2 (reuse)
# ---------------------------------------------------------------------------
class MemoryUnit(nn.Module):
    def __init__(s, m, d, sh=0.0025):
        super().__init__(); s.memory = nn.Parameter(torch.randn(m, d)); s.shrink_thres = sh
    def forward(s, z):
        sim = torch.softmax(z @ s.memory.T / (z.shape[1] ** 0.5), dim=1)
        sim = F.relu(sim - s.shrink_thres); sim = sim / sim.sum(1, keepdim=True).clamp(min=1e-8)
        return sim @ s.memory, sim


class MemAE(nn.Module):
    def __init__(s, input_dim=26, mem_size=100, latent_dim=8, shrink_thres=0.0025):
        super().__init__()
        s.encoder = nn.Sequential(nn.Linear(input_dim, 16), nn.ReLU(), nn.BatchNorm1d(16),
                                  nn.Linear(16, latent_dim), nn.ReLU())
        s.memory = MemoryUnit(mem_size, latent_dim, shrink_thres)
        s.decoder = nn.Sequential(nn.Linear(latent_dim, 16), nn.ReLU(), nn.BatchNorm1d(16),
                                  nn.Linear(16, input_dim))
    def forward(s, x):
        z = s.encoder(x); zh, a = s.memory(z); xh = s.decoder(zh)
        return xh, ((x - xh) ** 2).mean(1), a


ck = torch.load(f"{MODELS}/memae_v2_model.pth", map_location="cpu")
memae = MemAE(**ck["config"]); memae.load_state_dict(ck["state_dict"]); memae.eval()


def memae_score(Xf):
    with torch.no_grad():
        _, e, _ = memae(torch.tensor(Xf.astype(np.float32)))
    return e.numpy()


# ---------------------------------------------------------------------------
# Score all models (higher = more anomalous)
# ---------------------------------------------------------------------------
hr("SECTION 3: SCORE ALL MODELS ON IDENTICAL TEST DATA")
scorers = {
    "MemAE": lambda X: memae_score(X),
    "IsoForest": lambda X: -iso.score_samples(X),
    "OCSVM(nu=0.05)": lambda X: -ocsvms[0.05].decision_function(X),
    "OCSVM(nu=0.10)": lambda X: -ocsvms[0.10].decision_function(X),
    "OCSVM(nu=0.15)": lambda X: -ocsvms[0.15].decision_function(X),
}
benign_scores = {name: f(Xte_benign) for name, f in scorers.items()}
novel_scores = {name: f(Xte_novel) for name, f in scorers.items()}


def recall_at_fpr(benign, novel, target):
    """Lowest threshold with benign FPR<=target (=> max recall). Returns
    (recall, achieved_fpr, threshold)."""
    cand = np.sort(np.unique(np.concatenate([benign, novel])))
    for t in cand:
        fpr = float((benign >= t).mean())
        if fpr <= target:
            return float((novel >= t).mean()), fpr, float(t)
    return 0.0, 0.0, float("inf")


def best_f1(benign, novel):
    cand = np.unique(np.concatenate([benign, novel]))
    best, bt = 0.0, None
    for t in cand:
        tp = (novel >= t).sum(); fn = (novel < t).sum(); fp = (benign >= t).sum()
        d = 2 * tp + fp + fn
        f1 = 2 * tp / d if d else 0.0
        if f1 > best:
            best, bt = f1, t
    return best, bt


# ---------------------------------------------------------------------------
# Aggregate metrics + per-technique recall@10%FPR
# ---------------------------------------------------------------------------
hr("SECTION 4: AGGREGATE METRICS")
techs = sorted(nov.technique.unique())
agg_rows = []
per_tech = {t: {} for t in techs}
thr10 = {}
print(f"  {'Model':16s} {'rec@10%FPR':>11s} {'rec@5%FPR':>10s} {'bestF1':>7s} "
      f"{'benMed':>8s} {'novMed':>8s}  separation")
for name in scorers:
    b, nvl = benign_scores[name], novel_scores[name]
    r10, fpr10, t10 = recall_at_fpr(b, nvl, 0.10)
    r05, fpr05, _ = recall_at_fpr(b, nvl, 0.05)
    f1, _ = best_f1(b, nvl)
    bmed, nmed = float(np.median(b)), float(np.median(nvl))
    sep = "CORRECT" if nmed > bmed else "INVERTED"
    thr10[name] = t10
    print(f"  {name:16s} {r10*100:10.1f}% {r05*100:9.1f}% {f1:7.3f} "
          f"{bmed:8.3f} {nmed:8.3f}  {sep}")
    agg_rows.append(dict(model=name, recall_at_10pct_fpr=r10, achieved_fpr_10=fpr10,
                         recall_at_5pct_fpr=r05, best_f1=f1,
                         benign_median=bmed, novel_median=nmed, separation=sep,
                         threshold_10pct=t10))
    # per technique at the 10% FPR threshold
    for t in techs:
        s = nvl[nov.technique.values == t]
        per_tech[t][name] = float((s >= t10).mean()) if len(s) else float("nan")

hr("SECTION 5: PER-TECHNIQUE RECALL @ 10% FPR (the key table)")
counts = nov.technique.value_counts().to_dict()
hdr = f"{'Technique':12s} {'N':>3s} " + " ".join(f"{n:>15s}" for n in scorers)
print(hdr); print("-" * len(hdr))
pt_rows = []
for t in techs:
    line = f"{t:12s} {counts[t]:3d} " + " ".join(
        f"{per_tech[t][n]*100:14.1f}%" for n in scorers)
    print(line)
    row = dict(technique=t, n_alerts=counts[t])
    row.update({f"recall10_{n}": per_tech[t][n] for n in scorers})
    pt_rows.append(row)

# save full results
pd.DataFrame(agg_rows).to_csv(f"{RESULTS}/anomaly_model_comparison.csv", index=False)
pd.DataFrame(pt_rows).to_csv(f"{RESULTS}/anomaly_model_per_technique.csv", index=False)
print(f"\nSaved {RESULTS}/anomaly_model_comparison.csv")
print(f"Saved {RESULTS}/anomaly_model_per_technique.csv")


# ---------------------------------------------------------------------------
# SECTION 6: plots
# ---------------------------------------------------------------------------
hr("SECTION 6: PLOTS")
model_names = list(scorers.keys())
colors = ["#c33", "#2a7", "#46a", "#fa3", "#85f"]

# 1. grouped bar per technique
fig, ax = plt.subplots(figsize=(12, 6))
x = np.arange(len(techs)); w = 0.16
for i, name in enumerate(model_names):
    vals = [per_tech[t][name] * 100 for t in techs]
    ax.bar(x + (i - 2) * w, vals, w, label=name, color=colors[i])
ax.set_xticks(x)
ax.set_xticklabels([f"{t}\n(n={counts[t]})" for t in techs])
ax.set_ylabel("Recall @ 10% FPR (%)"); ax.set_ylim(0, 105)
ax.set_title("Per-technique novel-attack recall @ 10% FPR — 5 anomaly models")
ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(f"{PLOTS}/anomaly_model_comparison_per_technique.png", dpi=120)
plt.close()
print(f"  Saved {PLOTS}/anomaly_model_comparison_per_technique.png")

# 2. score-distribution histograms, one panel per model
fig, axes = plt.subplots(1, 5, figsize=(22, 4.2))
for ax, name in zip(axes, model_names):
    b, nvl = benign_scores[name], novel_scores[name]
    allv = np.concatenate([b, nvl]); xhi = max(float(np.percentile(allv, 97)), 1e-6)
    bins = np.linspace(float(allv.min()), xhi, 40)
    no_b = int((b > xhi).sum()); no_n = int((nvl > xhi).sum())
    ax.hist(np.clip(b, None, xhi), bins=bins, alpha=0.5, density=True,
            color="#46a", label=f"benign (n={len(b)}" + (f", {no_b} off)" if no_b else ")"))
    ax.hist(np.clip(nvl, None, xhi), bins=bins, alpha=0.5, density=True,
            color="#c33", label=f"novel (n={len(nvl)}" + (f", {no_n} off)" if no_n else ")"))
    ax.axvline(thr10[name], color="k", ls="--", lw=1, label="10%FPR θ")
    ax.set_title(name); ax.set_xlabel("anomaly score (clipped p97)")
    ax.legend(fontsize=7); ax.grid(alpha=0.3)
axes[0].set_ylabel("density")
fig.suptitle("Anomaly score distributions: held-out benign vs 43 novel attacks", fontsize=13)
plt.tight_layout(rect=[0, 0, 1, 0.94])
plt.savefig(f"{PLOTS}/anomaly_model_score_distributions_all.png", dpi=120); plt.close()
print(f"  Saved {PLOTS}/anomaly_model_score_distributions_all.png")

# 3. aggregate recall bar
fig, ax = plt.subplots(figsize=(9, 5))
agg = [recall_at_fpr(benign_scores[n], novel_scores[n], 0.10)[0] * 100 for n in model_names]
bars = ax.bar(model_names, agg, color=colors)
for bar, v in zip(bars, agg):
    ax.text(bar.get_x() + bar.get_width() / 2, v + 1, f"{v:.1f}%", ha="center", fontsize=9)
ax.set_ylabel("Aggregate recall @ 10% FPR (%)"); ax.set_ylim(0, 105)
ax.set_title("Aggregate novel-attack recall @ 10% FPR (all 43 novel alerts)")
ax.grid(axis="y", alpha=0.3); plt.xticks(rotation=15)
plt.tight_layout(); plt.savefig(f"{PLOTS}/anomaly_model_aggregate_recall.png", dpi=120)
plt.close()
print(f"  Saved {PLOTS}/anomaly_model_aggregate_recall.png")
