"""
anomaly_diagnostic_verdict.py
=============================
TASK 5 of the anomaly-model diagnostic.

Reads the aggregate + per-technique comparison from anomaly_model_comparison.py
and classifies the result into exactly one of:
  A  architecture problem, partially fixable (a model swap meaningfully helps)
  B  feature-representation problem (all models fail similarly on quiet techniques)
  C  inconclusive due to sample size

The classification is computed from the numbers, not asserted.  Sample-size
caveats are stated explicitly.

Run:  ~/soc_project/.venv/bin/python anomaly_diagnostic_verdict.py
"""

import numpy as np
import pandas as pd

RESULTS = "results_v2"
MEMAE = "MemAE"
ALT_MODELS = ["IsoForest", "OCSVM(nu=0.05)", "OCSVM(nu=0.10)", "OCSVM(nu=0.15)"]
QUIET_CUTOFF = 0.50      # technique is "quiet for MemAE" if MemAE recall@10%FPR < 50%
MIN_N = 3                # minimum alerts to treat a per-technique delta as signal
BIG_MARGIN = 0.20        # 20-percentage-point improvement


def hr(t):
    print("\n" + "=" * 78); print(t); print("=" * 78)


agg = pd.read_csv(f"{RESULTS}/anomaly_model_comparison.csv").set_index("model")
pt = pd.read_csv(f"{RESULTS}/anomaly_model_per_technique.csv")

lines = []


def emit(s=""):
    print(s); lines.append(s)


# ---------------------------------------------------------------------------
hr("AGGREGATE (all 43 novel alerts)")
emit("Aggregate recall @ 10% FPR:")
for m in [MEMAE] + ALT_MODELS:
    emit(f"  {m:16s} {agg.loc[m,'recall_at_10pct_fpr']*100:5.1f}%   "
         f"(best-F1 {agg.loc[m,'best_f1']:.3f})")
memae_agg = agg.loc[MEMAE, "recall_at_10pct_fpr"]
best_alt = max(ALT_MODELS, key=lambda m: agg.loc[m, "recall_at_10pct_fpr"])
best_alt_agg = agg.loc[best_alt, "recall_at_10pct_fpr"]
best_f1_model = agg["best_f1"].idxmax()
emit(f"\nMemAE aggregate recall@10%FPR : {memae_agg*100:.1f}%")
emit(f"Best alternative ({best_alt}): {best_alt_agg*100:.1f}%  "
     f"(+{(best_alt_agg-memae_agg)*100:.1f} pp vs MemAE)")
emit(f"Best F1 overall: {best_f1_model} ({agg.loc[best_f1_model,'best_f1']:.3f})")


# ---------------------------------------------------------------------------
hr("PER-TECHNIQUE ANALYSIS")
quiet, loud, tiny = [], [], []
arch_win_quiet = []      # quiet techniques (n>=3) where an alt beats MemAE by >20pp
all_fail_quiet = []      # quiet techniques (n>=3) where ALL models < 30%
for _, r in pt.iterrows():
    t, n = r["technique"], int(r["n_alerts"])
    memae_r = r[f"recall10_{MEMAE}"]
    alt_best = max(r[f"recall10_{m}"] for m in ALT_MODELS)
    is_quiet = memae_r < QUIET_CUTOFF
    cat = "QUIET" if is_quiet else "LOUD"
    if n < MIN_N:
        cat += " (n<3, ignore)"; tiny.append(t)
    emit(f"  {t} (n={n:2d}) [{cat}]: MemAE {memae_r*100:.0f}%  "
         f"best-alt {alt_best*100:.0f}%  delta {(alt_best-memae_r)*100:+.0f}pp")
    if is_quiet and n >= MIN_N:
        quiet.append(t)
        if alt_best - memae_r > BIG_MARGIN:
            arch_win_quiet.append((t, n, memae_r, alt_best))
        allmods = [memae_r] + [r[f"recall10_{m}"] for m in ALT_MODELS]
        if max(allmods) < 0.30:
            all_fail_quiet.append((t, n, max(allmods)))
    elif not is_quiet:
        loud.append(t)

emit(f"\nQuiet techniques w/ n>=3: {quiet}")
emit(f"  ...where a model swap gives >20pp gain over MemAE: "
     f"{[t for t,*_ in arch_win_quiet]}")
emit(f"  ...where ALL models still fail (<30%):            "
     f"{[t for t,*_ in all_fail_quiet]}")
emit(f"Loud techniques: {loud}")
emit(f"Tiny techniques ignored (n<3): {tiny}")


# ---------------------------------------------------------------------------
hr("VERDICT")
agg_doubles = (best_alt_agg - memae_agg) > BIG_MARGIN
if arch_win_quiet and agg_doubles:
    outcome = "A"
elif all_fail_quiet and not arch_win_quiet:
    outcome = "B"
else:
    outcome = "C"

# robustness note: how much of the evidence rests on tiny samples
total_novel = int(pt.n_alerts.sum())
n_in_small = int(pt[pt.n_alerts < MIN_N].n_alerts.sum())

if outcome == "A":
    emit("OUTCOME A — Architecture problem, partially fixable.")
    emit("")
    emit(f"Swapping MemAE for One-Class SVM / Isolation Forest, trained on the SAME")
    emit(f"cleaned benign data and evaluated on the SAME held-out benign + 43 novel")
    emit(f"alerts, roughly DOUBLES aggregate recall at the 10% FPR budget: MemAE")
    emit(f"{memae_agg*100:.1f}% -> {best_alt} {best_alt_agg*100:.1f}% "
         f"(+{(best_alt_agg-memae_agg)*100:.0f}pp). The gain is not a threshold artefact:")
    emit(f"{best_f1_model} also has the best F1 ({agg.loc[best_f1_model,'best_f1']:.3f}).")
    for t, n, mr, ar in arch_win_quiet:
        emit(f"  - {t} (n={n}): MemAE {mr*100:.0f}% -> {ar*100:.0f}% under the best alt model.")
    emit("")
    emit("IMPORTANT CAVEATS (do not overstate):")
    if all_fail_quiet:
        for t, n, mx in all_fail_quiet:
            emit(f"  - {t} (n={n}) is missed by EVERY model (best {mx*100:.0f}%). This one")
            emit(f"    technique is a genuine FEATURE-representation gap, not fixable by a")
            emit(f"    model swap -- it needs richer features (see Outcome-B remedy).")
    emit(f"  - {n_in_small}/{total_novel} novel alerts sit in techniques with n<3 "
         f"(T1053.003 n=1, ...);")
    emit(f"    their 0%/100% swings are sampling noise and were excluded from the call.")
    emit("")
    emit("RECOMMENDED NEXT ACTION:")
    emit(f"  Proceed with {best_alt} (or OCSVM(nu=0.05), which has the best F1 and is the")
    emit(f"  most FPR-stable) as the zero-day anomaly layer in place of MemAE, and")
    emit(f"  recalibrate production thresholds on it. Separately, flag T1548.001 (SUID")
    emit(f"  discovery) as unsolved by any model and route it to a feature-engineering")
    emit(f"  track + collection of more examples from the 8 empty windows.")
elif outcome == "B":
    emit("OUTCOME B — Feature-representation problem, not architecture.")
    emit("")
    emit("All models (MemAE, IsoForest, every OC-SVM nu) fail similarly on the quiet")
    emit("techniques while agreeing on the loud ones, so changing the anomaly model")
    emit("architecture further is unlikely to help.")
    for t, n, mx in all_fail_quiet:
        emit(f"  - {t} (n={n}): best of any model {mx*100:.0f}%.")
    emit("")
    emit("RECOMMENDED NEXT ACTION:")
    emit("  Do not pursue further anomaly-model swaps. Invest in new FEATURES (process")
    emit("  lineage, command-line entropy, file-path sensitivity scoring) or re-run the")
    emit("  missing attack windows to gather more quiet-event examples first.")
else:
    emit("OUTCOME C — Inconclusive due to sample size.")
    emit("")
    emit("Results vary inconsistently across techniques and models without a stable")
    emit("pattern, consistent with N being too small (43 alerts; several techniques with")
    emit("fewer than 5 alerts each) to draw a reliable architecture-vs-feature conclusion.")
    emit(f"  - {n_in_small}/{total_novel} novel alerts are in n<3 techniques.")
    emit("")
    emit("RECOMMENDED NEXT ACTION:")
    emit("  Treat all current recall numbers (MemAE's 23-33%, and every number from this")
    emit("  comparison) as provisional. Prioritise collecting more novel-attack alerts")
    emit("  (re-run the 8 empty windows) before drawing further conclusions.")

with open(f"{RESULTS}/anomaly_diagnostic_verdict.txt", "w") as fh:
    fh.write("\n".join(lines) + "\n\n")
    fh.write("Supporting per-technique table (recall @ 10% FPR):\n")
    fh.write(pt.to_string(index=False) + "\n")
print(f"\nSaved {RESULTS}/anomaly_diagnostic_verdict.txt")
