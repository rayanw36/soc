#!/usr/bin/env python3
"""
FIG9-M Task 2 -- AMiner model bar. Structural check first (do AMiner
records carry the 26-feature Wazuh vector at all -- no), then a minimal
model on genuinely NON-IDENTITY fields only:
  - raw_log_len: total character length of LogData.RawLogData
  - log_lines_count: LogData.LogLinesCount
  - alert_rate_1min / alerts_10min / time_since_last_alert: causal,
    per-source (AMiner.ID) temporal features, computed the same
    AgentHistory-style forward pass used for the Wazuh 26-feature
    pipeline (shared_features.py), reset per scenario file.

Deliberately EXCLUDED (these are signature identity, in different
forms): AnalysisComponentName, AnalysisComponentType,
AnalysisComponentIdentifier, PersistenceFileName, Message,
AffectedLogAtomPaths/Values. None of the 5 features used here can
recover which AMiner detector fired.

Read-only over data/ait_ads/raw/*_aminer.json and
newCol/xdet_aminer_split.npz (reused for its exact idx_train/idx_test/
y_all, not rebuilt -- this script only adds new non-identity feature
columns aligned to that same split, it does not construct a new split).
"""
import glob
import json
import os
from collections import deque

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score
from xgboost import XGBClassifier

RAW_DIR = "data/ait_ads/raw"
AMINER_SPLIT = "analysis/xdet_aminer_split.npz"
SEED = 42


class SourceHistory:
    def __init__(self, maxlen=20):
        self.buf = deque(maxlen=maxlen)

    def compute(self, ts):
        feats = {"alert_rate_1min": 0, "alerts_10min": 0, "time_since_last_alert": 999.0}
        if ts is None or not self.buf:
            return feats
        last_dt = None
        for rec_ts in self.buf:
            dt = ts - rec_ts
            if dt < 0:
                continue
            if dt <= 60:
                feats["alert_rate_1min"] += 1
            if dt <= 600:
                feats["alerts_10min"] += 1
            if last_dt is None or dt < last_dt:
                last_dt = dt
        if last_dt is not None:
            feats["time_since_last_alert"] = float(last_dt)
        return feats

    def add(self, ts):
        self.buf.append(ts)


def main():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*_aminer.json")))
    assert files, "no aminer files found"

    all_rawlen, all_nlines, all_rate1, all_rate10, all_tslast = [], [], [], [], []
    n_total = 0
    for fp in files:
        histories = {}
        with open(fp, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ld = alert.get("LogData") or {}
                raw = ld.get("RawLogData") or []
                rawlen = sum(len(s) for s in raw) if isinstance(raw, list) else 0
                nlines = ld.get("LogLinesCount", 0) or 0
                dt_vals = ld.get("DetectionTimestamp") or ld.get("Timestamps") or []
                ts = float(dt_vals[0]) if dt_vals else None
                src = (alert.get("AMiner") or {}).get("ID", "unknown")
                hist = histories.setdefault(src, SourceHistory())
                hf = hist.compute(ts)
                if ts is not None:
                    hist.add(ts)
                all_rawlen.append(rawlen)
                all_nlines.append(nlines)
                all_rate1.append(hf["alert_rate_1min"])
                all_rate10.append(hf["alerts_10min"])
                all_tslast.append(hf["time_since_last_alert"])
                n_total += 1
    print(f"Total AMiner alerts (re-parsed, same file order as xdet_build_aminer.py): {n_total:,}")

    X = np.column_stack([
        np.array(all_rawlen, dtype=np.float64),
        np.array(all_nlines, dtype=np.float64),
        np.array(all_rate1, dtype=np.float64),
        np.array(all_rate10, dtype=np.float64),
        np.array(all_tslast, dtype=np.float64),
    ])
    feat_names = ["raw_log_len", "log_lines_count", "alert_rate_1min", "alerts_10min", "time_since_last_alert"]
    print(f"Feature matrix: {X.shape}  columns: {feat_names}")

    split = np.load(AMINER_SPLIT, allow_pickle=True)
    idx_train, idx_test, y_all = split["idx_train"], split["idx_test"], split["y_all"]
    assert len(y_all) == n_total, f"row count mismatch: split has {len(y_all)}, reparse has {n_total}"

    X_train, y_train = X[idx_train], y_all[idx_train]
    X_test, y_test = X[idx_test], y_all[idx_test]
    print(f"train: {X_train.shape}  test: {X_test.shape}")

    # same audit-time XGB_PARAMS convention used throughout this response
    model = XGBClassifier(n_estimators=50, max_depth=5, subsample=0.5,
                           learning_rate=0.1, eval_metric="logloss",
                           random_state=SEED, n_jobs=-1)
    model.fit(X_train, y_train, verbose=False)
    proba = model.predict_proba(X_test)[:, 1]

    def find_best_theta(p, y, n_grid=300):
        best_f1, best_t = 0.0, 0.5
        for t in np.linspace(p.min() + 1e-6, p.max() - 1e-6, n_grid):
            f = f1_score(y, (p >= t).astype(int), zero_division=0)
            if f > best_f1:
                best_f1, best_t = f, t
        return best_t, best_f1

    theta, _ = find_best_theta(proba, y_test)
    pred = (proba >= theta).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = f1_score(y_test, pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"\nMinimal non-identity AMiner model (5 features, no signature identity):")
    print(f"  theta={theta:.5f}  P={precision:.4f}  R={recall:.4f}  F1={f1:.4f}  FPR={fpr:.4f}")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")

    # feature importance for interpretability (not causal, gain-based)
    importances = model.feature_importances_
    for name, imp in sorted(zip(feat_names, importances), key=lambda x: -x[1]):
        print(f"  importance {name}: {imp:.4f}")

    import json as _json
    out = {
        "feature_names": feat_names,
        "n_features": len(feat_names),
        "theta": float(theta),
        "precision": float(precision), "recall": float(recall),
        "f1": float(f1), "fpr": float(fpr),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "feature_importances": {n: float(i) for n, i in zip(feat_names, importances)},
    }
    with open("analysis/fig9m_task2_aminer_model_results.json", "w") as f:
        _json.dump(out, f, indent=2)
    print("\nSaved newCol/fig9m_task2_aminer_model_results.json")


if __name__ == "__main__":
    main()
