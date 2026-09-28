#!/usr/bin/env python3
"""
FIG9-C1 Task 1 -- Control C1 applied to the AMiner non-identity tempo
model's dominant feature (alert_rate_1min, 94.95% of gain per
newCol/fig9m_task2_aminer_model_results.json). Does the benign class
within the SAME split reach the range of values the attack class
occupies? Read-only: re-parses data/ait_ads/raw/*_aminer.json (identical
code path to newCol/fig9m_task2_aminer_model.py) and re-uses
newCol/xdet_aminer_split.npz's idx_train/idx_test/y_all -- no new
collection, no retraining.
"""
import glob
import json
import os
from collections import deque

import numpy as np

RAW_DIR = "data/ait_ads/raw"
AMINER_SPLIT = "analysis/xdet_aminer_split.npz"


class SourceHistory:
    def __init__(self, maxlen=20):
        self.buf = deque(maxlen=maxlen)

    def compute(self, ts):
        rate1 = 0
        if ts is not None:
            for rec_ts in self.buf:
                dt = ts - rec_ts
                if 0 <= dt <= 60:
                    rate1 += 1
        return rate1

    def add(self, ts):
        self.buf.append(ts)


def main():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*_aminer.json")))
    assert files, "no aminer files found"

    all_rate1 = []
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
                dt_vals = ld.get("DetectionTimestamp") or ld.get("Timestamps") or []
                ts = float(dt_vals[0]) if dt_vals else None
                src = (alert.get("AMiner") or {}).get("ID", "unknown")
                hist = histories.setdefault(src, SourceHistory())
                r1 = hist.compute(ts)
                if ts is not None:
                    hist.add(ts)
                all_rate1.append(r1)
                n_total += 1
    print(f"Total AMiner alerts (re-parsed): {n_total:,}")

    rate1 = np.array(all_rate1, dtype=np.float64)

    split = np.load(AMINER_SPLIT, allow_pickle=True)
    idx_train, idx_test, y_all = split["idx_train"], split["idx_test"], split["y_all"]
    assert len(y_all) == n_total

    rate1_eval = rate1[idx_test]
    y_eval = y_all[idx_test]
    n_eval = len(y_eval)
    n_attack = int(y_eval.sum())
    n_benign = int((y_eval == 0).sum())
    print(f"Eval split: n={n_eval:,}  attack={n_attack:,} ({100*n_attack/n_eval:.2f}%)  "
          f"benign={n_benign:,} ({100*n_benign/n_eval:.2f}%)")

    attack_vals = rate1_eval[y_eval == 1]
    benign_vals = rate1_eval[y_eval == 0]

    def stats(vals, label):
        vals_sorted = np.sort(vals)
        d = dict(
            n=len(vals), min=float(vals.min()), median=float(np.median(vals)),
            p90=float(np.percentile(vals, 90)), p95=float(np.percentile(vals, 95)),
            p99=float(np.percentile(vals, 99)), max=float(vals.max()),
        )
        print(f"\n{label}: n={d['n']:,} min={d['min']:.0f} median={d['median']:.1f} "
              f"p90={d['p90']:.1f} p95={d['p95']:.1f} p99={d['p99']:.1f} max={d['max']:.0f}")
        vc = np.unique(vals, return_counts=True)
        n_unique = len(vc[0])
        print(f"  distinct values: {n_unique}")
        if n_unique <= 25:
            for v, c in zip(*vc):
                print(f"    {v:.0f}: {c:,} ({100*c/len(vals):.2f}%)")
        d["value_counts"] = {str(int(v)): int(c) for v, c in zip(*vc)}
        return d

    d_attack = stats(attack_vals, "ATTACK alert_rate_1min")
    d_benign = stats(benign_vals, "BENIGN alert_rate_1min")

    # ---- Task 1b: C1 decision rule ----------------------------------------
    benign_max = d_benign["max"]
    attack_common_lo = d_attack["p90"]   # "the range attack rows commonly occupy" -- read as >=p90
    print(f"\n--- C1 decision rule ---")
    print(f"benign max = {benign_max:.0f}")
    print(f"attack p90 (a plausible reading of 'commonly occupy') = {attack_common_lo:.0f}")
    print(f"attack median = {d_attack['median']:.0f}, attack p99 = {d_attack['p99']:.0f}, attack max = {d_attack['max']:.0f}")
    verdict = "PASS" if benign_max >= attack_common_lo else "FAIL"
    print(f"benign_max >= attack_p90 ? {benign_max >= attack_common_lo}  -> {verdict}")

    # also check against attack median (weaker bar) and against full attack range, for context
    print(f"benign_max >= attack_median ? {benign_max >= d_attack['median']}")
    print(f"benign_max >= attack_max ? {benign_max >= d_attack['max']}")

    # ---- Task 1c: share of attack above benign p99 / benign max -----------
    benign_p99 = d_benign["p99"]
    share_above_p99 = float((attack_vals > benign_p99).mean())
    share_above_max = float((attack_vals > benign_max).mean())
    print(f"\nshare of attack rows > benign p99 ({benign_p99:.1f}): {100*share_above_p99:.2f}%")
    print(f"share of attack rows > benign max ({benign_max:.0f}): {100*share_above_max:.2f}%")

    out = {
        "n_eval": n_eval, "n_attack": n_attack, "n_benign": n_benign,
        "attack": d_attack, "benign": d_benign,
        "verdict": verdict,
        "share_attack_above_benign_p99": share_above_p99,
        "share_attack_above_benign_max": share_above_max,
    }
    with open("analysis/fig9c1_task1_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nSaved newCol/fig9c1_task1_results.json")


if __name__ == "__main__":
    main()
