#!/usr/bin/env python3
"""
XDET Task 2 (unfitted rate thresholds, schema-independent) and
Task 3 (labelling-artefact / signature-exclusivity check), for all three
detectors: Wazuh-native (rule.id != 86601), Suricata (rule.id == 86601,
keyed by rule.description), AMiner (keyed by AnalysisComponentName).

Task 2 rate definition (schema-independent, stated explicitly): per
alert, count of alerts from the SAME detector-subset and SAME scenario
falling in the trailing 60 seconds (inclusive), i.e. a simple per-scenario
sliding count from timestamps alone. This is deliberately NOT the
existing `alert_rate_1min` feature (which is per-agent and buffer-capped
at the last 20 alerts) -- that feature is Wazuh-specific engineering and
is not available/comparable for Suricata's collapsed identity or AMiner's
different agent scheme. This is a structural choice (fixed 60s window),
not selected by looking at performance.

Threshold provenance: the "unfitted" threshold is the 99th percentile of
the BENIGN rate distribution (a structural/percentile rule, computed once
per detector, not tuned against attack recall).

Task 3: for each detector, partitions signatures into "attack-only"
(100% of that signature's alerts fall in labeled attack windows),
"benign-only" (0%), and "mixed", with alert-volume totals per bucket.
"""
import json
import sys
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

sys.path.insert(0, REPO_ROOT)

WAZUH_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_wazuh_recovered_split.npz")
AMINER_NPZ = _os.path.join(REPO_ROOT, "analysis", "xdet_aminer_split.npz")


def rolling_rate_60s(eps, scn):
    """For each alert, count alerts (same scenario) within the trailing
    60s window (inclusive of itself). O(n log n) via sort + two-pointer
    per scenario group."""
    df = pd.DataFrame({"epoch": eps, "scn": scn, "orig_idx": np.arange(len(eps))})
    rates = np.zeros(len(eps), dtype=np.int64)
    for scenario, sub in df.groupby("scn"):
        sub = sub.sort_values("epoch")
        e = sub["epoch"].values
        n = len(e)
        left = 0
        counts = np.zeros(n, dtype=np.int64)
        for right in range(n):
            while e[right] - e[left] > 60:
                left += 1
            counts[right] = right - left + 1
        rates[sub["orig_idx"].values] = counts
    return rates


def rate_stats(rate, y):
    y = np.asarray(y)
    out = {}
    for cls, name in [(0, "benign"), (1, "attack")]:
        r = rate[y == cls]
        if len(r) == 0:
            out[name] = None
            continue
        out[name] = dict(
            n=int(len(r)), mean=float(r.mean()), median=float(np.median(r)),
            p90=float(np.percentile(r, 90)), p95=float(np.percentile(r, 95)),
            p99=float(np.percentile(r, 99)), max=float(r.max()),
        )
    return out


def task2_for_detector(name, eps, scn, y, exclude_mask=None, exclude_label=None):
    print(f"\n{'='*70}\nTASK 2 -- {name}\n{'='*70}")
    results = {}

    def run(eps_, scn_, y_, tag):
        rate = rolling_rate_60s(eps_, scn_)
        stats = rate_stats(rate, y_)
        print(f"  [{tag}] n={len(y_):,}")
        for cls in ("benign", "attack"):
            s = stats[cls]
            if s is None:
                print(f"    {cls}: (none)")
                continue
            print(f"    {cls:7s}: n={s['n']:>9,} mean={s['mean']:.2f} median={s['median']:.2f} "
                  f"p90={s['p90']:.2f} p95={s['p95']:.2f} p99={s['p99']:.2f} max={s['max']:.2f}")
        thr = stats["benign"]["p99"] if stats["benign"] else float("nan")
        frac_attack_above = float((rate[y_ == 1] > thr).mean()) if (y_ == 1).any() else float("nan")
        frac_benign_above = float((rate[y_ == 0] > thr).mean()) if (y_ == 0).any() else float("nan")
        recall = frac_attack_above
        fpr = frac_benign_above
        print(f"    unfitted threshold (benign p99) = {thr:.2f}  -> recall={recall:.4f} FPR={fpr:.4f}")
        return dict(stats=stats, threshold=thr, recall=recall, fpr=fpr, n=len(y_))

    results["all"] = run(eps, scn, y, "ALL DATA")

    if exclude_mask is not None:
        keep = ~exclude_mask
        results[f"excl_{exclude_label}"] = run(
            np.asarray(eps)[keep], np.asarray(scn)[keep], np.asarray(y)[keep],
            f"EXCLUDING {exclude_label}")

    return results


def task3_for_detector(name, sig, y):
    sig = np.asarray(sig, dtype=object)
    y = np.asarray(y)
    print(f"\n{'='*70}\nTASK 3 -- {name}\n{'='*70}")
    buckets = {"attack_only": [], "benign_only": [], "mixed": []}
    vol = {"attack_only": 0, "benign_only": 0, "mixed": 0}
    per_sig = defaultdict(lambda: [0, 0])  # sig -> [benign_n, attack_n]
    for s, yy in zip(sig, y):
        per_sig[s][int(yy)] += 1

    for s, (nb, na) in per_sig.items():
        total = nb + na
        if na > 0 and nb == 0:
            buckets["attack_only"].append(s)
            vol["attack_only"] += total
        elif nb > 0 and na == 0:
            buckets["benign_only"].append(s)
            vol["benign_only"] += total
        else:
            buckets["mixed"].append(s)
            vol["mixed"] += total

    n_total = len(sig)
    for k in buckets:
        print(f"  {k:12s}: {len(buckets[k]):3d} signatures, {vol[k]:>10,} alerts "
              f"({100*vol[k]/n_total:.2f}% of this detector's alerts)")
    if buckets["attack_only"]:
        print(f"    attack-only signatures: {buckets['attack_only']}")

    return dict(
        n_signatures_attack_only=len(buckets["attack_only"]),
        n_signatures_benign_only=len(buckets["benign_only"]),
        n_signatures_mixed=len(buckets["mixed"]),
        alerts_attack_only=vol["attack_only"],
        alerts_benign_only=vol["benign_only"],
        alerts_mixed=vol["mixed"],
        alerts_attack_only_pct=100 * vol["attack_only"] / n_total,
        alerts_benign_only_pct=100 * vol["benign_only"] / n_total,
        alerts_mixed_pct=100 * vol["mixed"] / n_total,
        attack_only_signatures=[str(s) for s in buckets["attack_only"]],
    )


def main():
    out = {}

    wz = np.load(WAZUH_NPZ, allow_pickle=True)
    rid_all, rdesc_all, y_all, scn_all, eps_all = (
        wz["rid_all"], wz["rdesc_all"], wz["y_all"], wz["scn_all"], wz["eps_all"])
    native_mask = rid_all != 86601
    suricata_mask = rid_all == 86601

    out["wazuh_native_task2"] = task2_for_detector(
        "Wazuh-native", eps_all[native_mask], scn_all[native_mask], y_all[native_mask])
    out["wazuh_native_task3"] = task3_for_detector(
        "Wazuh-native", rid_all[native_mask], y_all[native_mask])

    out["suricata_task2"] = task2_for_detector(
        "Suricata (rule 86601)", eps_all[suricata_mask], scn_all[suricata_mask], y_all[suricata_mask])
    out["suricata_task3"] = task3_for_detector(
        "Suricata (rule 86601)", rdesc_all[suricata_mask], y_all[suricata_mask])

    am = np.load(AMINER_NPZ, allow_pickle=True)
    name_all, y_am, scn_am, eps_am = am["name_all"], am["y_all"], am["scn_all"], am["eps_all"]

    # ---- Task 2c: AMiner training-phase FP caveat --------------------------
    # "first half of the first day of each scenario" -- compute per-scenario
    # day-0 start (min epoch across ALL AMiner alerts for that scenario) and
    # flag alerts within the first 12h.
    df_am = pd.DataFrame({"epoch": eps_am, "scn": scn_am, "y": y_am})
    day0_start = df_am.groupby("scn")["epoch"].min().to_dict()
    train_phase_mask = np.array([
        (e - day0_start[s]) <= 12 * 3600 for e, s in zip(eps_am, scn_am)
    ])
    n_in_train_phase = int(train_phase_mask.sum())
    print(f"\n{'='*70}\nTASK 2c -- AMiner training-phase (first 12h of each scenario) check\n{'='*70}")
    print(f"  alerts in first-12h-of-scenario window: {n_in_train_phase:,} / {len(y_am):,} "
          f"({100*n_in_train_phase/len(y_am):.2f}%)")
    print(f"  of those, attack-labeled: {int(y_am[train_phase_mask].sum()):,}  "
          f"benign-labeled: {int((y_am[train_phase_mask]==0).sum()):,}")

    out["aminer_task2"] = task2_for_detector(
        "AMiner", eps_am, scn_am, y_am,
        exclude_mask=train_phase_mask, exclude_label="first12h_training_phase")
    out["aminer_task2"]["training_phase_n"] = n_in_train_phase
    out["aminer_task2"]["training_phase_attack_n"] = int(y_am[train_phase_mask].sum())
    out["aminer_task2"]["training_phase_benign_n"] = int((y_am[train_phase_mask] == 0).sum())

    out["aminer_task3"] = task3_for_detector("AMiner", name_all, y_am)

    def jsonable(o):
        if isinstance(o, dict):
            return {str(k): jsonable(v) for k, v in o.items()}
        if isinstance(o, list):
            return [jsonable(v) for v in o]
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, (np.bool_,)):
            return bool(o)
        return o

    out_path = _os.path.join(REPO_ROOT, "analysis", "xdet_task2_task3_results.json")
    with open(out_path, "w") as f:
        json.dump(jsonable(out), f, indent=2)
    print(f"\nSaved {out_path}")


if __name__ == "__main__":
    main()
