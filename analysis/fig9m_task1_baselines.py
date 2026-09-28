#!/usr/bin/env python3
"""
FIG9-M Task 1 -- per-detector lookup/model F1 vs. trivial always-attack
baseline, on the exact eval splits already used by newCol/xdet_task1_results.json.
Read-only: does not retrain anything, only recomputes precision/F1/FPR of
a trivial classifier from the same confusion-matrix denominators already
committed (tp/fp/tn/fn per detector), plus derives the eval-split base
rate from those same counts (not the population-wide attack_rate field,
so the trivial baseline is computed on the identical population the
lookup/model rows are scored on).
"""
import json

with open("analysis/xdet_task1_results.json") as f:
    d = json.load(f)


def trivial_from_counts(tp, fp, tn, fn):
    """Trivial always-predict-attack classifier on a population with
    tp+fn actual attacks and fp+tn actual benign (the same population a
    lookup/model row was scored on)."""
    n_attack = tp + fn
    n_benign = fp + tn
    n = n_attack + n_benign
    precision = n_attack / n  # = base rate
    recall = 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = 1.0  # every benign row is flagged
    return dict(precision=precision, recall=recall, f1=f1, fpr=fpr,
                n_attack=n_attack, n_benign=n_benign, n=n)


rows = []
for det, key in [("Wazuh-native", "wazuh_native"), ("Suricata", "suricata"), ("AMiner", "aminer")]:
    lk = d[key]["lookup"]
    triv = trivial_from_counts(lk["tp"], lk["fp"], lk["tn"], lk["fn"])
    rows.append((det, "lookup", lk["precision"], lk["recall"], lk["f1"], lk["fpr"]))
    rows.append((det, "trivial", triv["precision"], triv["recall"], triv["f1"], triv["fpr"]))
    print(f"{det}: n={triv['n']:,} attack={triv['n_attack']:,} benign={triv['n_benign']:,} "
          f"base_rate={triv['precision']:.6f}")
    print(f"  lookup : P={lk['precision']:.4f} R={lk['recall']:.4f} F1={lk['f1']:.4f} FPR={lk['fpr']:.4f}")
    print(f"  trivial: P={triv['precision']:.4f} R={triv['recall']:.4f} F1={triv['f1']:.4f} FPR={triv['fpr']:.4f}")
    print(f"  lookup F1 - trivial F1 = {lk['f1'] - triv['f1']:+.4f}")

model_map = {
    "Wazuh-native": "Wazuh-native (rule.id != 86601)",
    "Suricata": "Suricata-via-Wazuh (rule.id == 86601)",
}
print()
for det, mk in model_map.items():
    m = d["deployed_model_by_subset"][mk]
    triv = trivial_from_counts(m["tp"], m["fp"], m["tn"], m["fn"])
    rows.append((det, "model", m["precision"], m["recall"], m["f1"], m["fpr"]))
    print(f"{det} model: P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} FPR={m['fpr']:.4f}  "
          f"(model F1 - trivial F1 = {m['f1']-triv['f1']:+.4f})")

with open("analysis/fig9m_task1_results.json", "w") as f:
    json.dump({
        "rows": [{"detector": r[0], "series": r[1], "precision": r[2], "recall": r[3],
                   "f1": r[4], "fpr": r[5]} for r in rows],
    }, f, indent=2)
print("\nSaved newCol/fig9m_task1_results.json")
