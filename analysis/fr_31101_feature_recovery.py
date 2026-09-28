"""
fr_31101_feature_recovery.py -- FR-31101: does URL/UA information recover
per-alert separability on rule 31101? ANALYSIS ONLY, new diagnostic models
fit here (not part of the production pipeline, not written back to
models_v2/). No retraining of any existing artifact. Writes
newCol/fr_31101_features.csv and prints everything needed for
newCol/fr_31101_report.md.

Source data: newCol/collection_lnx_alerts.json (attack, 2026-07-08),
newCol/collection_benign_lnx_alerts.json (benign, 2026-07-12). Both
read-only. Rule 31101 does not occur in either Windows collection
(checked directly) -- Linux only.
"""
import json
import math
import re
import sys
from collections import Counter

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import f1_score

HERE = "newCol"

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<httpver>[^"]+)" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def load(path, cls):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            if a.get("rule", {}).get("id") != "31101":
                continue
            full_log = a.get("full_log", "") or ""
            m = LOG_RE.match(full_log)
            if not m:
                raise ValueError(f"unparsed full_log: {full_log!r}")
            rows.append(dict(
                cls=cls, timestamp=a.get("timestamp"),
                path=m.group("path"), method=m.group("method"),
                status=m.group("status"), ua=m.group("ua"),
                referer=m.group("referer"),
            ))
    return rows


atk = load(f"{HERE}/collection_lnx_alerts.json", "attack")
ben = load(f"{HERE}/collection_benign_lnx_alerts.json", "benign")
print(f"attack 31101 n={len(atk)}   benign 31101 n={len(ben)}")

# ---------------------------------------------------------------------
# TASK 1 -- characterise
# ---------------------------------------------------------------------
print("\n" + "=" * 90)
print("TASK 1 -- characterisation")
print("=" * 90)
for name, rows in (("ATTACK", atk), ("BENIGN", ben)):
    print(f"\n-- {name} (n={len(rows)}) --")
    print("  null path:", sum(1 for r in rows if not r["path"]))
    print("  null ua:", sum(1 for r in rows if not r["ua"]))
    print("  distinct paths:", len(set(r["path"] for r in rows)))
    print("  distinct UAs:", len(set(r["ua"] for r in rows)))
    print("  distinct methods:", Counter(r["method"] for r in rows))
    print("  distinct status:", Counter(r["status"] for r in rows))
    print("  query strings present:", sum(1 for r in rows if "?" in r["path"]))
    if len(set(r["path"] for r in rows)) <= 10:
        print("  full path inventory:", Counter(r["path"] for r in rows))
    if len(set(r["ua"] for r in rows)) <= 5:
        print("  full UA inventory:", Counter(r["ua"] for r in rows))

# round boundaries in the attack stream (gap > 30s marks a new dirb round)
atk_sorted = sorted(atk, key=lambda r: r["timestamp"])
ts_atk = pd.to_datetime([r["timestamp"] for r in atk_sorted])
deltas = ts_atk.to_series().diff().dt.total_seconds().values
gap_idx = [i for i, g in enumerate(deltas) if g and g > 30]
print(f"\nattack round boundaries (gap>30s): {gap_idx} -> {len(gap_idx)+1} rounds, "
      f"sizes {[b - a for a, b in zip([0]+gap_idx, gap_idx+[len(atk_sorted)])]}")

BENIGN_SET = {"/api/status", "/contact", "/about"}
CURL_UA = "curl/8.5.0"

# ---------------------------------------------------------------------
# TASK 2 -- tiered feature construction
# ---------------------------------------------------------------------
EXT_GROUPS = {
    "script": {"php", "cgi", "asp", "aspx", "jsp", "pl", "py", "sh"},
    "config": {"conf", "config", "ini", "xml", "yml", "yaml", "env"},
    "backup": {"bak", "old", "swp", "orig", "save", "tmp", "1"},
    "log": {"log"},
}


def ext_class(path):
    base = path.rsplit("/", 1)[-1]
    if "." not in base:
        return "none"
    e = base.rsplit(".", 1)[-1].lower()
    for grp, members in EXT_GROUPS.items():
        if e in members:
            return grp
    return "other" if e else "none"


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


all_rows = atk_sorted + sorted(ben, key=lambda r: r["timestamp"])
df = pd.DataFrame(all_rows)
df["y"] = (df.cls == "attack").astype(int)

# Tier A -- identity / memorization-class
df["A_ua_is_curl"] = (df.ua == CURL_UA).astype(int)
df["A_path_in_benign_set"] = df.path.isin(BENIGN_SET).astype(int)
# exact-identity encodings, fit on TRAIN only (see split below) to avoid
# leaking test-only category codes into train; placeholder columns here,
# filled in after the split is defined.

# Tier B -- structural / generalizable
df["B_path_depth"] = df.path.apply(lambda p: p.strip("/").count("/") + (1 if p.strip("/") else 0))
df["B_path_length"] = df.path.apply(len)
df["B_char_entropy"] = df.path.apply(entropy)
df["B_ext_class_raw"] = df.path.apply(ext_class)
df["B_has_extension"] = (df.B_ext_class_raw != "none").astype(int)
df["B_is_dotfile"] = df.path.apply(lambda p: p.startswith("/.")).astype(int)
df["B_has_query"] = df.path.apply(lambda p: "?" in p).astype(int)
df["B_status_code"] = df.status.astype(int)
df["B_method_is_get"] = (df.method == "GET").astype(int)

ext_map = {e: i for i, e in enumerate(sorted(df.B_ext_class_raw.unique()))}
df["B_ext_class"] = df.B_ext_class_raw.map(ext_map)

print("\n" + "=" * 90)
print("TASK 2 -- Tier B feature variance check (both classes)")
print("=" * 90)
for col in ["B_path_depth", "B_path_length", "B_char_entropy", "B_has_extension",
            "B_is_dotfile", "B_has_query", "B_status_code", "B_method_is_get"]:
    print(f"  {col:<18} attack mean={df[df.y==1][col].mean():.4f}  "
          f"benign mean={df[df.y==0][col].mean():.4f}  "
          f"attack std={df[df.y==1][col].std():.4f}  benign std={df[df.y==0][col].std():.4f}")

# ---------------------------------------------------------------------
# Split -- temporal, per class, matching prior-phase discipline
# ---------------------------------------------------------------------
n_atk_rounds = len(gap_idx) + 1
round6_start = gap_idx[-1]
atk_train_idx = list(range(0, round6_start))
atk_test_idx = list(range(round6_start, len(atk_sorted)))

ben_sorted_idx = list(range(len(atk_sorted), len(atk_sorted) + len(ben)))
n_ben_train = int(0.8 * len(ben))
ben_train_idx = ben_sorted_idx[:n_ben_train]
ben_test_idx = ben_sorted_idx[n_ben_train:]

train_idx = atk_train_idx + ben_train_idx
test_idx = atk_test_idx + ben_test_idx
print(f"\nSPLIT: attack train=rounds 1-5 (n={len(atk_train_idx)}), "
      f"attack test=round 6 (n={len(atk_test_idx)}); "
      f"benign train=first 80% chronological (n={len(ben_train_idx)}), "
      f"benign test=last 20% (n={len(ben_test_idx)})")

train_df = df.iloc[train_idx].copy()
test_df = df.iloc[test_idx].copy()

# Tier A exact-identity encodings, fit on TRAIN vocabulary only; unseen
# test values get a distinct out-of-vocabulary code (-1), never silently
# folded into an existing code.
path_vocab = {p: i for i, p in enumerate(sorted(train_df.path.unique()))}
ua_vocab = {u: i for i, u in enumerate(sorted(train_df.ua.unique()))}
for d in (train_df, test_df):
    d["A_path_id"] = d.path.map(path_vocab).fillna(-1).astype(int)
    d["A_ua_id"] = d.ua.map(ua_vocab).fillna(-1).astype(int)

n_unseen_test_paths = int((test_df.A_path_id == -1).sum())
print(f"test-set alerts whose exact path never appeared in train: "
      f"{n_unseen_test_paths}/{len(test_df)}")

TIER_A = ["A_path_id", "A_ua_id", "A_path_in_benign_set", "A_ua_is_curl"]
TIER_B = ["B_path_depth", "B_path_length", "B_char_entropy", "B_ext_class",
          "B_has_extension", "B_is_dotfile", "B_has_query", "B_status_code",
          "B_method_is_get"]

# ---------------------------------------------------------------------
# TASK 3 -- evaluate each tier separately
# ---------------------------------------------------------------------
def fit_eval(features, tag, params=None):
    p = dict(n_estimators=100, max_depth=4, eval_metric="logloss",
             use_label_encoder=False, random_state=0)
    if params:
        p.update(params)
    clf = xgb.XGBClassifier(**p)
    clf.fit(train_df[features], train_df.y)
    pred = clf.predict(test_df[features])
    y = test_df.y.values
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    f1 = f1_score(y, pred)
    print(f"\n-- {tag} -- TP={tp} FN={fn} FP={fp} TN={tn}  "
          f"recall={recall*100:.2f}%  FPR={fpr*100:.2f}%  F1={f1:.4f}")
    imp = sorted(zip(features, clf.feature_importances_), key=lambda x: -x[1])
    for f, v in imp:
        print(f"    {f:<24} gain-importance={v:.4f}")
    return dict(tag=tag, tp=tp, fn=fn, fp=fp, tn=tn, recall=recall, fpr=fpr, f1=f1,
                importances=imp, clf=clf)


print("\n" + "=" * 90)
print("TASK 3 -- per-tier evaluation")
print("=" * 90)

res_a = fit_eval(TIER_A, "TIER A (identity/memorization)")
res_b = fit_eval(TIER_B, "TIER B (structural)")
res_b_altreg = fit_eval(TIER_B, "TIER B (structural), alt regularization reg_lambda=0/min_child_weight=0",
                         params=dict(reg_lambda=0, min_child_weight=0))

# combined A+B for reference (NOT the deliverable metric -- tiers must stay
# separate per the mandatory-tiering rule; printed only to show it adds
# nothing beyond Tier A alone, not as a blended headline number)
res_ab = fit_eval(TIER_A + TIER_B, "A+B COMBINED (reference only, not a tier)")

# ---------------------------------------------------------------------
# Task 3b -- feature-swap trace on Tier B's top feature (if Tier B
# separates at all) to test scanning-behavior vs disguised-wordlist-identity
# ---------------------------------------------------------------------
print("\n" + "=" * 90)
print("TASK 3b -- feature-swap trace on Tier B's top feature")
print("=" * 90)
top_b_feat = res_b["importances"][0][0] if res_b["importances"][0][1] > 0 else None
print(f"Tier B top feature by gain: {top_b_feat} (importance={res_b['importances'][0][1]:.4f})")

if top_b_feat is not None and res_b["importances"][0][1] > 0:
    benign_typical = train_df[train_df.y == 0][top_b_feat].median()
    print(f"benign-typical (median) value of {top_b_feat}: {benign_typical}")
    swapped = test_df[test_df.y == 1].copy()
    swapped[top_b_feat] = benign_typical
    pred_orig = res_b["clf"].predict(test_df[test_df.y == 1][TIER_B])
    pred_swapped = res_b["clf"].predict(swapped[TIER_B])
    print(f"attack-side Tier-B recall, real {top_b_feat}: {pred_orig.mean()*100:.2f}%")
    print(f"attack-side Tier-B recall, {top_b_feat} swapped to benign-typical: "
          f"{pred_swapped.mean()*100:.2f}%")
else:
    print("Tier B assigns zero importance to every feature -- no swap trace to run "
          "(nothing to swap that the model is using).")

# also swap the ALT-REGULARIZATION model's dominant feature (B_path_depth,
# importance=0.91 there vs 0.05 in the default-reg model) -- the two
# regularizations disagree on which feature matters most, so both must be
# swap-traced, not just the default run's top feature.
top_b_feat_alt = res_b_altreg["importances"][0][0]
if res_b_altreg["importances"][0][1] > 0:
    benign_typical_alt = train_df[train_df.y == 0][top_b_feat_alt].median()
    print(f"\n[alt-reg model] benign-typical (median) value of {top_b_feat_alt}: {benign_typical_alt}")
    swapped2 = test_df[test_df.y == 1].copy()
    swapped2[top_b_feat_alt] = benign_typical_alt
    pred_orig2 = res_b_altreg["clf"].predict(test_df[test_df.y == 1][TIER_B])
    pred_swapped2 = res_b_altreg["clf"].predict(swapped2[TIER_B])
    print(f"[alt-reg] attack-side Tier-B recall, real {top_b_feat_alt}: {pred_orig2.mean()*100:.2f}%")
    print(f"[alt-reg] attack-side Tier-B recall, {top_b_feat_alt} swapped to benign-typical: "
          f"{pred_swapped2.mean()*100:.2f}%")

# breakdown of Tier-B's benign-side FP/TN by exact path, to see whether
# the 66.67% FPR is uniform across the 3-path benign set or concentrated
print("\nTier B (default-reg) benign-test predictions, broken down by exact path:")
ben_test = test_df[test_df.y == 0].copy()
ben_test["pred"] = res_b["clf"].predict(ben_test[TIER_B])
print(ben_test.groupby("path").pred.agg(["count", "sum"]).rename(
    columns={"count": "n", "sum": "n_predicted_attack"}))

# ---------------------------------------------------------------------
# write features CSV
# ---------------------------------------------------------------------
out_cols = ["cls", "timestamp", "path", "ua", "method", "status", "y"] + TIER_A + TIER_B
train_df["split"] = "train"
test_df["split"] = "test"
out_df = pd.concat([train_df, test_df], axis=0)
out_cols.append("split")
out_df[out_cols].to_csv(f"{HERE}/fr_31101_features.csv", index=False)
print(f"\nwrote {HERE}/fr_31101_features.csv ({len(out_df)} rows)")
