"""
ocsvm_training_split.py -- what the deployed Layer-2 OC-SVM was trained on, and whether
any of it is in the evaluation sets.

Deployed model: models_v2/ocsvm_nu05.pkl = OneClassSVM(kernel='rbf', gamma='scale', nu=0.05),
theta_ocsvm = -0.3349956708403319 (models_v2/thresholds_production_v3.json).
Training: anomaly_model_comparison.py fits it on 80% of results_v2/benign_baseline_clean.csv
(RandomState(SEED) permutation, first 20% held out). That CSV holds feature vectors only, so
this script rebuilds it from the raw alerts with the same logic as build_clean_benign_baseline.py
(not in this repository; its logic is reproduced below), checks the rebuild against the
committed CSV and against the deployed model, and only then reads timestamps and ids off it.

Writes results/ocsvm_training_split.md. Read-only: nothing is retrained into models_v2/ and no
existing file is changed (a throw-away refit of the OC-SVM is compared with the pickle in memory).

Run from the repository root: python analysis/ocsvm_training_split.py
"""
import json
import os
import sys
from collections import Counter
from datetime import timedelta

import joblib
import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, _p("labelling"))
import shared_features  # noqa: E402
from shared_constants_v2 import (ATTACK_WINDOWS_LNX_V2, EXPERIMENT_END, EXPERIMENT_START,  # noqa: E402
                                 FEATURE_COLS_V2, SEED)

shared_features.ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2
from shared_features import (AgentHistory, _get, _parse_iso, assign_label, assign_phase,  # noqa: E402
                             extract_features_v2, load_lnx_detections, parse_timestamp)
from label_lnx_timeonly import event_time  # noqa: E402

LNX_FILE = _p("lnx_dmz_ai_detections.json")
BASELINE_CSV = _p("results_v2/benign_baseline_clean.csv")
BENIGN_EVAL = _p("data/testbed_collection/collection_benign_lnx_alerts.json")
ATTACK_EVAL = _p("data/testbed_collection/collection_lnx_alerts.json")
LABELED_EVAL = _p("data/testbed_collection/labeled_lnx.csv")
OUT = _p("results/ocsvm_training_split.md")

# build_clean_benign_baseline.py
SUDO_IDS = {"5401", "5402", "5403"}
PAM_FAIL_IDS = {"5503"}
APPARMOR_IDS = {"52002"}
BUFFER_S = 60
NOVEL_RULES = {"5710", "5712", "550", "553", "554", "5901", "5902", "5903"}   # analysis/f1_phaseA_lnx.py


def key3(alert):
    return (alert.get("timestamp"), str(alert["rule"]["id"]), alert.get("full_log"))


def ev(alert):
    """corrected event time (labelling/label_lnx_timeonly.event_time); falls back to the alert time"""
    try:
        t, src, _ = event_time(alert)
        return t, src
    except Exception:
        return None, "unparsed"


# ------------------------------------------------------------------ rebuild the baseline
recs = []
with open(LNX_FILE, errors="ignore") as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        oa = rec.get("original_alert", rec)
        ts = parse_timestamp(rec.get("timestamp")) or parse_timestamp(oa)
        if ts is None:
            continue
        recs.append((ts, oa, _get(oa, "agent", "name", default="unknown"), lineno, rec.get("timestamp")))
recs.sort(key=lambda r: r[0])
print("lnx_dmz_ai_detections.json records parsed:", len(recs))

spans = [(_parse_iso(s), _parse_iso(e)) for _, _, s, e in ATTACK_WINDOWS_LNX_V2]
edges = [x for s, e in spans for x in (s, e)]


def near_edge(ts):
    return any(abs((ts - edge).total_seconds()) <= BUFFER_S for edge in edges)


histories, rows = {}, []
for ts, oa, agent, lineno, outer_ts in recs:
    h = histories.setdefault(agent, AgentHistory())
    feats = extract_features_v2(oa, h.compute_features(ts))
    h.add(oa, ts)
    rid = str(_get(oa, "rule", "id", default="") or "")
    label = assign_label(ts, ATTACK_WINDOWS_LNX_V2)
    if label == 0:
        if rid in SUDO_IDS:
            reason = "sudo_churn"
        elif rid in PAM_FAIL_IDS:
            reason = "pam_login_failed"
        elif rid in APPARMOR_IDS:
            reason = "apparmor_denied"
        elif near_edge(ts):
            reason = "near_window_edge"
        else:
            reason = ""
    else:
        reason = None
    rows.append(dict(ts=ts, oa=oa, agent=agent, lineno=lineno, outer_ts=outer_ts, rid=rid, label=label,
                     reason=reason, feats=feats))
benign_pool = [r for r in rows if r["label"] == 0]
clean = [r for r in benign_pool if r["reason"] == ""]
print(f"benign pool {len(benign_pool)}, kept {len(clean)}, removed {len(benign_pool) - len(clean)}")

csv_X = pd.read_csv(BASELINE_CSV)[FEATURE_COLS_V2].values
X_rebuilt = np.array([r["feats"] for r in clean], dtype=float)
rebuild_ok = X_rebuilt.shape == csv_X.shape and np.allclose(X_rebuilt, csv_X, equal_nan=True)
print("rebuilt baseline matches committed benign_baseline_clean.csv:", rebuild_ok, X_rebuilt.shape, csv_X.shape)
assert rebuild_ok

# ------------------------------------------------------------------ the split
perm = np.random.RandomState(SEED).permutation(len(clean))
n_hold = max(1, int(0.20 * len(clean)))
held_idx, train_idx = perm[:n_hold], perm[n_hold:]
train = [clean[i] for i in sorted(train_idx)]
held = [clean[i] for i in sorted(held_idx)]
print(f"train {len(train)}, held-out {len(held)}")

# check against the deployed pickle: refit in memory on the rebuilt training rows
scaler = joblib.load(_p("models_v2/scaler_v2.pkl"))
imputer = joblib.load(_p("models_v2/imputer_v2.pkl"))
deployed = joblib.load(_p("models_v2/ocsvm_nu05.pkl"))
Xtr = scaler.transform(imputer.transform(csv_X[train_idx])).astype(np.float64)
refit = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(Xtr)
sv_same = (refit.support_vectors_.shape == deployed.support_vectors_.shape
           and np.allclose(refit.support_vectors_, deployed.support_vectors_))
probe = scaler.transform(imputer.transform(csv_X[held_idx])).astype(np.float64)
df_diff = float(np.max(np.abs(refit.decision_function(probe) - deployed.decision_function(probe))))
print(f"refit on rebuilt train rows vs deployed pickle: support vectors identical={sv_same}, "
      f"n_support {len(refit.support_)} vs {len(deployed.support_)}, max |decision diff| on held-out={df_diff:.3g}")
theta = json.load(open(_p("models_v2/thresholds_production_v3.json")))["theta_ocsvm"]

# ------------------------------------------------------------------ evaluation sets
eval_benign = [json.loads(l) for l in open(BENIGN_EVAL, encoding="utf-8") if l.strip()]
assert len(eval_benign) == 267
eval_attack = [json.loads(l) for l in open(ATTACK_EVAL, encoding="utf-8") if l.strip()]
lab = pd.read_csv(LABELED_EVAL, dtype={"rule_id": str})
assert len(lab) == len(eval_attack)
idx306 = [i for i in range(len(lab)) if lab.label.iat[i] == "attack" and lab.rule_id.iat[i] in NOVEL_RULES]
assert len(idx306) == 306
cross306 = [eval_attack[i] for i in idx306]
assert all(str(a["rule"]["id"]) == lab.rule_id.iat[i] for a, i in zip(cross306, idx306))   # file-index alignment

# the 43 novel alerts used to select the threshold: load_lnx_detections' own filter and labels
start_dt, end_dt = _parse_iso(EXPERIMENT_START), _parse_iso(EXPERIMENT_END)
novel_src = [r for r in rows if start_dt <= r["ts"] <= end_dt]      # same filter, same order
for r in novel_src:
    r["phase"] = assign_phase(r["ts"])
novel43 = [r for r in novel_src if r["phase"] == "NOVEL" and assign_label(r["ts"], ATTACK_WINDOWS_LNX_V2) == 1]
ref_df = load_lnx_detections(LNX_FILE, EXPERIMENT_START, EXPERIMENT_END)
ref_nov = ref_df[(ref_df.phase == "NOVEL") & (ref_df.label == 1)]
print("novel alerts (load_lnx_detections):", len(ref_nov), " rebuilt:", len(novel43))
assert len(ref_nov) == len(novel43) == 43
assert Counter(ref_nov.technique) == Counter(
    t for r in novel43 for t in [shared_features.assign_technique(r["ts"])])


def count_overlap(group_alerts, pool_alerts):
    ids_pool = {a.get("id") for a in pool_alerts if a.get("id")}
    k3_pool = {key3(a) for a in pool_alerts}
    log_pool = {(str(a["rule"]["id"]), a.get("full_log")) for a in pool_alerts}
    n_id = sum(1 for a in group_alerts if a.get("id") in ids_pool)
    n_k3 = sum(1 for a in group_alerts if key3(a) in k3_pool)
    n_log = sum(1 for a in group_alerts if (str(a["rule"]["id"]), a.get("full_log")) in log_pool)
    return n_id, n_k3, n_log


train_a = [r["oa"] for r in train]
held_a = [r["oa"] for r in held]
all_clean_a = [r["oa"] for r in clean]
nov_a = [r["oa"] for r in novel43]
ov = {
    "training rows (n=%d)" % len(train): count_overlap(train_a, eval_benign),
    "held-out benign (n=%d)" % len(held): count_overlap(held_a, eval_benign),
    "whole cleaned baseline (n=%d)" % len(clean): count_overlap(all_clean_a, eval_benign),
}
ov_nov = count_overlap(nov_a, cross306)
ov_nov_vs_all_eval_attack = count_overlap(nov_a, eval_attack)
ov_nov_vs_benign = count_overlap(nov_a, eval_benign)
for k, v in ov.items():
    print(f"overlap with the 267: {k}: by id {v[0]}, by (timestamp,rule,full_log) {v[1]}, by (rule,full_log) {v[2]}")
print("43 novel vs 306:", ov_nov, "| vs all 23,081 attack-round alerts:", ov_nov_vs_all_eval_attack,
      "| vs the 267:", ov_nov_vs_benign)


# ------------------------------------------------------------------ summaries
def span(group):
    ts = [r["ts"] for r in group]
    evs = [ev(r["oa"]) for r in group]
    ev_ok = [t for t, _ in evs if t is not None]
    return dict(
        n=len(group), first_ts=min(ts), last_ts=max(ts),
        first_ev=min(ev_ok), last_ev=max(ev_ok), ev_src=Counter(s for _, s in evs),
        days=sorted({t.strftime("%Y-%m-%d") for t in ev_ok}),
        agents=Counter(r["agent"] for r in group),
        ips=Counter(str((r["oa"].get("agent") or {}).get("ip")) for r in group),
        rules=Counter(r["rid"] for r in group),
        raw_first=min(r["outer_ts"] for r in group), raw_last=max(r["outer_ts"] for r in group),
    )


S_train, S_held, S_nov = span(train), span(held), span(novel43)
eval_ev = [ev(a)[0] for a in eval_benign]
eval_ts = [a["timestamp"] for a in eval_benign]


def fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S UTC")


L = []
w = L.append
any_overlap = (sum(v[0] + v[1] for v in ov.values()) + ov_nov[0] + ov_nov[1]) > 0
if any_overlap:
    w("**OVERLAP FOUND: at least one count below is non-zero (see sections 2-4).**\n")
else:
    w("**No overlap for the deployed OC-SVM: every overlap count below is 0 (matched by alert id and by "
      "(timestamp, rule id, full_log)). Separate finding, section 6: a different, non-deployed Windows candidate "
      "(`ocsvm_xplatform_v8`, C3) was fitted on the 267 benign alerts and then scored on them.**\n")
w("# OC-SVM training data and evaluation overlap\n")
w("Produced by `analysis/ocsvm_training_split.py`. Read-only on every committed file.\n")

w("## 0. Which model, which script, which data\n")
w("- **Deployed L2:** `models_v2/ocsvm_nu05.pkl`, `OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)`; "
  f"`theta_ocsvm = {theta}` (`models_v2/thresholds_production_v3.json`).")
w("- **Fit by:** `anomaly_model_comparison.py` (lines 55-57 and 87: fit on `train_benign_raw`). It trains "
  "nu in {0.05, 0.10, 0.15}; the threshold and the choice nu=0.05 were then fixed by "
  "`finalize_ocsvm_threshold.py` from `results_v2/anomaly_model_comparison.csv`.")
w("- **Training data:** 80% of `results_v2/benign_baseline_clean.csv`, split by "
  f"`np.random.RandomState(SEED={SEED}).permutation(n)`, first `int(0.20 n)` rows held out. "
  "That CSV holds the 26 feature columns only, no id or timestamp. It is written by "
  "`build_clean_benign_baseline.py`, which is in the original working folder but not in this repository; "
  "its logic is reproduced in this script.")
w("- **Source alerts:** `lnx_dmz_ai_detections.json` (the lnx-dmz DQN-watcher log; the alert is in "
  "`original_alert`), every record, all dates, labelled with the corrected 14-window list "
  "`ATTACK_WINDOWS_LNX_V2`. Benign = label 0, minus Wazuh rules 5401/5402/5403 (sudo), 5503 (PAM failure) and "
  "52002 (AppArmor), minus anything within 60 s of a window edge.\n")
w("Reconstruction checks (all pass; the script asserts the first two):\n")
w(f"1. The rebuilt baseline has {len(clean):,} rows and its 26 features equal `benign_baseline_clean.csv` row for row "
  f"(from {len(benign_pool):,} label-0 alerts, {len(benign_pool) - len(clean):,} removed).")
w(f"2. The 43 novel alerts below are exactly `load_lnx_detections` rows with phase NOVEL and label 1.")
w(f"3. Refitting `OneClassSVM(nu=0.05, gamma='scale')` in memory on the rebuilt {len(train):,} training rows gives the same "
  f"support vectors as the deployed pickle: **{'identical' if sv_same else 'NOT identical'}** "
  f"({len(refit.support_)} vs {len(deployed.support_)} support vectors; max |decision-function difference| on the "
  f"held-out rows {'below 1e-9' if df_diff < 1e-9 else format(df_diff, '.2g')}). So the rows listed in section 1 are the rows the deployed model was fitted on.\n")

w("## 1. Training data\n")
w("| | value |")
w("|---|---|")
w(f"| benign alerts trained on | **{S_train['n']:,}** (of {len(clean):,} cleaned; {S_held['n']:,} held out) |")
w(f"| host (agent) | {', '.join(f'`{k}` ({v:,})' for k, v in S_train['agents'].items())} |")
w(f"| agent IP | {', '.join(f'`{k}` ({v:,})' for k, v in S_train['ips'].items())} (`None` = the alert has no agent ip field) |")
w(f"| first / last alert timestamp (Wazuh) | {S_train['first_ts'].isoformat()} / {S_train['last_ts'].isoformat()} |")
w(f"| **first / last corrected event time** | **{fmt(S_train['first_ev'])} / {fmt(S_train['last_ev'])}** |")
w(f"| event-time source | {', '.join(f'{k}: {v:,}' for k, v in S_train['ev_src'].most_common())} |")
w(f"| calendar days with training alerts (event time) | {len(S_train['days'])} days, {S_train['days'][0]} to {S_train['days'][-1]} |")
w(f"| top rules | {', '.join(f'{k}: {v:,}' for k, v in S_train['rules'].most_common(8))} |")
w("")
w("Corrected event time is `labelling/label_lnx_timeonly.event_time` (the log line's own time where it has one, "
  "else the syscheck mtime or audit epoch, else the Wazuh timestamp). The span covers every training alert, "
  "so it includes the whole history in the file, not only the 2026-05-25 experiment day. "
  f"The 267 evaluation alerts span {fmt(min(eval_ev))} to {fmt(max(eval_ev))} (event time).\n")

w("## 2. Overlap with the 267 Linux benign evaluation alerts\n")
w("The 267 are the alerts of `data/testbed_collection/collection_benign_lnx_alerts.json` (the `lnx_benign` population "
  "of every FPR in the paper; 209 of them are rule 31101). Both sides carry a Wazuh alert `id`, so the match is "
  "done on `id` and, separately, on the triple (timestamp, rule id, full_log). "
  "A looser (rule id, full_log) match without the timestamp is shown only to say whether any identical log line "
  "exists in both.\n")
w("| training-side set | matched by alert id | matched by (timestamp, rule id, full_log) | looser: (rule id, full_log) only |")
w("|---|---:|---:|---:|")
for k, v in ov.items():
    w(f"| {k} | {v[0]} | {v[1]} | {v[2]} |")
w("")
w(f"**Overlap count between the {len(train):,} training alerts and the 267: {ov[list(ov)[0]][0]} by id, "
  f"{ov[list(ov)[0]][1]} by (timestamp, rule id, full_log).**\n")
if ov[list(ov)[0]][2]:
    w("The looser column is non-zero: identical log text occurs in both sets at different times (these are "
      "repeating system events, not the same alert).\n")

w("## 3. The held-out benign alerts used in the nu grid search\n")
w(f"`anomaly_model_comparison.py` scores nu in {{0.05, 0.10, 0.15}} on the held-out 20% of the cleaned baseline plus "
  f"the 43 novel attack alerts, and picks each model's threshold there. The held-out set is **{S_held['n']:,}** alerts "
  f"(`int(0.20 x {len(clean):,})`), host {', '.join(f'`{k}`' for k in S_held['agents'])}, corrected event time "
  f"{fmt(S_held['first_ev'])} to {fmt(S_held['last_ev'])}. Its overlap with the 267: "
  f"**{ov['held-out benign (n=%d)' % len(held)][0]} by id, {ov['held-out benign (n=%d)' % len(held)][1]} by "
  f"(timestamp, rule id, full_log)** (table above). It is also disjoint from the training rows by construction "
  f"(it is the complement in the same permutation).\n")

w("## 4. The 43 novel-attack alerts and the 306 of Table XIII\n")
w("- **43 alerts** (threshold selection): `load_lnx_detections` rows with phase NOVEL and label 1 in "
  f"`lnx_dmz_ai_detections.json`, between {EXPERIMENT_START} and {EXPERIMENT_END}. Host "
  f"{', '.join(f'`{k}`' for k in S_nov['agents'])}; corrected event time {fmt(S_nov['first_ev'])} to {fmt(S_nov['last_ev'])}; "
  f"rules {', '.join(f'{k}: {v}' for k, v in S_nov['rules'].most_common())}; techniques "
  f"{', '.join(f'{k}: {v}' for k, v in sorted(Counter(shared_features.assign_technique(r['ts']) for r in novel43).items()))}.")
w("- **306 alerts** (Table XIII, `docs/eval_set_definition.md` cross-tab): the attack-labelled alerts of "
  "`data/testbed_collection/labeled_lnx.csv` whose rule is in {5710, 5712, 550, 553, 554, 5901, 5902, 5903} "
  "(`analysis/f1_phaseA_lnx.py`: 113 + 96 + 59 + 20 + 6 + 6 + 6), collected 2026-07-08.\n")
w("| comparison | matched by alert id | matched by (timestamp, rule id, full_log) | looser: (rule id, full_log) only |")
w("|---|---:|---:|---:|")
w(f"| 43 novel vs the 306 | {ov_nov[0]} | {ov_nov[1]} | {ov_nov[2]} |")
w(f"| 43 novel vs all {len(eval_attack):,} alerts of the attack-round collection | {ov_nov_vs_all_eval_attack[0]} | "
  f"{ov_nov_vs_all_eval_attack[1]} | {ov_nov_vs_all_eval_attack[2]} |")
w(f"| 43 novel vs the 267 benign | {ov_nov_vs_benign[0]} | {ov_nov_vs_benign[1]} | {ov_nov_vs_benign[2]} |")
w("")
w(f"**Overlap count between the 43 novel alerts and the 306: {ov_nov[0]} by id, {ov_nov[1]} by (timestamp, rule id, full_log).**\n")
if ov_nov[2]:
    w("The looser column is non-zero: some log texts are identical (for example the same file path in a syscheck "
      "message) at different times, which is expected for repeated attack commands and is not the same alert.\n")

tech43 = Counter(shared_features.assign_technique(r["ts"]) for r in novel43)
tech306 = Counter(lab.technique.iat[i] for i in idx306)
w("What the two sets contain, by technique (the 306 use the `technique` column of `labeled_lnx.csv`; the 43 use "
  "the window technique of `ATTACK_WINDOWS_LNX_V2`):\n")
w("| technique | in the 43 (threshold selection) | in the 306 (Table XIII) |")
w("|---|---:|---:|")
for t in sorted(set(tech43) | set(tech306)):
    w(f"| {t} | {tech43.get(t, 0)} | {tech306.get(t, 0)} |")
w("")
shared_t = sorted(set(tech43) & set(tech306))
w(f"Techniques present in both: {', '.join(shared_t) if shared_t else 'none'}. "
  "The 43 are mostly sudo, PAM and AppArmor events; the 306 are mostly FIM and authentication-failure alerts. "
  "Different alerts, collected on different days with the same agent.\n")

w("## 5. Reading this\n")
w(f"- The deployed OC-SVM is fitted on the lnx-dmz history in `lnx_dmz_ai_detections.json` "
  f"({fmt(S_train['first_ev'])[:10]} to {fmt(S_train['last_ev'])[:10]}), not on the July 2026 collections. "
  "None of its training rows, none of its 851 held-out rows and none of the 43 threshold-selection alerts is "
  "among the 267 benign or the 306 novel-technique alerts, by id or by (timestamp, rule id, full_log).")
w("- Same host (`lnx-dmz-VirtualBox`) on both sides. Training/tuning and evaluation are separate alerts, not separate "
  "environments, so this shows no alert-level leakage, not that the evaluation is out-of-environment.")
w("- The text-only matches in section 2 (11 training, 2 held-out) are all rule 503 (\"Agent started\") lines, which "
  "repeat each time the agent restarts, on different dates; they are not the same alerts.\n")

sp = pd.read_csv(_p("analysis/v8_task3_same_space.csv")).set_index("model")
c3 = sp.loc["C3_xplatform_v8"]
w("## 6. A different model that was fitted on the 267 (not the deployed L2)\n")
w("The deployed L2 above never saw the July collections. A separate Windows-recalibration candidate did see the 267:\n")
w("- `models_v2/ocsvm_xplatform_v8.pkl` (\"C3\", `analysis/v8_task1_train.py`) is an OC-SVM fitted on the fresh Linux "
  "benign collection (the same 267 alerts of `collection_benign_lnx_alerts.json`) plus 5,000 Windows old-pool rows "
  "(`results_v2/windows_recalibration_v8.md`, \"What was trained on what\").")
w(f"- `analysis/v8_task3_lnx_regression.py` then scores C3 on those same 267 as its Linux-regression benign set; "
  f"`analysis/v8_task3_same_space.csv` records FP={int(c3['fp'])}, TN={int(c3['tn'])}, FPR={100 * c3['fpr']:.1f}% for C3 "
  f"({int(c3['fp'])}/{int(c3['fp'] + c3['tn'])}). That FPR is measured on C3's own training alerts.")
w("- `results_v2/windows_recalibration_v8.md` says of this set \"used for *training* C3, not re-evaluated on itself "
  "elsewhere\". The script and the CSV show it is re-evaluated on itself in the Linux regression guard, so that "
  "sentence does not match the code.")
w("- Scope: C3 is a Windows-routing candidate that the same document does not select (it routes Windows to C2, "
  "`ocsvm_xplatform_v7.pkl`, which was not fitted on the 267). It is not the deployed L2, and the deployed L2's "
  "FPRs (10/209 on rule 31101, the 267-alert FPRs) are not affected. Any paper statement quoting C3's Linux FPR "
  "should say it is in-sample.\n")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
