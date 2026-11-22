"""
nonattack_alerts_attack_rounds.py -- the alerts in the attack-round collections that are NOT labelled attack:
Linux 23,081 alerts of which 22,769 attack (so 312 others); Windows 401 of which 336 attack (65 others).

For each platform: what they are (label tier, top rules), where they fall relative to the marked technique
and baseline windows, how they were labelled, and where the labelled data is consumed. Writes
results/nonattack_alerts_attack_rounds.md. Read-only; nothing existing is changed.

Run from the repository root: python analysis/nonattack_alerts_attack_rounds.py
"""
import importlib.util
import os
from collections import Counter

import numpy as np
import pandas as pd

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(rel):
    return os.path.join(REPO_ROOT, rel)


D = "data/testbed_collection/"
OUT = _p("results/nonattack_alerts_attack_rounds.md")


def load_module(name, rel):
    spec = importlib.util.spec_from_file_location(name, _p(rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lnx_mod = load_module("label_lnx_timeonly", "labelling/label_lnx_timeonly.py")
win_mod = load_module("label_win_provenance", "labelling/label_win_provenance.py")

# the label files are written by those scripts; markers are read with the labellers' own parsers
lnx_cs, lnx_ce, lnx_tech, lnx_base = lnx_mod.load_markers()
win_act, win_ce, win_tech, win_base = win_mod.load_markers()

PLAT = {
    "Linux": dict(file="labeled_lnx.csv", tech=lnx_tech, base=lnx_base, first=min(s for s, *_ in lnx_tech),
                  last=max(e for _, e, *_ in lnx_tech), start=lnx_cs, end=lnx_ce),
    "Windows": dict(file="labeled_win.csv", tech=win_tech, base=win_base, first=min(s for s, *_ in win_tech),
                    last=max(e for _, e, *_ in win_tech), start=win_act, end=win_ce),
}


def gap_to_nearest(t, tech):
    best = None
    for s, e, *_ in tech:
        d = 0.0 if s <= t <= e else min(abs((t - s).total_seconds()), abs((t - e).total_seconds()))
        best = d if best is None else min(best, d)
    return best


def position(t, P):
    if any(s <= t <= e for s, e, *_ in P["tech"]):
        return "inside a technique window"
    if any(s <= t < e for s, e, *_ in P["base"]):
        return "inside a 90 s baseline window"
    if t < P["first"]:
        return "before the first technique window"
    if t > P["last"]:
        return "after the last technique window"
    return "between windows (not in a baseline window)"


def vc(series):
    """(value, count) pairs sorted by count, ties broken by value, so the output is identical on every run."""
    return sorted(Counter(series.tolist()).items(), key=lambda kv: (-kv[1], str(kv[0])))


def short(s, n=44):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "..."


report = {}
for plat, P in PLAT.items():
    df = pd.read_csv(_p(D + P["file"]), dtype={"rule_id": str})
    df["t"] = pd.to_datetime(df["event_time_utc"], format="ISO8601", utc=True)
    non = df[df.label != "attack"].copy()
    non["pos"] = [position(t.to_pydatetime(), P) for t in non["t"]]
    non["gap_s"] = [gap_to_nearest(t.to_pydatetime(), P["tech"]) for t in non["t"]]
    report[plat] = dict(df=df, non=non, P=P)
    print(plat, len(df), (df.label == "attack").sum(), len(non), Counter(zip(non.label, non.label_confidence)))
assert len(report["Linux"]["df"]) == 23081 and (report["Linux"]["df"].label == "attack").sum() == 22769
assert len(report["Windows"]["df"]) == 401 and (report["Windows"]["df"].label == "attack").sum() == 336

# ------------------------------------------------------------ where the labelled data is consumed
aug = pd.read_csv(_p("analysis/ew_features/ew_augmented_per_alert.csv"), low_memory=False)
mix = aug.groupby(["source", "label"]).size()
benign_in_attack_src = {"lnx": int(mix.get(("lnx_attack", "benign"), 0)), "win": int(mix.get(("win_attack", "benign"), 0))}
uncertain_in_attack_src = {"lnx": int(mix.get(("lnx_attack", "uncertain"), 0)), "win": int(mix.get(("win_attack", "uncertain"), 0))}
benign_collection = {"lnx": int(mix.get(("lnx_benign", "benign"), 0)), "win": int(mix.get(("win_benign", "benign"), 0))}
print("augmented table:", dict(mix))

# controls/run_all.py C3 pivot subset: platform==lnx & ew_user_present==1 & label in (attack, benign)
piv = aug[(aug["platform"] == "lnx") & (aug["ew_user_present"] == 1) & (aug["label"].isin(["attack", "benign"]))]
piv_benign_by_src = Counter(piv.loc[piv.label == "benign", "source"])
piv_benign_attack_src_rules = Counter(piv.loc[(piv.label == "benign") & (piv.source == "lnx_attack"), "rule_id"])
# controls/run_all.py C5: syscheck_path of the label=='benign' rows of labeled_lnx.csv
lnx_df = report["Linux"]["df"]
c5_paths = int(lnx_df.loc[lnx_df.label == "benign", "syscheck_path"].notna().sum())

# figures/fig5_tempo_asymmetry.py: all rows of source lnx_attack / win_attack, no label filter
def rate(sub):
    ts = pd.to_datetime(sub["ts"], utc=True, format="ISO8601")
    return len(sub) / (ts.max() - ts.min()).total_seconds()


fig5 = {}
for plat, key in (("Linux", "lnx"), ("Windows", "win")):
    a_all = aug[aug.source == f"{key}_attack"]
    a_att = a_all[a_all.label == "attack"]
    b = aug[aug.source == f"{key}_benign"]
    fig5[plat] = dict(n_all=len(a_all), n_att=len(a_att), r_all=rate(a_all), r_att=rate(a_att), r_ben=rate(b))
    print(plat, "fig5 ratio all rows:", fig5[plat]["r_all"] / fig5[plat]["r_ben"],
          " attack-labelled only:", fig5[plat]["r_att"] / fig5[plat]["r_ben"])

# what control C4 (attack-labelled rows only) reports, run live from controls/run_all.py
import sys
sys.path.insert(0, _p("controls"))
c4_spec = importlib.util.spec_from_file_location("run_all", _p("controls/run_all.py"))
c4_mod = importlib.util.module_from_spec(c4_spec)
c4_spec.loader.exec_module(c4_mod)
c4_res, c4_src = c4_mod.c4_testbed()
print("C4 (attack-labelled only):", c4_res.mean_rate_ratio, c4_res.peak_rate_ratio)


def _secs(s):
    return (pd.to_datetime(s, utc=True, format="ISO8601").astype("int64") / 1e9).values


# which choice moves C4's numbers: the attack population, or the benign time field (raw timestamp vs corrected ts)
lx_all = aug[aug.source == "lnx_attack"]
lx_att = lx_all[lx_all.label == "attack"]
lx_ben = aug[aug.source == "lnx_benign"]
ben_raw = pd.read_csv(_p(D + "collection_benign_lnx_alerts.csv"))["timestamp"]
c4_grid = {}
for name, a_ts, b_ts in (
        ("all attack-round rows, corrected `ts` | benign corrected `ts` (Fig. 5 basis)", _secs(lx_all["ts"]), _secs(lx_ben["ts"])),
        ("attack-labelled rows only | benign corrected `ts`", _secs(lx_att["ts"]), _secs(lx_ben["ts"])),
        ("attack-labelled rows only | benign raw `timestamp` (C4 as implemented)", _secs(lx_att["ts"]), _secs(ben_raw))):
    r = c4_mod.C4.run(a_ts, b_ts)
    c4_grid[name] = (r.mean_rate_ratio, r.peak_rate_ratio)
    print("C4 variant:", name, "->", round(r.mean_rate_ratio, 1), r.peak_rate_ratio)

# C3 on the pivot subset with and without the attack-round 'benign' rows
c3_sens = []
pa = piv.loc[piv.label == "attack", "rule_id"].tolist()
pb_all = piv.loc[piv.label == "benign", "rule_id"].tolist()
pb_fresh = piv.loc[(piv.label == "benign") & (piv.source == "lnx_benign"), "rule_id"].tolist()
for negl in (0.0, 0.01, 0.05):
    v_all = c4_mod.C3.run(pa, pb_all, negligible=negl).verdict
    v_fresh = c4_mod.C3.run(pa, pb_fresh, negligible=negl).verdict
    c3_sens.append((negl, v_all, v_fresh))
    print("C3 pivot subset negligible=%s: with the 5: %s ; fresh benign only: %s" % (negl, v_all, v_fresh))

# ------------------------------------------------------------ write
L = []
w = L.append
w("# The non-attack alerts in the attack rounds (Linux 312, Windows 65)\n")
w("Produced by `analysis/nonattack_alerts_attack_rounds.py` from `data/testbed_collection/labeled_lnx.csv` and "
  "`labeled_win.csv`, the collection markers (parsed with the labellers' own `load_markers`), and "
  "`analysis/ew_features/ew_augmented_per_alert.csv`. Read-only.\n")
w("**Short answer.** None of the 377 alerts (312 + 65) was used to train a model, to select a threshold, or in any "
  "FPR. 293 + 62 are labelled `uncertain` and dropped from every metric. The 19 + 3 labelled `benign` are not the "
  "benign class of any FPR (that is the separate benign-only collections, n=267 and n=201); they appear only as "
  "extra members of the benign class in the entity-window leakage audit and the C3 control, and in a path check "
  "(C5) that finds no path in them. All 377 also sit in the per-agent alert history that feeds the 26 features "
  "of their neighbours, and all of them are inside the row counts of the Fig. 5 tempo-asymmetry rates. Details below.\n")

for plat in ("Linux", "Windows"):
    df, non, P = report[plat]["df"], report[plat]["non"], report[plat]["P"]
    nat = (df.label == "attack").sum()
    w(f"## {plat}: {len(df):,} alerts, {nat:,} attack, {len(non)} not attack\n")
    w(f"Marked windows (from the collection markers): {len(P['tech'])} technique windows, {len(P['base'])} baseline windows; "
      f"first technique window starts {P['first']:%Y-%m-%d %H:%M:%S}Z, last ends {P['last']:%H:%M:%S}Z. "
      f"Non-attack alerts span {non['t'].min():%Y-%m-%d %H:%M:%S}Z to {non['t'].max():%H:%M:%S}Z (event time).\n")
    w("How each was labelled (`label_confidence` is the labeller's own tier):\n")
    w("| label | tier (`label_confidence`) | alerts | what it means | top rules (id: alerts) | where it falls | median / max seconds to the nearest technique window |")
    w("|---|---|---:|---|---|---|---|")
    meaning = {
        "UNCERTAIN-artifact-teardown": "alert's own fields name a collection artifact (e.g. `col_cron`, passwd-family files) but it is outside every technique window: attack setup or teardown, deliberately not called benign",
        "UNCERTAIN-session-gap": "inside the collection session, outside every technique and baseline window",
        "UNCERTAIN-out-of-session": "outside the collection session",
        "UNCERTAIN-pre-collection": "before the first window: export padding (the export starts 30 min early)",
        "UNCERTAIN-post-marker": "after the last marked window (the markers stop mid-round 5; alerts continue)",
        "UNCERTAIN-overlap": "inside two technique windows",
        "BENIGN-baseline": "inside a 90 s quiet-baseline window, no collection artifact named, exact event time",
        "BENIGN-baseline-weak": "as BENIGN-baseline but only the Wazuh timestamp is available (18-80 s lag unresolved)",
    }
    for (lab_, conf), g in non.groupby(["label", "label_confidence"], sort=False):
        rules = "; ".join("%s %s: %d" % (r, short(g[g.rule_id == r].rule_description.iloc[0], 30), n)
                          for r, n in vc(g.rule_id)[:4])
        where = "; ".join("%s: %d" % (k, v) for k, v in vc(g.pos))
        w(f"| {lab_} | `{conf}` | {len(g)} | {meaning.get(conf, '')} | {rules} | {where} | "
          f"{g.gap_s.median():.0f} / {g.gap_s.max():.0f} |")
    w("")
    w(f"Whole group, by rule: " + ", ".join("%s: %d" % (r, n) for r, n in vc(non.rule_id)) + ".\n")

w("## Were they used anywhere?\n")
w("Checked by reading every script that reads `labeled_lnx.csv`, `labeled_win.csv`, `ew_augmented_per_alert.csv` or "
  "fits a model on testbed data (grep of the repository), not by assuming.\n")
w("| use | Linux (312: 293 uncertain + 19 benign) | Windows (65: 62 uncertain + 3 benign) |")
w("|---|---|---|")
w("| training of a deployed model (L1 `xgb_model.pkl`, L2 `ocsvm_nu05.pkl`) | no: both were fitted in June 2026, "
  "before the 2026-07-08 collection (L2 on `lnx_dmz_ai_detections.json`, see `results/ocsvm_training_split.md`) | no: same |")
w("| training of any diagnostic model on testbed data | no. `fr_31101_feature_recovery.py`, `ew_phase3_31101_case_study.py` fit on rule 31101 only, and none of the 312 is rule 31101; `ew_phase4_deferral_study.py` fits on attack-labelled and fresh-benign rows only; `v8_task1_train.py` (Windows candidates) uses the old pool and the fresh benign collections | no: same scripts |")
w("| threshold selection | no: thresholds were locked 2026-06-19 (`thresholds_production_v3.json`); Windows candidates calibrate on an old-pool holdout (`v8_task1_train.py`) | no |")
w("| any FPR | no. Every FPR denominator is the benign-only collection (Linux n=267, Windows n=201). `eval_phase4.py` counts the 'benign'-labelled rows and reports FPR as not computable from them | no: same |")
w(f"| attack-side recall | no: attack side is `label == 'attack'` in every script found | no |")
w(f"| control C1 (cap censoring) | context only: the AgentHistory-replicated `alert_rate_1min` is computed over all rows, then masked to attack | not run |")
w(f"| control C2, C4 | no: attack side only (`label == 'attack'`) | not run |")
w(f"| control C3 (rule-share, pivot subset) | **yes, benign class**: the filter is `label in (attack, benign)` with no source filter. Benign members of the pivot subset: {piv_benign_by_src['lnx_benign']} from the benign collection and {piv_benign_by_src['lnx_attack']} from the attack round (rule 5501: {piv_benign_attack_src_rules[5501]}, rule 5402: {piv_benign_attack_src_rules[5402]}). The 293 uncertain are excluded. Dropping those {piv_benign_by_src['lnx_attack']} leaves the C3 verdict unchanged: {'; '.join('negligible=%s: %s with them, %s without' % (n_, a_, b_) for n_, a_, b_ in c3_sens)} | not run |")
w(f"| control C5 (artifact persistence) | `label == 'benign'` rows of `labeled_lnx.csv` are read; {c5_paths} of the 19 carry a `syscheck_path`, so they contribute no path to the check | not run |")
w(f"| `ew_phase2_leakage_audit.py` (entity-window MI) | **yes, benign class**: benign-labelled attack-round rows are kept, uncertain dropped (`n_uncertain_dropped`). Benign class = {benign_in_attack_src['lnx']} + {benign_collection['lnx']} = {benign_in_attack_src['lnx'] + benign_collection['lnx']} Linux; {uncertain_in_attack_src['lnx']} dropped | **yes**: benign class = {benign_in_attack_src['win']} + {benign_collection['win']} = {benign_in_attack_src['win'] + benign_collection['win']}; {uncertain_in_attack_src['win']} dropped |")
w(f"| 26 features of the attack rows (`AgentHistory`) | **yes, as context**: every alert of the session, whatever its label, is added to the per-agent history in event-time order, so the 312 shape `alert_rate_1min`, `rule_diversity_10min` etc. of nearby attack rows | same, over all 401 |")
w(f"| Fig. 5 tempo asymmetry (`fig5_tempo_asymmetry.py`) | **yes**: the attack rate is all rows of source `lnx_attack` (n={fig5['Linux']['n_all']:,}), no label filter. With attack-labelled rows only (n={fig5['Linux']['n_att']:,}) the ratio is {fig5['Linux']['r_att'] / fig5['Linux']['r_ben']:.1f}x instead of {fig5['Linux']['r_all'] / fig5['Linux']['r_ben']:.1f}x | **yes**: all {fig5['Windows']['n_all']} rows; attack-labelled only ({fig5['Windows']['n_att']}) gives {fig5['Windows']['r_att'] / fig5['Windows']['r_ben']:.1f}x instead of {fig5['Windows']['r_all'] / fig5['Windows']['r_ben']:.1f}x |")
w("")
w("## Reading this\n")
w("- The 19 + 3 `benign` rows are not background traffic: `eval_phase4.py` already describes the Linux ones as "
  "attack-script side effects, and the Windows ones are three 'Windows logon success' events inside a baseline window. "
  "They should not be described as benign evaluation data. The benign class of every FPR is the separate collection.")
w("- The two places that do treat them as benign members, the leakage audit's benign class and control C3's pivot subset, "
  "are descriptive (mutual information, rule-share) rather than FPR or recall claims. Whether to drop them there is a "
  "choice for the authors; this report only shows where they enter.")
w("- Fig. 5's 135.2x / 1.5x use all rows of the attack-round files, including the 312 and 65. The two ratios in the "
  "table above show how far restricting to attack-labelled rows would move them.")
w(f"- Control C4 restricts to attack-labelled rows, so it does not reproduce the frozen figures. Run live from "
  f"`controls/run_all.py`, Linux C4 reports a mean-rate ratio of {c4_res.mean_rate_ratio:.1f}x and a peak-rate ratio of "
  f"{c4_res.peak_rate_ratio:.1f}x, not 135.2x / 820.8x, although the source string it prints says it reproduces those. "
  "Recomputed three ways (Linux, mean-rate ratio / peak-rate ratio):\n")
w("| attack population | benign time field | mean-rate ratio | peak-rate ratio |")
w("|---|---|---:|---:|")
for name, (mr, pr) in c4_grid.items():
    pop, ben_f = [x.strip() for x in name.split("|", 1)][0], name.split("|", 1)[1].strip()
    w(f"| {pop} | {ben_f} | {mr:.1f}x | {pr:.1f}x |")
w("")
w("The mean-rate ratio depends on which alerts count as the attack population (the non-attack alerts lie before and "
  "after the labelled attack alerts and lengthen the span): all rows give the frozen 135.2x, attack-labelled rows give "
  "227.5x. The peak-rate ratio is 684.0x in every variant, so none of them reproduces the frozen 820.8x; the cause "
  "of that difference is not determined here. The asymmetry is far above 1 under every variant. The scripts were not "
  "edited; which population the paper should quote is for the authors to decide.")
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(L) + "\n")
print("wrote", OUT)
