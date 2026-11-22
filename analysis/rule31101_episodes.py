#!/usr/bin/env python3
"""
Episode-level recall / FPR for rule 31101 on the Linux testbed host.

Why: the per-alert recall (465/20,665 = 2.25%) and FPR (10/209 = 4.78%)
treat every alert as an independent trial, but alerts inside a burst are
not independent, so the per-alert Wilson intervals and the two-proportion
z-test (z = 2.445, p = 0.014) may overstate significance. This script
regroups alerts into episodes and re-asks the question at the episode level.

Decision analysed: the deployed v5+defer decision for rule 31101, which is
the L2 OC-SVM flag (ocsvm_score >= theta_ocsvm). L1 is deferred for this
rule (models_v2/rule_confound_fixes_v5.json), so the combined decision
equals the L2 decision; this reproduces 465/20,665 and 10/209 exactly
(asserted below).

Episodes: within each (rule, agent, source IP, label) group, sort by corrected
event time; a new episode starts when the gap to the previous alert is >= G
seconds. Attack and benign alerts are never in the same episode (label is
part of the group key). G is run at {1, 10, 60, 300} -- fixed, all reported.

Outputs (new files only; nothing existing is modified):
  results/rule31101_episodes.csv
  results/rule31101_episodes.md

Run from the repository root:  python analysis/rule31101_episodes.py
"""
import importlib.util
import json
import math
import os
import sys

import numpy as np
import pandas as pd
from scipy.stats import fisher_exact

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE = 31101
G_VALUES = (1, 10, 60, 300)
N_BOOT = 10_000
SEED = 42
ALPHA = 0.05
Z95 = 1.959963984540054


# ---------------------------------------------------------------- load data
def _label_module():
    path = os.path.join(REPO_ROOT, "labelling", "label_lnx_timeonly.py")
    spec = importlib.util.spec_from_file_location("label_lnx_timeonly", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_alerts():
    """One row per rule-31101 alert: label, agent, srcip, corrected event
    time (epoch seconds), and the deployed flag (L2 score >= theta)."""
    theta = json.load(open(os.path.join(REPO_ROOT, "models_v2", "thresholds_production_v3.json")))["theta_ocsvm"]
    comb = pd.read_csv(os.path.join(REPO_ROOT, "analysis", "ew_phase3_31101_per_alert_combined.csv"))

    # ---- attack side: labelled collection (event_time_utc is the time used for labelling)
    lab = pd.read_csv(os.path.join(REPO_ROOT, "data", "testbed_collection", "labeled_lnx.csv"))
    lab = lab[lab["rule_id"] == RULE].reset_index(drop=True)
    comb_a = comb[comb["label"] == "attack"].reset_index(drop=True)
    assert len(lab) == len(comb_a) == 20665, (len(lab), len(comb_a))
    t_lab = pd.to_datetime(lab["event_time_utc"], format="ISO8601", utc=True)
    t_cmb = pd.to_datetime(comb_a["ts"], format="ISO8601", utc=True)
    assert (t_lab.values == t_cmb.values).all(), "attack score rows are not aligned with labelled rows"
    att = pd.DataFrame({
        "label": "attack",
        "agent": lab["agent_name"].fillna("NA"),
        "srcip": lab["srcip"].fillna("NA"),
        "t": t_lab.astype("int64") / 1e9,
        "score": comb_a["ocsvm_score"].values,
    })

    # ---- benign side: dedicated benign collection; event time recovered with
    # the same function the labeller uses (full_log CLF/syslog time first)
    lm = _label_module()
    rows = [json.loads(l) for l in open(os.path.join(REPO_ROOT, "data", "testbed_collection",
                                                     "collection_benign_lnx_alerts.json"))]
    rows = [r for r in rows if r["rule"]["id"] == str(RULE)]
    comb_b = comb[comb["label"] == "benign"].reset_index(drop=True)
    assert len(rows) == len(comb_b) == 209, (len(rows), len(comb_b))
    j_ts = pd.to_datetime([r["timestamp"] for r in rows], format="ISO8601", utc=True)
    c_ts = pd.to_datetime(comb_b["raw_ts"], format="ISO8601", utc=True)
    assert (j_ts.values == c_ts.values).all(), "benign score rows are not aligned with raw alerts"
    ev = [lm.event_time(r) for r in rows]
    ben = pd.DataFrame({
        "label": "benign",
        "agent": [r["agent"]["name"] for r in rows],
        "srcip": [(r.get("data") or {}).get("srcip", "NA") for r in rows],
        "t": [e[0].timestamp() for e in ev],
        "score": comb_b["ocsvm_score"].values,
        "time_source": [e[1] for e in ev],
    })

    df = pd.concat([att, ben], ignore_index=True)
    df["rule"] = RULE
    df["flag"] = (df["score"] >= theta).astype(int)
    assert int(df[df.label == "attack"].flag.sum()) == 465
    assert int(df[df.label == "benign"].flag.sum()) == 10
    return df, theta, ben["time_source"].value_counts().to_dict()


# ---------------------------------------------------------------- episodes
def build_episodes(df, G):
    """Return a DataFrame with one row per episode:
    label, n_alerts, n_flagged, duration_s."""
    out = []
    for (rule, agent, srcip, label), g in df.groupby(["rule", "agent", "srcip", "label"], sort=True):
        g = g.sort_values("t", kind="mergesort")  # stable: ties keep file order
        t = g["t"].values
        f = g["flag"].values
        new = np.ones(len(t), dtype=bool)
        new[1:] = (t[1:] - t[:-1]) >= G
        ep_id = np.cumsum(new) - 1
        n_ep = ep_id[-1] + 1
        n_alerts = np.bincount(ep_id, minlength=n_ep)
        n_flag = np.bincount(ep_id, weights=f, minlength=n_ep).astype(int)
        first = np.full(n_ep, np.inf)
        last = np.full(n_ep, -np.inf)
        np.minimum.at(first, ep_id, t)
        np.maximum.at(last, ep_id, t)
        out.append(pd.DataFrame({"label": label, "agent": agent, "srcip": srcip,
                                 "n_alerts": n_alerts, "n_flagged": n_flag,
                                 "duration_s": last - first}))
    return pd.concat(out, ignore_index=True)


# ---------------------------------------------------------------- statistics
def wilson(k, n, z=Z95):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def two_prop(k1, n1, k2, n2):
    """Pooled two-proportion z-test of rate1 vs rate2 (two-sided).
    Returns z (rate1 - rate2 over pooled SE) and p."""
    p1, p2 = k1 / n1, k2 / n2
    pool = (k1 + k2) / (n1 + n2)
    se = math.sqrt(pool * (1 - pool) * (1 / n1 + 1 / n2))
    if se == 0:
        return float("nan"), float("nan")
    z = (p1 - p2) / se
    p = math.erfc(abs(z) / math.sqrt(2))
    return z, p


def boot_rates(unit_flag, unit_n, rng, B=N_BOOT, chunk=500):
    """Cluster bootstrap over units (episodes). Each resample draws m units
    with replacement and returns sum(flag)/sum(n) -- for episode rates
    unit_n is all ones; for per-alert rates unit_n is the alert count and
    unit_flag the number of flagged alerts."""
    m = len(unit_flag)
    unit_flag = np.asarray(unit_flag, dtype=float)
    unit_n = np.asarray(unit_n, dtype=float)
    out = np.empty(B)
    for s in range(0, B, chunk):
        b = min(chunk, B - s)
        idx = rng.integers(0, m, size=(b, m))
        out[s:s + b] = unit_flag[idx].sum(1) / unit_n[idx].sum(1)
    return out


def pct_ci(x):
    return (float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5)))


def significance(ben_k, ben_n, atk_k, atk_n):
    z, zp = two_prop(ben_k, ben_n, atk_k, atk_n)
    table = [[ben_k, ben_n - ben_k], [atk_k, atk_n - atk_k]]
    min_cell = min(min(r) for r in table)
    fp = float(fisher_exact(table, alternative="two-sided")[1])
    # pre-specified: z-test unless any cell of the 2x2 table is < 5, then Fisher
    test, p = ("fisher", fp) if min_cell < 5 else ("z", zp)
    return dict(z=z, z_p=zp, fisher_p=fp, min_cell=min_cell, decision_test=test, decision_p=p)


# ---------------------------------------------------------------- main
def main():
    df, theta, ben_time_src = load_alerts()
    atk_a = df[df.label == "attack"]
    ben_a = df[df.label == "benign"]
    A_k, A_n = int(atk_a.flag.sum()), len(atk_a)
    B_k, B_n = int(ben_a.flag.sum()), len(ben_a)

    rows = []

    def row(G, unit, a_n, a_k, b_n, b_k, a_boot, b_boot, d_boot, n_atk_ep, n_ben_ep, note=""):
        a_w, b_w = wilson(a_k, a_n), wilson(b_k, b_n)
        sig = significance(b_k, b_n, a_k, a_n)
        diff = b_k / b_n - a_k / a_n
        d_lo, d_hi = d_boot
        benign_gt = diff > 0
        degenerate = (n_atk_ep != "" and min(n_atk_ep, n_ben_ep) == 1)
        if unit == "per_alert" and G != "iid":
            # The independent-alert z / Fisher test is exactly what is in question for these rows,
            # so it is not used for the call: significance = cluster-bootstrap difference CI above 0.
            sig = dict(sig, decision_test="cluster-bootstrap diff CI", decision_p=float("nan"))
            significant = bool(benign_gt and d_lo > 0 and not degenerate)
        else:
            significant = bool(benign_gt and sig["decision_p"] < ALPHA)
        rows.append(dict(
            G_seconds=G, unit=unit, n_attack_episodes=n_atk_ep, n_benign_episodes=n_ben_ep,
            attack_units=a_n, attack_flagged=a_k, attack_rate=a_k / a_n,
            attack_wilson_lo=a_w[0], attack_wilson_hi=a_w[1], attack_boot_lo=a_boot[0], attack_boot_hi=a_boot[1],
            benign_units=b_n, benign_flagged=b_k, benign_rate=b_k / b_n,
            benign_wilson_lo=b_w[0], benign_wilson_hi=b_w[1], benign_boot_lo=b_boot[0], benign_boot_hi=b_boot[1],
            diff_benign_minus_attack=diff, diff_boot_lo=d_lo, diff_boot_hi=d_hi,
            boot_diff_excludes_0=bool(d_lo > 0 or d_hi < 0),
            min_cell=sig["min_cell"], z=sig["z"], z_p_two_sided=sig["z_p"], fisher_p_two_sided=sig["fisher_p"],
            decision_test=sig["decision_test"], decision_p=sig["decision_p"],
            benign_rate_gt_attack_rate=bool(benign_gt),
            significant_benign_gt_attack_0_05=significant,
            note=note,
        ))

    # ---- baseline: every alert treated as an independent trial (the thing in question)
    rng = np.random.default_rng(SEED)
    a_b = rng.binomial(A_n, A_k / A_n, size=N_BOOT) / A_n     # iid bootstrap of a Bernoulli rate
    b_b = rng.binomial(B_n, B_k / B_n, size=N_BOOT) / B_n
    row("iid", "per_alert", A_n, A_k, B_n, B_k, pct_ci(a_b), pct_ci(b_b), pct_ci(b_b - a_b), "", "",
        note="alerts treated as independent; iid bootstrap")

    # ---- episodes
    for G in G_VALUES:
        ep = build_episodes(df, G)
        ea, eb = ep[ep.label == "attack"], ep[ep.label == "benign"]
        n_ea, n_eb = len(ea), len(eb)
        rng = np.random.default_rng(SEED)

        # per-alert rates, resampling episodes (cluster bootstrap)
        a_pa = boot_rates(ea.n_flagged.values, ea.n_alerts.values, rng)
        b_pa = boot_rates(eb.n_flagged.values, eb.n_alerts.values, rng)
        # NOTE: the two classes are resampled independently (they are separate groups)
        row(G, "per_alert", A_n, A_k, B_n, B_k, pct_ci(a_pa), pct_ci(b_pa), pct_ci(b_pa - a_pa), n_ea, n_eb,
            note="rate over alerts; CI by cluster bootstrap over episodes"
                 + ("; DEGENERATE: 1 episode in a class" if min(n_ea, n_eb) == 1 else ""))

        for unit, fa, fb in (
            ("episode_any", (ea.n_flagged >= 1).astype(int).values, (eb.n_flagged >= 1).astype(int).values),
            ("episode_majority", (2 * ea.n_flagged > ea.n_alerts).astype(int).values,
             (2 * eb.n_flagged > eb.n_alerts).astype(int).values),
        ):
            a_e = boot_rates(fa, np.ones(len(fa)), rng)
            b_e = boot_rates(fb, np.ones(len(fb)), rng)
            row(G, unit, n_ea, int(fa.sum()), n_eb, int(fb.sum()), pct_ci(a_e), pct_ci(b_e), pct_ci(b_e - a_e),
                n_ea, n_eb,
                note="DEGENERATE: 1 episode in a class (bootstrap CI collapses to a point)" if min(n_ea, n_eb) == 1 else "")

    res = pd.DataFrame(rows)
    out_dir = os.path.join(REPO_ROOT, "results")
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "rule31101_episodes.csv")
    res.to_csv(csv_path, index=False, float_format="%.6g")
    print(f"wrote {csv_path}")

    # episode-size context for the md
    ctx = {}
    for G in G_VALUES:
        ep = build_episodes(df, G)
        ctx[G] = {lbl: ep[ep.label == lbl].n_alerts.describe()[["count", "min", "50%", "max"]].to_dict()
                  for lbl in ("attack", "benign")}
    write_md(res, ctx, theta, ben_time_src, os.path.join(out_dir, "rule31101_episodes.md"))
    print("wrote", os.path.join(out_dir, "rule31101_episodes.md"))


def fmt_p(p):
    if p != p:  # NaN
        return ""
    return "p<0.001" if p < 0.001 else f"p={p:.3f}"


def write_md(res, ctx, theta, ben_time_src, path):
    base = res[res.G_seconds == "iid"].iloc[0]
    lines = []
    lines.append("# Rule 31101: episode-level recall and FPR\n")
    lines.append(
        "Per-alert recall (465/20,665 = 2.25%) and FPR (10/209 = 4.78%) treat every alert as an independent "
        "trial. Alerts inside a burst are not independent, so this regroups them into episodes and repeats the "
        "comparison. Script: `analysis/rule31101_episodes.py`; full numbers: `results/rule31101_episodes.csv`.\n")
    lines.append("**Setup.** Decision = the deployed v5+defer flag for rule 31101, i.e. the L2 OC-SVM flag "
                 f"(`ocsvm_score >= {theta:.4f}`); L1 is deferred for this rule, so this is the decision that "
                 "reproduces 465/20,665 and 10/209 (asserted in the script). Episodes are built within each "
                 "(rule, agent, source IP, label) group on the corrected event time (the time used for labelling; "
                 "benign event time recovered with the same function from `full_log`, "
                 f"source counts {ben_time_src}); a new episode starts when the gap to the previous alert is "
                 ">= G seconds; attack and benign alerts are never merged. There is one agent and one source IP "
                 "(127.0.0.1) in each class, so each class is a single group and episodes are set by time gaps alone. "
                 "G in {1, 10, 60, 300} s, all reported. \"Any\" = episode flagged if at least one alert is flagged; "
                 "\"majority\" = more than half of its alerts flagged. Bootstrap = 10,000 resamples, seed 42, "
                 "resampling episodes with replacement (separately within each class). Test rule fixed in advance: "
                 "two-sided pooled two-proportion z-test on episode counts, replaced by Fisher's exact test when any "
                 "cell of the 2x2 table is < 5. \"Significant\" = benign rate > attack rate and p < 0.05.\n")

    lines.append("**Baseline (alerts as independent):** attack {}/{} = {:.2%} (Wilson {:.2%}-{:.2%}), benign {}/{} = "
                 "{:.2%} (Wilson {:.2%}-{:.2%}); z = {:.3f}, p = {:.3f}.\n".format(
                     int(base.attack_flagged), int(base.attack_units), base.attack_rate, base.attack_wilson_lo,
                     base.attack_wilson_hi, int(base.benign_flagged), int(base.benign_units), base.benign_rate,
                     base.benign_wilson_lo, base.benign_wilson_hi, base.z, base.z_p_two_sided))

    lines.append("## Table\n")
    lines.append("Rates are flagged/units. Wilson = 95% interval on the counts; Boot = 95% percentile interval, "
                 "resampling episodes. p = test on the 2x2 table (z or Fisher as stated). The per-alert rows keep "
                 "the same alert counts at every G; only their bootstrap interval changes, because the resampling "
                 "unit is the episode.\n")
    lines.append("| G (s) | unit | attack eps | benign eps | attack rate (Wilson; Boot) | benign rate (Wilson; Boot) "
                 "| benign-attack diff, Boot CI | test, p | signif. (benign > attack, p<0.05) |")
    lines.append("|---|---|--:|--:|---|---|---|---|---|")
    for _, r in res.iterrows():
        def cell(k, n, rate, wl, wh, bl, bh):
            return f"{int(k)}/{int(n)} = {rate:.1%} ({wl:.1%}-{wh:.1%}; {bl:.1%}-{bh:.1%})"
        G = "iid" if r.G_seconds == "iid" else int(r.G_seconds)
        lines.append("| {} | {} | {} | {} | {} | {} | {:+.1%} ({:+.1%} to {:+.1%}) | {} {} | {} |".format(
            G, r.unit, r.n_attack_episodes, r.n_benign_episodes,
            cell(r.attack_flagged, r.attack_units, r.attack_rate, r.attack_wilson_lo, r.attack_wilson_hi,
                 r.attack_boot_lo, r.attack_boot_hi),
            cell(r.benign_flagged, r.benign_units, r.benign_rate, r.benign_wilson_lo, r.benign_wilson_hi,
                 r.benign_boot_lo, r.benign_boot_hi),
            r.diff_benign_minus_attack, r.diff_boot_lo, r.diff_boot_hi, r.decision_test, fmt_p(r.decision_p),
            "**yes**" if r.significant_benign_gt_attack_0_05 else "no"))
    lines.append("")

    lines.append("## Episode sizes (alerts per episode)\n")
    lines.append("| G (s) | attack: episodes / median / max | benign: episodes / median / max |")
    lines.append("|--:|---|---|")
    for G, c in ctx.items():
        a, b = c["attack"], c["benign"]
        lines.append(f"| {G} | {int(a['count'])} / {a['50%']:.0f} / {int(a['max'])} | "
                     f"{int(b['count'])} / {b['50%']:.0f} / {int(b['max'])} |")
    lines.append("")

    lines.append("## Does benign flag rate > attack flag rate remain significant at 0.05?\n")
    for G in G_VALUES:
        sub = res[res.G_seconds == G].set_index("unit")
        parts = []
        for unit, name in (("episode_any", "any-flag"), ("episode_majority", "majority-flag")):
            r = sub.loc[unit]
            if r.benign_rate_gt_attack_rate:
                verdict = "YES" if r.significant_benign_gt_attack_0_05 else "NO (benign > attack, but not significant)"
            elif r.diff_benign_minus_attack == 0:
                verdict = "NO (equal rates)"
            else:
                sig_rev = r.decision_p < ALPHA
                verdict = "NO (direction reversed: attack >= benign" + (", and the reversal is significant)" if sig_rev else ")")
            parts.append(f"{name}: {verdict} [{int(r.benign_flagged)}/{int(r.benign_units)} benign vs "
                         f"{int(r.attack_flagged)}/{int(r.attack_units)} attack episodes, {r.decision_test} {fmt_p(r.decision_p)}]")
        pa = sub.loc["per_alert"]
        degenerate = min(pa.n_attack_episodes, pa.n_benign_episodes) == 1
        if degenerate:
            pa_txt = "per-alert rates: cluster bootstrap not estimable (one episode in a class)"
        else:
            pa_txt = ("per-alert rates, cluster-bootstrap difference CI "
                      + ("is above 0 (significant)" if pa.significant_benign_gt_attack_0_05
                         else "includes 0 (not significant)")
                      + f" ({pa.diff_boot_lo:+.1%} to {pa.diff_boot_hi:+.1%})")
        deg = " Degenerate: one episode per class, so no episode-level inference is possible." if degenerate else ""
        lines.append(f"- **G = {G} s** ({int(pa.n_attack_episodes)} attack / {int(pa.n_benign_episodes)} benign "
                     f"episodes): " + "; ".join(parts) + f"; {pa_txt}.{deg}")
    lines.append("")
    lines.append("## Notes\n")
    lines.append("- The \"any\" rule is not neutral: an attack episode contains hundreds to thousands of alerts, each "
                 "flagged with probability about 2%, so almost every attack episode contains at least one flagged "
                 "alert, while a short benign episode usually does not. Read the \"any\" rows with that bias in mind; "
                 "the \"majority\" rows and the per-alert rows are not subject to it.")
    lines.append("- Episode flag rates are not like-for-like across the two classes: attack episodes hold hundreds to "
                 "thousands of alerts (one `dirb` run each) while benign episodes at G = 1 s are single alerts, so an "
                 "episode-level rate partly measures episode size. At G = 1 s a benign episode's flag rate is just the "
                 "per-alert rate (10/209), and an attack episode can essentially never be \"majority\" flagged at a "
                 "~2% per-alert flag rate.")
    lines.append("- Bootstrap percentile intervals collapse to a point when a rate is 0% or 100% (or there is one "
                 "episode); use the Wilson intervals in those cells.")
    lines.append("- Even with alerts treated as independent (the `iid` row), the bootstrap interval for the "
                 "benign-minus-attack difference includes 0, whereas the pooled z-test gives p = 0.014: with only 10 "
                 "flagged benign alerts the benign rate is imprecise, and a pooled-variance test and an "
                 "estimation interval are not the same question. The per-alert significance claim was already marginal "
                 "before any dependence correction.")
    lines.append("- Benign alerts are one polling client (`curl`, three fixed endpoints, 127.0.0.1) in a single "
                 "session, and attack alerts are one `dirb` scan per round, so both classes are few, highly regular "
                 "bursts; episode counts at larger G are small, and intervals are correspondingly wide.")
    lines.append("- Benign `timestamp` (ingestion) precedes the `full_log` event time by about 38 s in that session "
                 "(median), unlike the attack session where ingestion lags the event. Episodes use the event time "
                 "for both classes; a constant offset does not change gaps.")
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
