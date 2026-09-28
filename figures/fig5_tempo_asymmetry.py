"""
fig5_tempo_asymmetry.py -- Fig 5: the Linux fresh collection has a 135x
attack:benign capture-tempo asymmetry; Windows does not (1.5x).

This is the mechanism behind every retracted rate/volume-shaped EW finding
on Linux (eval_set_definition.md's Task 1c) and behind why this project's
carrier-classification work treats Linux rate-shaped features as
tempo-contaminated while Windows is not (ew_carrier_classification.md).

FIG-D F1 correction: an earlier draft of this script computed span from
the raw Wazuh alert `timestamp` field in the four `collection_*.csv`
files, giving 136.2x/1.5x -- close to, but not exactly, the frozen
135.2x/1.5x already used throughout eval_set_definition.md,
ew_carrier_classification.md, and the drafted abstract. Root-caused, not
just re-rounded: `timestamp` is Wazuh's alert-ingestion time, which lags
the true event by a VARIABLE 18.2s-80.4s (median ~36s) --
`newCol/label_lnx_timeonly.py`'s own documented reason for building a
corrected `event_time_utc` field. `newCol/ew_features/ew_augmented_per_alert.csv`'s
`ts` column is that corrected value where available (falls back to raw
`timestamp` only when no correction exists) -- built by
`entity_window_extractor_ew.py:build_canonical()`, whose own inline
comment states the preference explicitly: "prefer validated
event_time_utc (eval_set_definition.md methodology)". This script now
uses `ts`, which reproduces the frozen 135.2x/1.5x table exactly (see
fig_followups.md F1 for the full reconciliation and every other
propagation site checked).

Source: `newCol/ew_features/ew_augmented_per_alert.csv` (`source`, `ts`
columns; mean rate = row count / (ts.max() - ts.min()) per `source`
group). No new experiment: descriptive statistics on an already-committed,
already-corrected timestamp field.
"""
import sys

sys.path.insert(0, ".")
import figstyle
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
def _p(rel):
    return _os.path.join(REPO_ROOT, rel)
import matplotlib.pyplot as plt
import pandas as pd

AUG = _p("analysis/ew_features/ew_augmented_per_alert.csv")
SOURCES = {
    ("Linux", "attack"): "lnx_attack",
    ("Linux", "benign"): "lnx_benign",
    ("Windows", "attack"): "win_attack",
    ("Windows", "benign"): "win_benign",
}

print(f"source: {AUG}")
df = pd.read_csv(AUG, low_memory=False)

rates = {}
for (platform, cls), src in SOURCES.items():
    sub = df[df.source == src]
    ts = pd.to_datetime(sub["ts"], utc=True, format="ISO8601")
    span_s = (ts.max() - ts.min()).total_seconds()
    rate = len(sub) / span_s
    rates[(platform, cls)] = rate
    print(f"  {platform} {cls} (source={src}): n={len(sub)}, span={span_s:.3f}s, "
          f"rate={rate:.6f} alerts/s")

ratio_lnx = rates[("Linux", "attack")] / rates[("Linux", "benign")]
ratio_win = rates[("Windows", "attack")] / rates[("Windows", "benign")]
print(f"Linux attack:benign mean-rate ratio = {ratio_lnx:.1f}x "
      f"(eval_set_definition.md Task 1c: 135.2x)")
print(f"Windows attack:benign mean-rate ratio = {ratio_win:.1f}x "
      f"(eval_set_definition.md Task 1c: 1.5x)")

fig, axes = plt.subplots(1, 2, figsize=(figstyle.DOUBLE_COL_W * 0.75, 2.8),
                          sharey=False)

for ax, platform, ratio in zip(axes, ["Linux", "Windows"], [ratio_lnx, ratio_win]):
    vals = [rates[(platform, "attack")], rates[(platform, "benign")]]
    bars = ax.bar(["attack\nround", "benign\nround"], vals,
                   color=[figstyle.RED, figstyle.BLUE],
                   hatch=[figstyle.HATCHES[7], figstyle.HATCHES[0]],
                   edgecolor=figstyle.INK_PRIMARY, width=0.55, zorder=3)
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:.3f}/s", (b.get_x() + b.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 3), ha="center",
                    va="bottom", fontsize=6.5)
    ax.set_title(f"{platform}\nratio = {ratio:.1f}$\\times$", fontsize=8.5)
    ax.set_ylabel("mean alert rate (alerts/s)" if platform == "Linux" else "")

fig.suptitle("")
fig.tight_layout()
figstyle.save(fig, "fig5_tempo_asymmetry")
