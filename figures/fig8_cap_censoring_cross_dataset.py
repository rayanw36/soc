"""
fig8_cap_censoring_cross_dataset.py -- Fig 8: the same unfitted control
(alert_rate_1min >= cap) discriminates "partly legitimate signal" from
"pure collection artifact" using only the benign-side distribution --
this project's methodological contribution made visible.

FIG-D F5. Chosen as a STANDALONE figure rather than a third panel on
Fig 5: Fig 5 plots mean alert RATE (a single scalar per round, alerts/s,
using the event-time-corrected `ts` field) across FOUR bars; this figure
plots the FULL per-alert DISTRIBUTION of one specific capped FEATURE
(alert_rate_1min, using the raw-timestamp field production actually
sees, per eval_set_definition.md EW block v4's documented exception) for
the BENIGN class only, across two datasets, with the cap marked. Sharing
one figure would force two different x-axis quantities (a rate in
alerts/s vs. a capped per-alert count) and two different timestamp-field
conventions onto one plot -- clearer as two figures with one point each.

Same unfitted rule both datasets: alert_rate_1min >= 20 (the feature's
hard AgentHistory buffer cap, shared_features.py:157). Applied to the
BENIGN class only in each dataset:
  - AIT-ADS: 32.9% of benign reaches the cap (rule FPR 0.3291) --
    partial signal, not a clean artifact (tempo_ait_check.md).
  - Linux testbed: 0.00% of benign reaches the cap, max value 10 of 20
    (rule FPR 0.0000) -- clean artifact (fig_corrections.md Task 3).
The SAME control, applied the SAME way, gives opposite verdicts purely
from where the benign distribution sits relative to the cap -- that
contrast is the point of this figure.

Source: models_v2/ait_split.npz (AIT-ADS benign rows, y==0) and
newCol/collection_benign_lnx_alerts.csv (Linux benign round), the latter
recomputed alert-by-alert with the exact AgentHistory logic from
shared_features.py (same method as fig_corrections.md Task 3 -- not a
new experiment, a replotting of that already-computed distribution plus
a fresh, equivalent computation for the AIT-ADS side that fig3a's right
panel already summarized as two scalars).
"""
import sys
from collections import deque

sys.path.insert(0, ".")
import figstyle
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
def _p(rel):
    return _os.path.join(REPO_ROOT, rel)
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

AIT_SPLIT = _p("models_v2/ait_split.npz")
LNX_BENIGN = _p("data/testbed_collection/collection_benign_lnx_alerts.csv")
CAP = 20

# --- AIT-ADS benign distribution ---
data = np.load(AIT_SPLIT, allow_pickle=True)
feat_cols = list(data["feature_cols"])
X = np.concatenate([data["X_train"], data["X_test"]], axis=0)
y = np.concatenate([data["y_train"], data["y_test"]], axis=0)
ar_ait_benign = X[y == 0, feat_cols.index("alert_rate_1min")].astype(int)
print(f"source: {AIT_SPLIT}")
print(f"  AIT-ADS benign: n={len(ar_ait_benign)}, frac at cap={float((ar_ait_benign >= CAP).mean()):.4f}")

# --- Linux testbed benign distribution (AgentHistory replication) ---
lnx = pd.read_csv(LNX_BENIGN).sort_values("timestamp").reset_index(drop=True)
ts = pd.to_datetime(lnx["timestamp"])
buf = deque(maxlen=CAP)
rates = []
for cur_ts in ts:
    rate = sum(1 for rts in buf if 0 <= (cur_ts - rts).total_seconds() <= 60)
    rates.append(rate)
    buf.append(cur_ts)
ar_lnx_benign = np.array(rates)
print(f"source: {LNX_BENIGN} (alert_rate_1min recomputed via AgentHistory replication, "
      f"raw timestamp field -- production behavior, per eval_set_definition.md EW block v4)")
print(f"  Linux testbed benign: n={len(ar_lnx_benign)}, frac at cap={float((ar_lnx_benign >= CAP).mean()):.4f}, "
      f"max={ar_lnx_benign.max()}")

fig, axes = plt.subplots(1, 2, figsize=(figstyle.DOUBLE_COL_W * 0.85, 3.0))

panel_data = [
    ("AIT-ADS", ar_ait_benign, 0.3291, "partial signal, not a clean artifact"),
    ("Linux testbed", ar_lnx_benign, 0.0000, "clean artifact"),
]
bins = np.arange(0, CAP + 2) - 0.5
for ax, (name, vals, fpr, verdict) in zip(axes, panel_data):
    ax.hist(vals, bins=bins, color=figstyle.BLUE, edgecolor=figstyle.INK_PRIMARY,
             linewidth=0.5, zorder=3, weights=np.ones(len(vals)) / len(vals) * 100)
    ax.axvline(CAP, color=figstyle.INK_PRIMARY, lw=1.1, ls="--", zorder=4)
    ax.set_xlim(-1, CAP + 1)
    ax.set_xlabel("alert_rate_1min (benign alerts)")
    ax.set_title(f"{name} benign (n={len(vals)})\nrule FPR={fpr:.4f} -- {verdict}", fontsize=7.8)

axes[0].set_ylabel("share of benign alerts (%)")
axes[0].annotate("cap (20)", xy=(CAP, axes[0].get_ylim()[1] * 0.9),
                  xytext=(CAP - 6, axes[0].get_ylim()[1] * 0.9), fontsize=6.5,
                  color=figstyle.INK_SECONDARY, va="center",
                  arrowprops=dict(arrowstyle="->", color=figstyle.INK_MUTED, lw=0.7))

fig.tight_layout()
figstyle.save(fig, "fig8_cap_censoring_cross_dataset")
