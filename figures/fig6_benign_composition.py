"""
fig6_benign_composition.py -- Fig 6: each platform's fresh benign
collection is dominated by a narrow rule population, and it is not the
same population the attack-side headline recall is scored against for
several rules -- the population-mismatch caveat (A3/A4-style defect,
ew_carrier_classification.md) shown directly as data rather than
restated as prose.

FIG-D F4: axis labels now carry a short rule.description alongside each
rule ID (source: the four raw collection_*.csv files' own `description`
column, first occurrence per rule_id -- these are uninterpretable as
bare numbers otherwise). Caption also states the combined reading across
both panels: Linux benign is 78.3% curl polling three fixed endpoints
(rule 31101, "Web server 400 error code" -- curl hitting non-2xx paths)
plus a file-integrity remainder that is CUPS's own periodic
subscription-lease file rewrite, not human file activity
(art_contamination_check.md / pre_ms_number_fixes.md FIX 1/2) -- the
Linux benign corpus is machine-generated daemon traffic almost end to
end, not human activity. This is the concrete form of this study's
benign-realism limitation, not a new finding -- see captions.md.

Source: newCol/ew_features/ew_augmented_per_alert.csv (source, rule_id
columns), grouped by source in {lnx_benign, win_benign}. Numbers
reproduce figure_inventory.md's own citation of the Windows benign
composition (92004: 38.8%, 60106: 28.9%) exactly. Plotting only -- no
new experiment.
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
RAW_FILES = [
    _p("data/testbed_collection/collection_lnx_alerts.csv"), _p("data/testbed_collection/collection_benign_lnx_alerts.csv"),
    _p("data/testbed_collection/collection_win_alerts.csv"), _p("data/testbed_collection/collection_benign_win_alerts.csv"),
]

df = pd.read_csv(AUG, low_memory=False)
print(f"source: {AUG}")

# rule_id -> short description, sourced from the raw collections' own
# `description` field (first occurrence per rule_id), not fabricated.
desc_by_rule = {}
for path in RAW_FILES:
    raw = pd.read_csv(path)
    print(f"source: {path} (for rule descriptions)")
    for rid, desc in zip(raw["rule_id"], raw["description"]):
        desc_by_rule.setdefault(int(rid), desc)


def short_desc(rid, maxlen=28):
    d = desc_by_rule.get(int(rid), "")
    d = d.rstrip(".")
    return d if len(d) <= maxlen else d[:maxlen - 1] + "…"

TOP_N = 5
panels = {}
for src, platform in [("lnx_benign", "Linux"), ("win_benign", "Windows")]:
    sub = df[df.source == src]
    counts = sub["rule_id"].value_counts(normalize=True) * 100
    top = counts.head(TOP_N)
    other = 100 - top.sum()
    panels[platform] = (top, other, len(sub))
    print(f"  {platform} benign (n={len(sub)}): "
          + ", ".join(f"rule {rid}={pct:.1f}%" for rid, pct in top.items())
          + f", other={other:.1f}%")

# Rules the retracted v8 F1=0.80 headline was scored against (T1110.001
# brute-force, rule_id in {60122, 60204}) -- checked for zero representation,
# not assumed.
win_benign_rules = set(df[df.source == "win_benign"]["rule_id"].unique())
for r in (60122, 60204):
    assert r not in win_benign_rules, f"rule {r} unexpectedly present in win_benign"
print("  confirmed: rules 60122/60204 (v8's T1110.001 brute-force headline) "
      "have zero representation in win_benign")

fig, axes = plt.subplots(1, 2, figsize=(figstyle.DOUBLE_COL_W * 0.85, 3.2))

for ax, platform in zip(axes, ["Linux", "Windows"]):
    top, other, n = panels[platform]
    labels = [f"rule {rid}\n({short_desc(rid)})" for rid in top.index] + ["all other\nrules"]
    vals = list(top.values) + [other]
    colors = figstyle.CATEGORICAL[:len(vals) - 1] + [figstyle.INK_MUTED]
    hatches = figstyle.HATCHES[:len(vals) - 1] + [figstyle.HATCHES[0]]
    bars = ax.bar(labels, vals, color=colors, hatch=hatches,
                   edgecolor=figstyle.INK_PRIMARY, width=0.6, zorder=3)
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:.1f}%", (b.get_x() + b.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 3), ha="center",
                    va="bottom", fontsize=6.5)
    ax.set_ylim(0, 100)
    ax.set_title(f"{platform} benign (n={n})", fontsize=8.5)
    ax.set_ylabel("share of benign alerts (%)" if platform == "Linux" else "")
    ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=5.8)

fig.tight_layout()
figstyle.save(fig, "fig6_benign_composition")
