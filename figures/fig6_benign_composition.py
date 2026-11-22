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

# ---------------------------------------------------------------------------
# Horizontal-bar version (fig6_benign_composition_h). Same data, same top-5
# rules per platform and same "all other rules" bucket as the figure above;
# only the layout changes: horizontal bars, one panel per platform stacked
# vertically at full page width, unrotated y labels "rule id: description",
# and "count (percentage)" printed at the end of each bar. The five named
# rules are ordered by count (descending); the "all other rules" bucket is a
# remainder, not a rule, so it is always drawn last.
# ---------------------------------------------------------------------------
H_FS = dict(tick=7.5, val=7.5, title=8.5, axis=8)


import os.path
import re
import textwrap

all_desc = {}                                  # rule_id -> set of distinct raw descriptions
for path in RAW_FILES:
    raw = pd.read_csv(path)
    for rid, desc in zip(raw["rule_id"], raw["description"]):
        all_desc.setdefault(int(rid), set()).add(desc)


def long_desc(rid, wrap=44):
    """Description for the y label. Backslash runs in the raw text are collapsed to one
    (the CSVs carry them multiply escaped). A rule whose description varies per alert
    (e.g. 92219, one description per DLL name) is shown as the shared prefix, cut at a
    path separator, plus the number of variants. Long labels wrap onto two lines."""
    descs = sorted({re.sub(r"\\+", r"\\", d).rstrip(".") for d in all_desc.get(int(rid), {""})})
    if len(descs) == 1:
        d = descs[0]
    else:
        pre = os.path.commonprefix(descs)
        cut = pre.rfind("\\")
        # shorten to the part before the first long hash-like directory component
        m = re.search(r"\\[0-9a-f]{16,}", pre)
        if m:
            cut = m.start()
        d = pre[:cut + 1] + f"… ({len(descs)} variants)"
    return "\n".join(textwrap.wrap(d, wrap)) if len(d) > wrap else d


fig_h, axes_h = plt.subplots(2, 1, figsize=(figstyle.DOUBLE_COL_W, 4.9))
for ax, platform in zip(axes_h, ["Linux", "Windows"]):
    src = "lnx_benign" if platform == "Linux" else "win_benign"
    sub = df[df.source == src]
    n = len(sub)
    counts = sub["rule_id"].value_counts()
    top_c = counts.head(TOP_N)                       # sorted by count, descending
    other_c = int(counts.iloc[TOP_N:].sum())
    names = [f"{int(rid)}: {long_desc(rid)}" for rid in top_c.index] + ["all other rules"]
    vals = [int(v) for v in top_c.values] + [other_c]
    assert sum(vals) == n
    colors = figstyle.CATEGORICAL[:len(vals) - 1] + [figstyle.INK_MUTED]
    hatches = figstyle.HATCHES[:len(vals) - 1] + [figstyle.HATCHES[0]]
    ypos = list(range(len(vals)))[::-1]              # first (largest) rule at the top
    bars = ax.barh(ypos, vals, color=colors, hatch=hatches, edgecolor=figstyle.INK_PRIMARY,
                   height=0.62, zorder=3)
    for b, v in zip(bars, vals):
        ax.annotate(f"{v} ({100 * v / n:.1f}%)", (v, b.get_y() + b.get_height() / 2),
                    textcoords="offset points", xytext=(4, 0), ha="left", va="center",
                    fontsize=H_FS["val"])
    ax.set_yticks(ypos)
    ax.set_yticklabels(names, fontsize=H_FS["tick"])
    ax.set_xlim(0, max(vals) * 1.28)
    ax.tick_params(axis="x", labelsize=H_FS["tick"])
    ax.set_xlabel("benign alerts (count)", fontsize=H_FS["axis"])
    ax.set_title(f"{platform} benign (n={n})", fontsize=H_FS["title"], loc="left")
    ax.grid(axis="y", visible=False)
    print(f"  [h] {platform} benign (n={n}): "
          + ", ".join(f"{nm.split(':')[0]}={v}" for nm, v in zip(names, vals)))

# fixed margins so both panels start their bars at the same x position
fig_h.subplots_adjust(left=0.40, right=0.97, top=0.95, bottom=0.08, hspace=0.50)
figstyle.save(fig_h, "fig6_benign_composition_h")
