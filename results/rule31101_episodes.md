# Rule 31101: episode-level recall and FPR

Per-alert recall (465/20,665 = 2.25%) and FPR (10/209 = 4.78%) treat every alert as an independent trial. Alerts inside a burst are not independent, so this regroups them into episodes and repeats the comparison. Script: `analysis/rule31101_episodes.py`; full numbers: `results/rule31101_episodes.csv`.

**Setup.** Decision = the deployed v5+defer flag for rule 31101, i.e. the L2 OC-SVM flag (`ocsvm_score >= -0.3350`); L1 is deferred for this rule, so this is the decision that reproduces 465/20,665 and 10/209 (asserted in the script). Episodes are built within each (rule, agent, source IP, label) group on the corrected event time (the time used for labelling; benign event time recovered with the same function from `full_log`, source counts {'full_log_clf': 209}); a new episode starts when the gap to the previous alert is >= G seconds; attack and benign alerts are never merged. There is one agent and one source IP (127.0.0.1) in each class, so each class is a single group and episodes are set by time gaps alone. G in {1, 10, 60, 300} s, all reported. "Any" = episode flagged if at least one alert is flagged; "majority" = more than half of its alerts flagged. Bootstrap = 10,000 resamples, seed 42, resampling episodes with replacement (separately within each class). Test rule fixed in advance: two-sided pooled two-proportion z-test on episode counts, replaced by Fisher's exact test when any cell of the 2x2 table is < 5. "Significant" = benign rate > attack rate and p < 0.05.

**Baseline (alerts as independent):** attack 465/20665 = 2.25% (Wilson 2.06%-2.46%), benign 10/209 = 4.78% (Wilson 2.62%-8.58%); z = 2.445, p = 0.014.

## Table

Rates are flagged/units. Wilson = 95% interval on the counts; Boot = 95% percentile interval, resampling episodes. p = test on the 2x2 table (z or Fisher as stated). The per-alert rows keep the same alert counts at every G; only their bootstrap interval changes, because the resampling unit is the episode.

| G (s) | unit | attack eps | benign eps | attack rate (Wilson; Boot) | benign rate (Wilson; Boot) | benign-attack diff, Boot CI | test, p | signif. (benign > attack, p<0.05) |
|---|---|--:|--:|---|---|---|---|---|
| iid | per_alert |  |  | 465/20665 = 2.3% (2.1%-2.5%; 2.1%-2.5%) | 10/209 = 4.8% (2.6%-8.6%; 1.9%-7.7%) | +2.5% (-0.2% to +5.5%) | z p=0.014 | **yes** |
| 1 | per_alert | 18 | 209 | 465/20665 = 2.3% (2.1%-2.5%; 1.6%-3.1%) | 10/209 = 4.8% (2.6%-8.6%; 1.9%-7.7%) | +2.5% (-0.3% to +5.7%) | cluster-bootstrap diff CI  | no |
| 1 | episode_any | 18 | 209 | 17/18 = 94.4% (74.2%-99.0%; 83.3%-100.0%) | 10/209 = 4.8% (2.6%-8.6%; 1.9%-7.7%) | -89.7% (-97.1% to -76.6%) | fisher p<0.001 | no |
| 1 | episode_majority | 18 | 209 | 0/18 = 0.0% (0.0%-17.6%; 0.0%-0.0%) | 10/209 = 4.8% (2.6%-8.6%; 1.9%-7.7%) | +4.8% (+1.9% to +7.7%) | fisher p=1.000 | no |
| 10 | per_alert | 6 | 84 | 465/20665 = 2.3% (2.1%-2.5%; 2.0%-2.5%) | 10/209 = 4.8% (2.6%-8.6%; 0.0%-11.1%) | +2.5% (-2.2% to +8.8%) | cluster-bootstrap diff CI  | no |
| 10 | episode_any | 6 | 84 | 6/6 = 100.0% (61.0%-100.0%; 100.0%-100.0%) | 3/84 = 3.6% (1.2%-10.0%; 0.0%-8.3%) | -96.4% (-100.0% to -91.7%) | fisher p<0.001 | no |
| 10 | episode_majority | 6 | 84 | 0/6 = 0.0% (0.0%-39.0%; 0.0%-0.0%) | 3/84 = 3.6% (1.2%-10.0%; 0.0%-8.3%) | +3.6% (+0.0% to +8.3%) | fisher p=1.000 | no |
| 60 | per_alert | 6 | 7 | 465/20665 = 2.3% (2.1%-2.5%; 2.0%-2.5%) | 10/209 = 4.8% (2.6%-8.6%; 0.0%-20.6%) | +2.5% (-2.5% to +18.5%) | cluster-bootstrap diff CI  | no |
| 60 | episode_any | 6 | 7 | 6/6 = 100.0% (61.0%-100.0%; 100.0%-100.0%) | 1/7 = 14.3% (2.6%-51.3%; 0.0%-42.9%) | -85.7% (-100.0% to -57.1%) | fisher p=0.005 | no |
| 60 | episode_majority | 6 | 7 | 0/6 = 0.0% (0.0%-39.0%; 0.0%-0.0%) | 0/7 = 0.0% (0.0%-35.4%; 0.0%-0.0%) | +0.0% (+0.0% to +0.0%) | fisher p=1.000 | no |
| 300 | per_alert | 1 | 1 | 465/20665 = 2.3% (2.1%-2.5%; 2.3%-2.3%) | 10/209 = 4.8% (2.6%-8.6%; 4.8%-4.8%) | +2.5% (+2.5% to +2.5%) | cluster-bootstrap diff CI  | no |
| 300 | episode_any | 1 | 1 | 1/1 = 100.0% (20.7%-100.0%; 100.0%-100.0%) | 1/1 = 100.0% (20.7%-100.0%; 100.0%-100.0%) | +0.0% (+0.0% to +0.0%) | fisher p=1.000 | no |
| 300 | episode_majority | 1 | 1 | 0/1 = 0.0% (0.0%-79.3%; 0.0%-0.0%) | 0/1 = 0.0% (0.0%-79.3%; 0.0%-0.0%) | +0.0% (+0.0% to +0.0%) | fisher p=1.000 | no |

## Episode sizes (alerts per episode)

| G (s) | attack: episodes / median / max | benign: episodes / median / max |
|--:|---|---|
| 1 | 18 / 1452 / 2103 | 209 / 1 / 1 |
| 10 | 6 / 3540 / 3806 | 84 / 2 / 6 |
| 60 | 6 / 3540 / 3806 | 7 / 21 / 74 |
| 300 | 1 / 20665 / 20665 | 1 / 209 / 209 |

## Does benign flag rate > attack flag rate remain significant at 0.05?

- **G = 1 s** (18 attack / 209 benign episodes): any-flag: NO (direction reversed: attack >= benign, and the reversal is significant) [10/209 benign vs 17/18 attack episodes, fisher p<0.001]; majority-flag: NO (benign > attack, but not significant) [10/209 benign vs 0/18 attack episodes, fisher p=1.000]; per-alert rates, cluster-bootstrap difference CI includes 0 (not significant) (-0.3% to +5.7%).
- **G = 10 s** (6 attack / 84 benign episodes): any-flag: NO (direction reversed: attack >= benign, and the reversal is significant) [3/84 benign vs 6/6 attack episodes, fisher p<0.001]; majority-flag: NO (benign > attack, but not significant) [3/84 benign vs 0/6 attack episodes, fisher p=1.000]; per-alert rates, cluster-bootstrap difference CI includes 0 (not significant) (-2.2% to +8.8%).
- **G = 60 s** (6 attack / 7 benign episodes): any-flag: NO (direction reversed: attack >= benign, and the reversal is significant) [1/7 benign vs 6/6 attack episodes, fisher p=0.005]; majority-flag: NO (equal rates) [0/7 benign vs 0/6 attack episodes, fisher p=1.000]; per-alert rates, cluster-bootstrap difference CI includes 0 (not significant) (-2.5% to +18.5%).
- **G = 300 s** (1 attack / 1 benign episodes): any-flag: NO (equal rates) [1/1 benign vs 1/1 attack episodes, fisher p=1.000]; majority-flag: NO (equal rates) [0/1 benign vs 0/1 attack episodes, fisher p=1.000]; per-alert rates: cluster bootstrap not estimable (one episode in a class). Degenerate: one episode per class, so no episode-level inference is possible.

## Notes

- The "any" rule is not neutral: an attack episode contains hundreds to thousands of alerts, each flagged with probability about 2%, so almost every attack episode contains at least one flagged alert, while a short benign episode usually does not. Read the "any" rows with that bias in mind; the "majority" rows and the per-alert rows are not subject to it.
- Episode flag rates are not like-for-like across the two classes: attack episodes hold hundreds to thousands of alerts (one `dirb` run each) while benign episodes at G = 1 s are single alerts, so an episode-level rate partly measures episode size. At G = 1 s a benign episode's flag rate is just the per-alert rate (10/209), and an attack episode can essentially never be "majority" flagged at a ~2% per-alert flag rate.
- Bootstrap percentile intervals collapse to a point when a rate is 0% or 100% (or there is one episode); use the Wilson intervals in those cells.
- Even with alerts treated as independent (the `iid` row), the bootstrap interval for the benign-minus-attack difference includes 0, whereas the pooled z-test gives p = 0.014: with only 10 flagged benign alerts the benign rate is imprecise, and a pooled-variance test and an estimation interval are not the same question. The per-alert significance claim was already marginal before any dependence correction.
- Benign alerts are one polling client (`curl`, three fixed endpoints, 127.0.0.1) in a single session, and attack alerts are one `dirb` scan per round, so both classes are few, highly regular bursts; episode counts at larger G are small, and intervals are correspondingly wide.
- Benign `timestamp` (ingestion) precedes the `full_log` event time by about 38 s in that session (median), unlike the attack session where ingestion lags the event. Episodes use the event time for both classes; a constant offset does not change gaps.
