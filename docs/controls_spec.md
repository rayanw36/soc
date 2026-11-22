# Evaluation controls: specification

Source: manuscript Section III-D, Table IX (specification), Table X
(observed verdicts), and Appendix A (pseudocode).

**Numbering.** There are five controls, C1-C5. Earlier drafts listed seven;
the mapping is: C1, C2, C3 unchanged; capture-tempo asymmetry (was C5) is
now C4; post-attack artifact persistence (was C7) is now C5. Small-n
hyperparameter determinism (was C4) and claim provenance (was C6) are kept
as **practices**, not controls (see "Practices" below); their code is in
`controls/practices/`.

The controls are not uniform in kind:

- **Binary (B):** C2, C5. The decision needs no calibration.
- **Structural (S):** C1, C3. The decision is a criterion over
  distributions, stated without a calibrated numeric threshold, because
  calibrating one would need a population of corpora and this study has
  two.
- **Diagnostic (D):** C4. It flags features for C1 and has no
  independent pass/fail.

The set is empirically derived: each control was added where a result in
this study failed. It is not claimed to be exhaustive.

## C1: Benign behavioural class, burst (S)

- **Input:** benign and attack corpora; the rate- or volume-shaped
  feature under test.
- **Statistic:** range of feature values each class occupies; benign
  maximum relative to the attack operating range. For a feature
  censored at a structural ceiling, the share of each class at the
  ceiling.
- **Decision:** FAIL if the benign maximum does not reach the range in
  which attack rows sit. Where the feature is censored at a structural
  ceiling, range overlap is uninformative; compare density at the
  ceiling instead, and FAIL if benign density there is negligible
  relative to attack density.
- **On failure:** the feature is unvalidated. Report it as mechanism
  only, or collect benign data that exercises the behaviour.
- **Falsified:** R1, the global-window rate signal.

```
input: benign[], attack[], feature f
a_lo <- min of f over attack rows
b_hi <- max of f over benign rows
if b_hi < a_lo: return FAIL
if f is capped at value c:
    p_atk <- frac(attack, f >= c)
    p_ben <- frac(benign, f >= c)
    if p_atk is high and p_ben ~ 0: return FAIL
return PASS
```

## C2: Benign behavioural class, failure events (B)

- **Input:** benign corpus; the event class the feature keys on.
- **Statistic:** count of that event class in the benign corpus.
- **Decision:** FAIL if the count is zero.
- **On failure:** the feature is a label proxy. Discard it, or mark the
  population unmeasurable.
- **Falsified:** R2, the Windows brute-force features.

## C3: Rule-composition confounding (S)

- **Input:** the pivot subset on which the feature is computed, split by
  class.
- **Statistic:** per-class rule-identifier composition within the subset.
- **Decision:** FAIL if any rule exceeds half of one class's volume
  within the subset while being absent or negligible in the other.
- **On failure:** the signal is attributable to rule composition, not the
  pivot. Re-test on a composition-matched subset.
- **Falsified:** R3, the cross-platform interarrival feature.

## C4: Capture-tempo asymmetry (D)

- **Input:** attack and benign collections with timestamps.
- **Statistic:** attack-to-benign ratio of mean alert rate and of peak
  alert rate.
- **Decision:** diagnostic only. A ratio far from 1 marks every
  rate-shaped feature in the corpus as suspect and requires each to pass
  C1.
- **On failure:** refer all rate-shaped features to C1; report the ratio
  alongside any result that uses one.
- **Falsified:** R4, the user-block classifier.

## C5: Post-attack artifact persistence (B)

- **Input:** inventory of artifacts each technique created; alerts in the
  benign collection window.
- **Statistic:** exact-path and identifier matches in the benign window;
  interarrival periodicity on affected rules.
- **Decision:** FAIL if any exact artifact path or identifier appears, or
  if benign interarrivals on affected rules show periodicity consistent
  with a scheduled artifact.
- **On failure:** the benign corpus is contaminated. Exclude affected
  alerts, or collect benign data before attack rounds.
- **Falsified:** none; returned negative.

## Practices

Two binary checks are kept as practices rather than controls. They are
not in the controls table (`controls/run_all.py`); their code still runs
(`controls/practices/run_practices.py`).

### Small-n hyperparameter determinism (B)

- **Input:** a fitted model; its training row count; at least two
  hyperparameter settings, including library defaults.
- **Statistic:** the qualitative verdict (and headline metric) under each
  setting.
- **Decision:** FAIL if the qualitative verdict changes across settings.
- **On failure:** the result is determined by hyperparameters and is not
  evidence.
- **Falsified:** the rule-31101 window study (n = 7).

### Claim provenance (B)

- **Input:** every reported claim.
- **Statistic:** whether a named artifact produced the claim.
- **Decision:** FAIL if no artifact can be named.
- **On failure:** the claim is not reported until an artifact produces
  it. Existing occurrences are superseded in place, not deleted.
- **Falsified:** the "endogenous auth aggregates" carrier
  characterisation.

## Expected verdicts (paper Table X)

| ID | Testbed corpus | AIT-ADS |
|---|---|---|
| C1 | fail (benign max 10 of cap 20; 99.2% attack at cap) | pass (32.9% benign at cap) |
| C2 | fail (0/267 Linux, 0/201 Windows auth failures) | pass (auth-failure alerts present) |
| C3 | fail (attack side 55% rule 5710, absent from benign) | not applied |
| C4 | flagged (135.2x mean, 820.8x peak on Linux; 1.5x Windows) | not flagged |
| C5 | pass (0 of 29 FPs match artifacts; irregular interarrivals) | not applicable |

Practices (not controls):

| Practice | Testbed corpus | AIT-ADS |
|---|---|---|
| Small-n hyperparameter determinism | fail (n = 7; verdict flips) | pass (verdict stable across 10 seeds) |
| Claim provenance | fail (1 claim without artifact; historical claim set) | not applied |

## Implementation parameters

The specification above leaves three words unquantified by design: C1's
"high"/"negligible", C3's "negligible", and C4's "far from 1". These
belong to the code, not the paper — the paper deliberately states the
decision rule without a calibrated numeric threshold (see the
Structural/Diagnostic category note above). `controls/` exposes each as
a named, documented parameter:

- `negligible = 0.01` (C1, C3)
- `high = 0.5` (C1)
- `far_from_one = 2.0` (C4)

`controls/run_all.py` sweeps each structural control's parameter over a
small range (`negligible` in `{0, 0.01, 0.05}`) and reports whether any
verdict in the table above changes under that sweep; the result is printed
at the end of its output.
