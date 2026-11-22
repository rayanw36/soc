"""
C1 -- Benign behavioural class, burst (Structural).

Spec: docs/controls_spec.md. Does the benign class ever reach the range
of values the attack class occupies for a rate-/volume-shaped feature?
For a feature censored at a structural ceiling (e.g. a rolling-buffer
cap), range overlap is uninformative on its own (both classes can share
a maximum without sharing a distribution) -- compare density at the
ceiling instead.

The paper leaves "high" and "negligible" unquantified (they would need a
population of corpora to calibrate, and this study has two). This module
exposes them as parameters, not tuned to match the paper's verdicts --
see run_all.py's parameter sweep for whether the verdicts are sensitive
to the exact value chosen.
"""
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class C1Result:
    verdict: str  # "PASS" or "FAIL"
    a_lo: float
    b_hi: float
    range_overlap: bool
    cap: Optional[float] = None
    p_attack_at_cap: Optional[float] = None
    p_benign_at_cap: Optional[float] = None
    reason: str = ""
    params: dict = field(default_factory=dict)


def run(attack: np.ndarray, benign: np.ndarray, cap: Optional[float] = None,
        high: float = 0.5, negligible: float = 0.01) -> C1Result:
    """
    attack, benign: 1-D arrays of the feature's value for each class.
    cap: the feature's structural ceiling, if it has one (e.g. 20 for
         alert_rate_1min, a 20-alert rolling-buffer cap). If None, only
         the range-overlap branch of the spec's pseudocode is used.
    high, negligible: parameters for the censored-feature branch --
         "p_atk is high" means p_attack_at_cap >= high; "p_ben ~ 0" means
         p_benign_at_cap <= negligible.
    """
    attack = np.asarray(attack)
    benign = np.asarray(benign)
    a_lo = float(attack.min())
    b_hi = float(benign.max())
    range_overlap = b_hi >= a_lo

    params = dict(high=high, negligible=negligible, cap=cap)

    if cap is None:
        verdict = "PASS" if range_overlap else "FAIL"
        reason = (f"benign max ({b_hi:g}) {'reaches' if range_overlap else 'does not reach'} "
                  f"the attack operating range (attack min {a_lo:g})")
        return C1Result(verdict, a_lo, b_hi, range_overlap, reason=reason, params=params)

    # censored-feature branch: range overlap alone is uninformative once
    # both classes can be capped at the same ceiling -- compare density.
    p_atk = float((attack >= cap).mean())
    p_ben = float((benign >= cap).mean())
    fails = (p_atk >= high) and (p_ben <= negligible)
    verdict = "FAIL" if fails else "PASS"
    reason = (f"cap={cap:g}: attack density at cap={p_atk:.4f} "
              f"({'>=' if p_atk >= high else '<'} high={high}), "
              f"benign density at cap={p_ben:.4f} "
              f"({'<=' if p_ben <= negligible else '>'} negligible={negligible})")
    return C1Result(verdict, a_lo, b_hi, range_overlap, cap=cap,
                     p_attack_at_cap=p_atk, p_benign_at_cap=p_ben,
                     reason=reason, params=params)
