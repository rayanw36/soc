"""
C3 -- Rule-composition confounding (Structural).

Spec: docs/controls_spec.md. A feature computed on some pivot subset
(e.g. "alerts from this user") can look like it separates attack from
benign purely because one rule dominates one class's slice of the
subset and is absent from the other -- the signal is then about rule
composition, not about the pivot itself.

"Negligible" (how small a share counts as "absent") is left unquantified
by the paper; exposed here as a parameter.
"""
from collections import Counter
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class C3Result:
    verdict: str
    dominant_rule: str
    attack_share: float
    benign_share: float
    reason: str
    params: dict = field(default_factory=dict)


def run(attack_rule_ids: Sequence, benign_rule_ids: Sequence, negligible: float = 0.01) -> C3Result:
    """
    attack_rule_ids, benign_rule_ids: the rule identifier for every
        alert in the pivot subset, split by class.
    negligible: a rule's share of a class counts as "absent or
        negligible" if it is <= this fraction.
    """
    n_attack = len(attack_rule_ids)
    n_benign = len(benign_rule_ids)
    attack_counts = Counter(attack_rule_ids)
    benign_counts = Counter(benign_rule_ids)

    worst_rule, worst_atk_share, worst_ben_share = None, 0.0, 0.0
    for rule in set(list(attack_counts.keys()) + list(benign_counts.keys())):
        atk_share = attack_counts.get(rule, 0) / n_attack if n_attack else 0.0
        ben_share = benign_counts.get(rule, 0) / n_benign if n_benign else 0.0
        dominates_one_side = (atk_share > 0.5 and ben_share <= negligible) or \
                              (ben_share > 0.5 and atk_share <= negligible)
        if dominates_one_side and atk_share > worst_atk_share:
            worst_rule, worst_atk_share, worst_ben_share = rule, atk_share, ben_share

    if worst_rule is not None:
        verdict = "FAIL"
        reason = (f"rule {worst_rule} is {worst_atk_share*100:.1f}% of attack-side volume "
                  f"in this subset but only {worst_ben_share*100:.1f}% of benign-side volume "
                  f"(<= negligible={negligible}) -- signal is rule-composition, not the pivot")
    else:
        verdict = "PASS"
        reason = "no rule exceeds half of one class's volume while being negligible in the other"

    return C3Result(verdict, str(worst_rule), worst_atk_share, worst_ben_share, reason,
                     params=dict(negligible=negligible))
