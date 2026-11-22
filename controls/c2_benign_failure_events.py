"""
C2 -- Benign behavioural class, failure events (Binary).

Spec: docs/controls_spec.md. A feature that keys on a specific event
class (e.g. "auth failure") is a label proxy, not a learned signal, if
that event class never occurs in the benign corpus at all -- the model
cannot have learned to distinguish "failure occurred" from "failure
didn't occur" if it never observed a benign failure.
"""
from dataclasses import dataclass


@dataclass
class C2Result:
    verdict: str
    benign_event_count: int
    benign_total: int
    reason: str


def run(benign_event_count: int, benign_total: int) -> C2Result:
    """
    benign_event_count: count of the event class (e.g. auth-failure
        alerts) within the benign corpus.
    benign_total: total alerts in the benign corpus (for context only;
        the decision rule only looks at whether the count is zero).
    """
    verdict = "FAIL" if benign_event_count == 0 else "PASS"
    reason = (f"{benign_event_count} of {benign_total} benign alerts are this event class "
              f"({'zero -- feature is a label proxy' if benign_event_count == 0 else 'nonzero -- measurable'})")
    return C2Result(verdict, benign_event_count, benign_total, reason)
