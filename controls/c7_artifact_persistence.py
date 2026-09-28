"""
C7 -- Post-attack artifact persistence (Binary).

Spec: docs/controls_spec.md. Checks whether the benign collection window
is contaminated by leftover artifacts from the attack rounds: exact
matches on artifact paths/identifiers, or periodicity in benign-side
interarrivals on the rules those artifacts would fire, consistent with a
still-scheduled task rather than organic activity.
"""
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

import numpy as np


@dataclass
class C7Result:
    verdict: str
    exact_matches: list
    periodicity_flagged: bool
    reason: str
    params: dict = field(default_factory=dict)


def _exact_matches(benign_paths_or_ids: Iterable[str], artifact_inventory: Iterable[str]) -> list:
    inv = set(artifact_inventory)
    return sorted({p for p in benign_paths_or_ids if p in inv})


def _periodicity_flag(interarrivals_s: Optional[np.ndarray], cv_threshold: float = 0.15,
                       min_n: int = 5) -> bool:
    """A low coefficient of variation (std/mean) in interarrival times is
    the signature of a still-running scheduled task rather than organic,
    irregular activity. Requires a minimum sample size to be meaningful."""
    if interarrivals_s is None or len(interarrivals_s) < min_n:
        return False
    ia = np.asarray(interarrivals_s, dtype=float)
    mean = ia.mean()
    if mean <= 0:
        return False
    cv = ia.std() / mean
    return cv <= cv_threshold


def run(benign_paths_or_ids: Sequence[str], artifact_inventory: Sequence[str],
        affected_rule_interarrivals_s: Optional[np.ndarray] = None,
        cv_threshold: float = 0.15) -> C7Result:
    """
    benign_paths_or_ids: every exact path/identifier touched by alerts in
        the benign collection window (e.g. syscheck.path values).
    artifact_inventory: the exact paths/identifiers each attack technique
        is known to have created (from the collection's own command log).
    affected_rule_interarrivals_s: interarrival times (seconds) between
        consecutive benign-window alerts on the rule(s) the artifacts
        would fire, if any exist to check.
    """
    matches = _exact_matches(benign_paths_or_ids, artifact_inventory)
    periodic = _periodicity_flag(affected_rule_interarrivals_s, cv_threshold)

    verdict = "FAIL" if (matches or periodic) else "PASS"
    reason_parts = []
    if matches:
        reason_parts.append(f"{len(matches)} exact artifact path/identifier match(es) in benign window: {matches}")
    else:
        reason_parts.append("0 exact artifact path/identifier matches in benign window")
    if affected_rule_interarrivals_s is not None:
        reason_parts.append(
            f"interarrival periodicity {'FLAGGED (regular, CV<=' + str(cv_threshold) + ')' if periodic else 'not flagged (irregular)'}"
        )
    reason = "; ".join(reason_parts)
    return C7Result(verdict, matches, periodic, reason, params=dict(cv_threshold=cv_threshold))
