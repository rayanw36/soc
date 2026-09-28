"""
C5 -- Capture-tempo asymmetry (Diagnostic).

Spec: docs/controls_spec.md. Diagnostic only -- no independent pass/fail.
Computes the attack:benign ratio of mean and peak alert rate; a ratio far
from 1 marks every rate-shaped feature in the corpus as suspect and
requires each to be checked with C1.
"""
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class C5Result:
    mean_rate_ratio: float
    peak_rate_ratio: Optional[float]
    flagged: bool
    reason: str
    params: dict = field(default_factory=dict)


def _mean_rate(timestamps_sorted_seconds: np.ndarray) -> float:
    span = timestamps_sorted_seconds[-1] - timestamps_sorted_seconds[0]
    return len(timestamps_sorted_seconds) / span if span > 0 else float("nan")


def _peak_rate(timestamps_sorted_seconds: np.ndarray, window_s: float = 10.0) -> float:
    """Max alerts observed in any window_s-second sliding window."""
    ts = timestamps_sorted_seconds
    j = 0
    best = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > window_s:
            j += 1
        best = max(best, i - j + 1)
    return best / window_s


def run(attack_timestamps_s: np.ndarray, benign_timestamps_s: np.ndarray,
        far_from_one: float = 2.0, peak_window_s: float = 10.0) -> C5Result:
    """
    attack_timestamps_s, benign_timestamps_s: sorted (ascending) arrays
        of alert timestamps in seconds (any common epoch), one array per
        class, for the SAME corpus.
    far_from_one: the ratio (or its reciprocal) must exceed this to be
        "flagged" as suspect.
    """
    a = np.sort(np.asarray(attack_timestamps_s, dtype=float))
    b = np.sort(np.asarray(benign_timestamps_s, dtype=float))

    mean_a, mean_b = _mean_rate(a), _mean_rate(b)
    mean_ratio = mean_a / mean_b if mean_b else float("inf")

    try:
        peak_a, peak_b = _peak_rate(a, peak_window_s), _peak_rate(b, peak_window_s)
        peak_ratio = peak_a / peak_b if peak_b else float("inf")
    except Exception:
        peak_ratio = None

    flagged = (mean_ratio >= far_from_one) or (mean_ratio <= 1 / far_from_one) or \
              (peak_ratio is not None and (peak_ratio >= far_from_one or peak_ratio <= 1 / far_from_one))

    reason = (f"mean-rate ratio (attack:benign) = {mean_ratio:.1f}x"
              + (f", peak-rate ratio = {peak_ratio:.1f}x" if peak_ratio is not None else "")
              + (" -- far from 1, every rate-shaped feature in this corpus is suspect (refer to C1)"
                 if flagged else " -- not far from 1"))
    return C5Result(mean_ratio, peak_ratio, flagged, reason, params=dict(far_from_one=far_from_one))
