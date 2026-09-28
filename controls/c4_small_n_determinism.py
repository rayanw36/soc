"""
C4 -- Small-n hyperparameter determinism (Binary).

Spec: docs/controls_spec.md. Fit the same model family under at least
two hyperparameter settings (including library defaults) and check
whether the qualitative verdict changes. If it does, the result is an
artifact of the hyperparameter choice, not evidence.
"""
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass
class C4Result:
    verdict: str
    verdicts_by_setting: dict
    metrics_by_setting: dict
    reason: str


def run(settings: Sequence[dict], fit_and_score: Callable[[dict], tuple]) -> C4Result:
    """
    settings: a list of hyperparameter dicts to try (must include at
        least one representing the library defaults).
    fit_and_score: a callable(setting_dict) -> (qualitative_verdict: str,
        headline_metric: float). The caller supplies the actual model
        fit/score logic (this control is model-family-agnostic); this
        module only checks whether the returned qualitative verdict is
        stable across settings.
    """
    verdicts, metrics = {}, {}
    for i, setting in enumerate(settings):
        label = setting.get("_label", f"setting_{i}")
        v, m = fit_and_score(setting)
        verdicts[label] = v
        metrics[label] = m

    distinct = set(verdicts.values())
    if len(distinct) > 1:
        verdict = "FAIL"
        reason = f"qualitative verdict changes across settings: {verdicts}"
    else:
        verdict = "PASS"
        reason = f"qualitative verdict stable across all {len(settings)} settings: {distinct.pop()}"

    return C4Result(verdict, verdicts, metrics, reason)


def run_from_precomputed(verdicts_by_setting: dict, metrics_by_setting: dict = None) -> C4Result:
    """Convenience path for when the per-setting fits were already run
    elsewhere (e.g. the multiseed analysis in analysis/rev_task3_multiseed.py)
    and only the resulting verdicts need to be compared -- avoids
    retraining models this control doesn't own."""
    distinct = set(verdicts_by_setting.values())
    if len(distinct) > 1:
        verdict = "FAIL"
        reason = f"qualitative verdict changes across settings: {verdicts_by_setting}"
    else:
        verdict = "PASS"
        reason = f"qualitative verdict stable across all {len(verdicts_by_setting)} settings: {distinct.pop()}"
    return C4Result(verdict, verdicts_by_setting, metrics_by_setting or {}, reason)
