"""Conditional routing for the Attack -> {Analyse | Report} edge (loop-back)."""

from __future__ import annotations

from typing import Any


def route_after_attack(state: dict[str, Any]) -> str:
    """Return "replan" to loop back to Analyse, or "done" to proceed to Report.

    The replan *bound* is enforced upstream in attack_stage (it only sets
    replan_requested while replan_count < max_replans and budget remains), so this stays a
    pure read of the signal.
    """
    results = state.get("results")
    if results is not None and getattr(results, "replan_requested", False):
        return "replan"
    return "done"
