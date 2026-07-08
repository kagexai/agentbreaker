"""Campaign Blackboard -- the shared state passed between pipeline stages.

Implemented as a TypedDict so it can serve directly as LangGraph's `StateGraph` state
schema (nodes return partial dict updates that LangGraph merges). The same dict is used by
the built-in fallback orchestrator, so there is one state shape regardless of runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict

from .contracts import ReconReport, AttackPlan, AttackResults, Report


class Budget(TypedDict, total=False):
    max_experiments: int        # hard ceiling across the whole campaign
    max_replans: int            # bounds Attack -> Analyse loop-back
    experiments_spent: int


class CampaignBlackboard(TypedDict, total=False):
    # Inputs
    target_id: str
    config_path: str
    campaign_tag: str | None
    profile: dict[str, Any]

    # Stage contracts (filled as the graph advances)
    recon: ReconReport
    plan: AttackPlan
    results: AttackResults
    report: Report

    # Control
    budget: Budget
    replan_count: int
    stop: bool
    log: list[str]


def new_blackboard(
    *,
    target_id: str,
    config_path: str | Path,
    profile: dict[str, Any] | None = None,
    campaign_tag: str | None = None,
    max_experiments: int = 50,
    max_replans: int = 2,
) -> CampaignBlackboard:
    return CampaignBlackboard(
        target_id=target_id,
        config_path=str(config_path),
        campaign_tag=campaign_tag,
        profile=profile or {},
        budget=Budget(max_experiments=max_experiments, max_replans=max_replans, experiments_spent=0),
        replan_count=0,
        stop=False,
        log=[],
    )


def remaining_experiments(bb: CampaignBlackboard) -> int:
    b = bb.get("budget", {})
    return max(0, int(b.get("max_experiments", 0)) - int(b.get("experiments_spent", 0)))
