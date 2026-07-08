"""Staged multi-agent pipeline for AgentBreaker (recon -> analyse -> attack -> report).

This package implements the architecture in docs/architecture.md Part 2. It is opt-in via
`--engine staged` and reuses the existing harness, judge, providers, taxonomy, belief
state, and findings pipeline as tools -- it changes *who decides*, not how payloads are
sent or scored.

Runtime: LangGraph when installed (`pip install agentbreaker[agents]`); otherwise a thin
built-in sequential orchestrator runs the same stage nodes and loop-back routing, so the
pipeline works (and is testable) without the optional dependency.
"""

from __future__ import annotations

from .contracts import (
    ReconReport,
    AttackObjective,
    AttackPlan,
    AttackResults,
    Report,
)
from .runner import run_staged_campaign

__all__ = [
    "ReconReport",
    "AttackObjective",
    "AttackPlan",
    "AttackResults",
    "Report",
    "run_staged_campaign",
]
