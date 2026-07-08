"""Pipeline assembly.

Primary runtime is LangGraph: a StateGraph whose nodes are the stages, with a conditional
edge implementing Attack -> {Analyse | Report} loop-back. When LangGraph is not installed,
`run_pipeline` falls back to a built-in sequential orchestrator that executes the exact
same node functions and routing, so the pipeline runs (and is testable) either way.
"""

from __future__ import annotations

import logging
from typing import Any

from .blackboard import CampaignBlackboard
from .stages import (
    recon_stage, analyse_stage, attack_stage, report_stage, route_after_attack,
)

logger = logging.getLogger(__name__)

# Safety cap for the fallback loop (LangGraph has its own recursion_limit).
_MAX_NODE_STEPS = 50


def langgraph_available() -> bool:
    try:
        import langgraph  # noqa: F401
        return True
    except Exception:
        return False


def build_langgraph():
    """Construct and compile the LangGraph StateGraph. Raises if langgraph is missing."""
    from langgraph.graph import StateGraph, END

    g = StateGraph(CampaignBlackboard)
    g.add_node("recon", recon_stage)
    g.add_node("analyse", analyse_stage)
    g.add_node("attack", attack_stage)
    g.add_node("report", report_stage)

    g.set_entry_point("recon")
    g.add_edge("recon", "analyse")
    g.add_edge("analyse", "attack")
    g.add_conditional_edges("attack", route_after_attack, {"replan": "analyse", "done": "report"})
    g.add_edge("report", END)
    return g.compile()


def _merge(state: dict, updates: dict) -> dict:
    """Apply a node's partial update to the running state (fallback orchestrator)."""
    state.update(updates or {})
    return state


def run_fallback(initial: dict[str, Any]) -> dict[str, Any]:
    """Sequential orchestrator used when LangGraph is not installed.

    Mirrors the graph topology: recon -> analyse -> attack -> (analyse | report).
    """
    state = dict(initial)
    _merge(state, recon_stage(state))
    node = "analyse"
    steps = 0
    while steps < _MAX_NODE_STEPS:
        steps += 1
        if node == "analyse":
            _merge(state, analyse_stage(state))
            node = "attack"
        elif node == "attack":
            _merge(state, attack_stage(state))
            node = route_after_attack(state)  # "replan" -> analyse, "done" -> report
            node = "analyse" if node == "replan" else "report"
        elif node == "report":
            _merge(state, report_stage(state))
            break
    return state


def run_pipeline(initial: dict[str, Any], *, prefer_langgraph: bool = True) -> dict[str, Any]:
    """Run the staged pipeline, using LangGraph if available."""
    if prefer_langgraph and langgraph_available():
        try:
            app = build_langgraph()
            result = app.invoke(initial, config={"recursion_limit": _MAX_NODE_STEPS})
            return dict(result)
        except Exception:
            logger.warning("LangGraph execution failed; using fallback orchestrator", exc_info=True)
    return run_fallback(initial)
