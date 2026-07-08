"""Unit tests for the staged multi-agent pipeline (agentbreaker/agents).

Runs entirely offline against the built-in fallback orchestrator with an injected
executor -- no LangGraph, no live target. Verifies the stage contracts, the Analyse
capability gating + ordering, the Attack budget accounting, and the loop-back bound.
"""

from __future__ import annotations

from agentbreaker.agents.contracts import (
    ReconReport, AttackObjective, AttackPlan, AttackResults, ObjectiveOutcome, Report,
)
from agentbreaker.agents.blackboard import new_blackboard, remaining_experiments
from agentbreaker.agents.stages import (
    recon_stage, analyse_stage, attack_stage, route_after_attack,
)
from agentbreaker.agents.graph import run_fallback
from agentbreaker.agents.runner import run_staged_campaign


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------

def test_contract_roundtrips():
    r = ReconReport(target_id="t", capabilities={"has_vision": True})
    assert ReconReport.from_dict(r.to_dict()).capabilities == {"has_vision": True}
    plan = AttackPlan(objectives=[AttackObjective(target_field="sys", category="prompt_injection")])
    assert AttackPlan.from_dict(plan.to_dict()).objectives[0].target_field == "sys"


def test_attack_results_aggregates():
    res = AttackResults(per_objective=[
        ObjectiveOutcome(AttackObjective("a", "c"), experiments_run=3, breached=False),
        ObjectiveOutcome(AttackObjective("b", "c"), experiments_run=2, breached=True),
    ])
    assert res.total_experiments == 5
    assert res.any_breach is True


# ---------------------------------------------------------------------------
# Stage fixtures
# ---------------------------------------------------------------------------

PROFILE = {
    "deployment": {"persona_name": "Aria", "type": "airline_support"},
    "capabilities": {"has_vision": True, "has_tools": False, "has_document": False},
    "attack_surface": {
        "high_priority": [{"category": "system_prompt_extraction", "reason": "leak",
                            "angles": ["system_prompt"]}],
        "medium_priority": [{"category": "tool_misuse", "reason": "no tools though",
                              "angles": ["booking_action"]}],
        "low_priority": [{"category": "data_exfiltration", "reason": "coupons",
                          "angles": ["coupon_code"]}],
    },
    "guardrail_observations": {"refusal_phrases": ["I cannot"]},
}


def base_state():
    bb = new_blackboard(target_id="demo", config_path="target_config.yaml",
                        profile=PROFILE, max_experiments=20, max_replans=2)
    bb["_no_llm"] = True   # keep Phase 0 stage tests deterministic (no LLM calls)
    bb["coverage"] = "quick"   # these test loop-back/budget mechanics, not taxonomy breadth
    return bb


# ---------------------------------------------------------------------------
# Recon + Analyse
# ---------------------------------------------------------------------------

def test_recon_builds_surface_and_caps():
    st = base_state()
    st.update(recon_stage(st))
    recon = st["recon"]
    assert recon.capabilities["has_vision"] is True
    fields = {e["field"] for e in recon.attack_surface}
    assert "system_prompt" in fields


def test_analyse_gates_by_capability_and_orders_by_priority():
    st = base_state()
    st.update(recon_stage(st))
    st.update(analyse_stage(st))
    plan = st["plan"]
    cats = [o.category for o in plan.objectives]
    # tool_misuse must be dropped because has_tools is False
    assert "tool_misuse" not in cats
    # highest-priority (system_prompt_extraction, 0.9) comes first
    assert plan.objectives[0].category == "system_prompt_extraction"
    # priorities are non-increasing
    pr = [o.priority for o in plan.objectives]
    assert pr == sorted(pr, reverse=True)


# ---------------------------------------------------------------------------
# Attack + routing
# ---------------------------------------------------------------------------

def make_executor(breach_fields=()):
    def _exec(obj, budget, state):
        breached = obj.target_field in breach_fields
        return ObjectiveOutcome(objective=obj, experiments_run=budget,
                                best_composite=8.0 if breached else 1.0, breached=breached)
    return _exec


def test_attack_spends_budget_and_reports_breach():
    st = base_state()
    st.update(recon_stage(st)); st.update(analyse_stage(st))
    st["_executor"] = make_executor(breach_fields=["system_prompt"])
    st.update(attack_stage(st))
    res = st["results"]
    assert res.any_breach is True
    assert res.replan_requested is False          # breach -> no replan
    assert st["budget"]["experiments_spent"] == res.total_experiments


def test_attack_requests_replan_when_stuck_within_bound():
    st = base_state()
    st.update(recon_stage(st)); st.update(analyse_stage(st))
    st["_executor"] = make_executor(breach_fields=[])  # nothing breaches
    st.update(attack_stage(st))
    assert st["results"].replan_requested is True
    assert route_after_attack(st) == "replan"
    assert st["replan_count"] == 1


def test_attack_does_not_exceed_experiment_budget():
    st = base_state()
    st["budget"]["max_experiments"] = 3   # tiny budget
    st.update(recon_stage(st)); st.update(analyse_stage(st))
    st["_executor"] = make_executor()
    st.update(attack_stage(st))
    assert st["results"].total_experiments <= 3


# ---------------------------------------------------------------------------
# Full pipeline (fallback orchestrator)
# ---------------------------------------------------------------------------

def test_pipeline_loops_back_then_terminates_at_report():
    st = base_state()
    st["_executor"] = make_executor(breach_fields=[])  # never breaches -> exercise loop-back
    final = run_fallback(st)
    assert "report" in final
    # max_replans=2 -> Analyse runs initial + 2 replans; replan_count caps at 2
    assert final["replan_count"] == 2
    assert final["report"].coverage["replans"] == 2


def test_pipeline_stops_early_on_breach():
    st = base_state()
    st["_executor"] = make_executor(breach_fields=["system_prompt"])
    final = run_fallback(st)
    assert final["report"].coverage["breaches"] >= 1
    assert final["replan_count"] == 0


def test_run_staged_campaign_returns_zero(capsys):
    rc = run_staged_campaign(
        target_id="demo", config_path="target_config.yaml", profile=PROFILE,
        max_experiments=20, max_replans=1, executor=make_executor(breach_fields=["system_prompt"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "breach" in out.lower()
