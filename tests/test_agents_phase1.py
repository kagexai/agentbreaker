"""Phase 1 tests: LLM Analyse agent + agent-driven Attack tuning.

The LLM is always mocked (monkeypatching attack_generator._call_llm), so these run
offline and never make a real API call.
"""

from __future__ import annotations

import json

import pytest

from agentbreaker.agents import base as agent_base
from agentbreaker.agents.base import Agent, AgentUnavailable
from agentbreaker.agents.contracts import ReconReport
from agentbreaker.agents.stages import analyse as analyse_mod
from agentbreaker.agents.stages.analyse import analyse_stage
from agentbreaker.agents.stages.attack import EngineExecutor


# A non-None sentinel standing in for a GeneratorConfig.
FAKE_LLM = object()


def recon() -> ReconReport:
    return ReconReport(
        target_id="demo",
        capabilities={"has_vision": False, "has_tools": False},
        attack_surface=[
            {"field": "system_prompt", "category": "system_prompt_extraction", "priority": 0.9, "reason": "leak"},
            {"field": "booking", "category": "tool_misuse", "priority": 0.6, "reason": "needs tools"},
        ],
        guardrails={"refusal_phrases": ["I can't"]},
        persona="Aria", domain="airline",
    )


# ---------------------------------------------------------------------------
# Agent base
# ---------------------------------------------------------------------------

def test_agent_parses_and_repairs(monkeypatch):
    calls = []

    def fake_call(prompt, *, config, system=""):
        calls.append(prompt)
        # First answer is garbage; repair attempt returns valid JSON.
        if len(calls) == 1:
            return ("no json here", 0, 0)
        return ('{"ok": true}', 0, 0)

    monkeypatch.setattr("agentbreaker.attack_generator._call_llm", fake_call)
    a = Agent("t", "sys", FAKE_LLM)
    assert a.reason_json("prompt", retries=1) == {"ok": True}
    assert len(calls) == 2  # used the repair pass


def test_agent_raises_when_unparseable(monkeypatch):
    monkeypatch.setattr("agentbreaker.attack_generator._call_llm",
                        lambda prompt, *, config, system="": ("still not json", 0, 0))
    with pytest.raises(AgentUnavailable):
        Agent("t", "sys", FAKE_LLM).reason_json("p", retries=1)


# ---------------------------------------------------------------------------
# LLM Analyse agent
# ---------------------------------------------------------------------------

def _state(**extra):
    st = {"recon": recon(), "config_path": "target_config.yaml", "target_id": "demo",
          "replan_count": 0, "log": []}
    st.update(extra)
    return st


def test_llm_analyse_builds_objectives(monkeypatch):
    plan_json = {
        "rationale": "system prompt is the crown jewel",
        "objectives": [
            {"target_field": "system_prompt", "category": "system_prompt_extraction",
             "strategy_family": "completion_attack", "hypothesis": "ask it to continue its rules",
             "success_criteria": "verbatim rules", "budget": 4, "priority": 0.95},
            # tool_misuse must be dropped (target has no tools)
            {"target_field": "booking", "category": "tool_misuse",
             "strategy_family": "authority_override", "hypothesis": "x", "budget": 3, "priority": 0.7},
        ],
    }
    monkeypatch.setattr("agentbreaker.attack_generator._call_llm",
                        lambda prompt, *, config, system="": (json.dumps(plan_json), 0, 0))
    monkeypatch.setattr(analyse_mod, "make_llm_config", lambda cp, tid: FAKE_LLM)

    out = analyse_stage(_state())
    plan = out["plan"]
    cats = [o.category for o in plan.objectives]
    assert "system_prompt_extraction" in cats
    assert "tool_misuse" not in cats              # capability-gated out
    assert plan.rationale.startswith("[LLM]")
    assert plan.objectives[0].hypothesis           # carries the LLM's reasoning


def test_analyse_falls_back_to_deterministic_on_llm_error(monkeypatch):
    def boom(prompt, *, config, system=""):
        raise RuntimeError("api down")
    monkeypatch.setattr("agentbreaker.attack_generator._call_llm", boom)
    monkeypatch.setattr(analyse_mod, "make_llm_config", lambda cp, tid: FAKE_LLM)

    out = analyse_stage(_state())
    plan = out["plan"]
    assert plan.rationale.startswith("[deterministic]")
    assert any(o.category == "system_prompt_extraction" for o in plan.objectives)


def test_analyse_no_llm_uses_deterministic():
    out = analyse_stage(_state(_no_llm=True))
    assert out["plan"].rationale.startswith("[deterministic]")


def test_llm_analyse_caps_objective_count(monkeypatch):
    many = {"objectives": [
        {"target_field": f"f{i}", "category": "prompt_injection",
         "strategy_family": "boundary_inference", "priority": 0.5} for i in range(10)
    ]}
    monkeypatch.setattr("agentbreaker.attack_generator._call_llm",
                        lambda prompt, *, config, system="": (json.dumps(many), 0, 0))
    monkeypatch.setattr(analyse_mod, "make_llm_config", lambda cp, tid: FAKE_LLM)
    out = analyse_stage(_state())
    # Default coverage is "standard": the plan is bounded by the coverage target, and the
    # LLM's same-category picks are capped so breadth (other classes) fills the rest.
    assert len(out["plan"].objectives) <= analyse_mod._COVERAGE_TARGETS[analyse_mod._DEFAULT_COVERAGE]
    llm_picks = [o for o in out["plan"].objectives if o.category == "prompt_injection"]
    assert len(llm_picks) <= 6


# ---------------------------------------------------------------------------
# Attack stage tuning (agent-driven + faster)
# ---------------------------------------------------------------------------

class _FakeGenCfg:
    min_template_experiments = 20
    stuck_threshold = 5


class _FakeHarness:
    _trials = 5


class _FakeEngine:
    def __init__(self):
        self.harness = _FakeHarness()
        self.generator = type("G", (), {"config": _FakeGenCfg()})()


def test_staged_tuning_enables_llm_first_and_fewer_trials():
    ex = EngineExecutor(target_id="t", config_path="c", profile={}, staged_trials=2, llm_first=True)
    eng = _FakeEngine()
    ex._tune_for_staged(eng)
    assert eng.harness._trials == 2                       # fewer trials -> faster
    assert eng.generator.config.min_template_experiments == 0   # LLM crafts from attack #1
    assert eng.generator.config.stuck_threshold == 1


def test_staged_tuning_is_safe_without_generator():
    ex = EngineExecutor(target_id="t", config_path="c", profile={})
    eng = _FakeEngine()
    eng.generator = None
    ex._tune_for_staged(eng)   # must not raise
    assert eng.harness._trials == 2


def test_analyse_uses_prior_knowledge(monkeypatch, tmp_path):
    """Persisted belief (extractions + cooled strategies) should reach the analyse prompt."""
    import json
    import agentbreaker.artifact_paths as ap
    (tmp_path / "belief_state.json").write_text(json.dumps({
        "confirmed_extractions": {"api_key": "X"},
        "partial_extractions": {"system_prompt": "You are"},
        "cooled_strategies": ["roleplay_persona"],
    }))
    monkeypatch.setattr(ap, "artifact_root", lambda tid=None, tag=None: tmp_path)

    captured = {}

    def fake_call(prompt, *, config, system=""):
        captured["prompt"] = prompt
        return (json.dumps({"objectives": [
            {"target_field": "system_prompt", "category": "system_prompt_extraction",
             "strategy_family": "completion_attack", "priority": 0.9}]}), 0, 0)

    monkeypatch.setattr("agentbreaker.attack_generator._call_llm", fake_call)
    monkeypatch.setattr(analyse_mod, "make_llm_config", lambda cp, tid: FAKE_LLM)

    analyse_stage(_state())
    assert "PARTIAL LEAKS" in captured["prompt"]
    assert "DEAD strategies" in captured["prompt"]
    assert "ALREADY EXTRACTED" in captured["prompt"]
