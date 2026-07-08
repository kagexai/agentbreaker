"""Model-safety objectives: a bare frontier model gets safety objectives, an app doesn't."""

from __future__ import annotations

from agentbreaker.agents.contracts import ReconReport
from agentbreaker.agents.stages.analyse import analyse_stage, _is_bare_model


def _state(recon: ReconReport):
    return {"recon": recon, "config_path": "target_config.yaml", "target_id": "t",
            "replan_count": 0, "log": [], "_no_llm": True}   # deterministic path


def _bare_model_recon() -> ReconReport:
    return ReconReport(
        target_id="gpt-5.4", capabilities={"has_multi_turn": True},
        attack_surface=[{"field": "system_prompt", "category": "system_prompt_extraction",
                         "priority": 0.7, "reason": "leak"}],
        persona="Assistant", domain="general", deployment_type="general",
    )


def _app_recon() -> ReconReport:
    return ReconReport(
        target_id="airline-bot", capabilities={"has_tools": True},
        attack_surface=[
            {"field": "coupon_code", "category": "data_exfiltration", "priority": 0.8, "reason": "coupons"},
            {"field": "booking", "category": "prompt_injection", "priority": 0.6, "reason": "x"},
        ],
        persona="Aria", domain="airline_support", deployment_type="airline_support",
    )


def test_bare_model_detected():
    assert _is_bare_model(_bare_model_recon()) is True
    assert _is_bare_model(_app_recon()) is False


def test_bare_model_gets_safety_objectives():
    out = analyse_stage(_state(_bare_model_recon()))
    cats = {o.category for o in out["plan"].objectives}
    # jailbreak + prompt-extraction guaranteed for a bare model
    assert "jailbreak" in cats
    assert "prompt_extraction" in cats
    # and it did NOT invent app fields
    fields = {o.target_field for o in out["plan"].objectives}
    assert "coupon_code" not in fields


def test_app_target_stays_app_focused():
    out = analyse_stage(_state(_app_recon()))
    cats = {o.category for o in out["plan"].objectives}
    fields = {o.target_field for o in out["plan"].objectives}
    # app surface preserved (its high-priority fields lead the plan) ...
    assert "coupon_code" in fields
    # ... but the scan now ALSO spans the vulnerability taxonomy (breadth), not just the
    # app's extraction surface -- at least one judgment-family class is covered.
    assert cats & {"bias_gender", "bias_race", "misinformation", "toxicity_insult",
                   "hallucination", "intellectual_property"}
    # bare-model safety seed still NOT injected into an app plan
    assert not any(o.target_field == "system_prompt" and o.category == "prompt_extraction"
                   for o in out["plan"].objectives)
