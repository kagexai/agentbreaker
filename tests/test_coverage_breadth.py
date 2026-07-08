"""Breadth-guaranteed planning: a scan spans the vulnerability taxonomy, not just extraction.

The Analyse stage used to stop at the planner's top-4 picks, which on an app target always
meant system-prompt / PII extraction -- so bias, toxicity, misinformation, hallucination, IP,
overreliance (all with working evaluators) never got attacked. These tests pin that a
"standard" scan now covers those judgment families, that the coverage knob scales breadth,
and that the planner's targeted picks still lead.
"""

from __future__ import annotations

from agentbreaker.agents.contracts import ReconReport
from agentbreaker.agents.stages import analyse as A
from agentbreaker.agents.stages.analyse import analyse_stage


def _app_recon() -> ReconReport:
    return ReconReport(
        target_id="airline-bot", capabilities={"has_tools": True},
        attack_surface=[
            {"field": "coupon_code", "category": "data_exfiltration", "priority": 0.8, "reason": "c"},
            {"field": "booking", "category": "prompt_injection", "priority": 0.6, "reason": "x"},
        ],
        persona="Aria", domain="airline_support", deployment_type="airline_support",
    )


def _state(coverage: str) -> dict:
    return {"recon": _app_recon(), "config_path": "c", "target_id": "t",
            "replan_count": 0, "log": [], "_no_llm": True, "coverage": coverage}


def test_standard_spans_judgment_families():
    cats = {o.category for o in analyse_stage(_state("standard"))["plan"].objectives}
    # The classes the eval layer was built for, that the old 4-cap never reached:
    judgment = {"bias_gender", "toxicity_insult", "misinformation", "hallucination",
                "deception", "intellectual_property", "input_overreliance"}
    assert len(cats & judgment) >= 5, f"standard scan too narrow: {sorted(cats)}"


def test_coverage_scales_breadth():
    n_quick = len(analyse_stage(_state("quick"))["plan"].objectives)
    n_std = len(analyse_stage(_state("standard"))["plan"].objectives)
    n_deep = len(analyse_stage(_state("deep"))["plan"].objectives)
    assert n_quick < n_std < n_deep
    assert n_quick <= 4


def test_deep_covers_full_plannable_catalog():
    from agentbreaker.vulnerabilities import CATALOG
    cats = {o.category for o in analyse_stage(_state("deep"))["plan"].objectives}
    plannable = {v.id for v in CATALOG if not v.requires}
    missing = plannable - cats
    assert not missing, f"deep scan missed plannable classes: {missing}"


def test_planner_picks_lead_breadth_fills():
    # The app's high-priority surface fields must appear before the 0.3-priority catalog fills.
    objs = analyse_stage(_state("standard"))["plan"].objectives
    assert objs[0].target_field == "coupon_code"      # highest surface priority leads
    prios = [o.priority for o in objs]
    assert prios == sorted(prios, reverse=True)        # non-increasing


def test_capability_gated_classes_left_to_sandbox():
    # Tool/vision execution vulns must NOT enter the text campaign (the sandbox handles them).
    caps = {"has_tools": False, "has_vision": False}
    cats = {o.category for o in A._catalog_objectives(caps)}
    assert "bola" not in cats and "ssrf" not in cats and "sql_injection" not in cats
