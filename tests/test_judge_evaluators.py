"""LLM-judge evaluators + their calibration — fully offline via a scripted judge."""

from __future__ import annotations

from agentbreaker.judge_evaluators import (
    JUDGE_RUBRICS, JUDGE_CASES, judge_evaluator, calibrate_judge, calibrate_all,
    judge_categories,
)
from agentbreaker.evaluators import evaluator_for


def _oracle_judge(decide_map):
    """A scripted judge: returns breached=True when the response contains any trigger word."""
    def _decide(prompt: str) -> dict:
        low = prompt.lower()
        for trigger in decide_map:
            if trigger in low:
                return {"breached": True, "reason": f"matched '{trigger}'"}
        return {"breached": False, "reason": "no violation"}
    return _decide


def test_rubrics_and_cases_present():
    for cat in ["bias_gender", "misinformation", "deception", "hallucination"]:
        assert cat in JUDGE_RUBRICS
        assert JUDGE_CASES.get(cat)


def _response_section(prompt: str) -> str:
    # A realistic judge reads only the response it's asked to judge, not the rubric.
    marker = "ASSISTANT RESPONSE (judge this):"
    return prompt.split(marker, 1)[1].lower() if marker in prompt else prompt.lower()


def test_judge_evaluator_uses_decision():
    ev = judge_evaluator(
        "misinformation",
        lambda p: {"breached": "that's a fact" in _response_section(p), "reason": "r"})
    assert ev("q", "Vaccines cause autism, that's a fact.").breached
    assert ev("q", "No evidence supports that.").breached is False


def test_judge_evaluator_failsafe_on_error():
    def _boom(_p):
        raise RuntimeError("judge down")
    v = judge_evaluator("bias_gender", _boom)("q", "anything")
    assert v.breached is False and "unavailable" in v.reason


def test_calibration_perfect_judge_scores_1():
    # A judge that flags exactly the breach responses -> precision/recall 1.0
    breach_texts = {c.response.lower() for cases in JUDGE_CASES.values() for c in cases if c.expected == "breach"}
    def _perfect(prompt: str) -> dict:
        return {"breached": any(t in prompt.lower() for t in breach_texts), "reason": ""}
    rep = calibrate_judge("misinformation", _perfect)
    assert rep.precision == 1.0 and rep.recall == 1.0 and rep.fp == 0 and rep.fn == 0


def test_calibration_catches_a_trigger_happy_judge():
    always = lambda p: {"breached": True, "reason": "x"}
    rep = calibrate_judge("bias_gender", always)
    # flags the safe case too -> a false positive, precision < 1
    assert rep.fp >= 1 and rep.precision < 1.0 and rep.recall == 1.0


def test_calibrate_all_aggregates():
    breach_texts = {c.response.lower() for cases in JUDGE_CASES.values() for c in cases if c.expected == "breach"}
    perfect = lambda p: {"breached": any(t in p.lower() for t in breach_texts), "reason": ""}
    out = calibrate_all(perfect)
    assert out["overall"]["precision"] == 1.0 and out["overall"]["recall"] == 1.0
    assert set(out["per_category"]) == set(JUDGE_CASES)


def test_registry_returns_judge_only_with_a_decider():
    assert evaluator_for("bias_gender") is None                      # honest: no judge -> None
    ev = evaluator_for("bias_gender", judge=lambda p: {"breached": False})
    assert callable(ev)


def test_judge_categories_listed():
    assert "bias_gender" in judge_categories() and "misinformation" in judge_categories()
