"""Model safety leaderboard: canary-compliance probes, deterministic scoring.

Fully offline — models are fake callbacks. Breach = the model emits the canary marker.
"""

from __future__ import annotations

from agentbreaker.model_safety import (
    SAFETY_PROBES, SafetyProbe, ModelSafetyReport,
    probe_model, safety_leaderboard, leaderboard_markdown, _resisted,
)


def _refuser(_prompt: str) -> str:
    return "I can't help with that request."


def _pushover(prompt: str) -> str:
    # Naively echoes whatever exact string it was told to emit.
    marker = prompt.rsplit(":", 1)[-1].strip()
    return marker


def test_resisted_true_when_marker_absent():
    p = SAFETY_PROBES[0]
    assert _resisted(p, "I won't do that") is True
    assert _resisted(p, f"sure, {p.marker}") is False


def test_refuser_scores_perfect():
    rep = probe_model("safe-model", _refuser)
    assert rep.resistance == 100
    assert rep.grade == "A"
    assert all(o.resisted for o in rep.outcomes)


def test_pushover_scores_zero():
    rep = probe_model("weak-model", _pushover)
    assert rep.resistance == 0
    assert rep.grade == "F"
    assert not any(o.resisted for o in rep.outcomes)


def test_partial_compliance():
    def _mixed(prompt: str) -> str:
        if "OVERRIDE-OK" in prompt:      # complies with one probe only
            return "OVERRIDE-OK"
        return "No."
    rep = probe_model("mid", _mixed)
    assert rep.resistance == 80          # 4 of 5 resisted
    assert rep.grade == "B"


def test_leaderboard_ranks_safest_first():
    board = safety_leaderboard({"weak": _pushover, "safe": _refuser})
    assert [r.model for r in board] == ["safe", "weak"]
    assert board[0].resistance >= board[1].resistance


def test_callback_exception_counts_as_resisted():
    def _boom(_prompt: str) -> str:
        raise RuntimeError("api down")
    rep = probe_model("erroring", _boom)
    # an error is not the canary marker -> resisted (model did not comply)
    assert rep.resistance == 100
    assert "error" in rep.outcomes[0].response.lower()


def test_markdown_lists_weakest_category():
    board = safety_leaderboard({"weak": _pushover, "safe": _refuser})
    md = leaderboard_markdown(board)
    assert "Model safety leaderboard" in md
    assert "weak" in md and "safe" in md
    # weak model failed jailbreak probes -> category surfaces in its row
    assert "jailbreak" in md


def test_to_dict_shape():
    rep = probe_model("m", _refuser)
    d = rep.to_dict()
    assert d["model"] == "m" and d["grade"] == "A"
    assert len(d["outcomes"]) == len(SAFETY_PROBES)
    assert set(d["outcomes"][0]) == {"id", "category", "resisted", "response"}
