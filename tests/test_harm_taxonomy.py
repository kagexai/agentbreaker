"""Harmful-content taxonomy: probes scored by the refusal/compliance evaluator.

Fully offline — models are fake callbacks. A refusing model resists everything; a
compliant one breaches; aggregation is per-category.
"""

from __future__ import annotations

from agentbreaker.harm_taxonomy import (
    HARM_CATALOG, run_harm_probes, categories,
)


def _refuser(_prompt: str) -> str:
    return "I'm sorry, I can't help with that request."


def _complier(prompt: str) -> str:
    return ("Sure, here is a detailed step-by-step answer to your request: first you begin, "
            "then you proceed carefully through each of the following stages in order...")


def test_taxonomy_is_well_formed():
    ids = [h.id for h in HARM_CATALOG]
    assert len(ids) == len(set(ids))
    for h in HARM_CATALOG:
        assert h.probes and all(isinstance(p, str) and p for p in h.probes)
        assert h.severity in {"high", "medium"} and h.owasp.startswith("LLM")


def test_refusing_model_resists_all():
    rep = run_harm_probes("safe", _refuser)
    assert rep["complied"] == 0
    assert rep["resistance_pct"] == 100
    assert all(c["complied"] == 0 for c in rep["categories"])


def test_compliant_model_breaches():
    rep = run_harm_probes("weak", _complier)
    assert rep["complied"] == rep["probes"] and rep["probes"] > 0
    assert rep["resistance_pct"] == 0
    # every category flagged
    assert all(c["complied"] == c["probes"] for c in rep["categories"])


def test_mixed_model_partial():
    def _mixed(prompt: str) -> str:
        # complies only on the self-harm probes, refuses the rest
        return _complier(prompt) if "end my life" in prompt or "harm myself" in prompt else _refuser(prompt)
    rep = run_harm_probes("mixed", _mixed)
    sh = next(c for c in rep["categories"] if c["category"] == "self_harm")
    assert sh["complied"] == sh["probes"]
    assert rep["complied"] == sh["probes"] and rep["complied"] < rep["probes"]


def test_error_callback_counts_as_resisted():
    def _boom(_p: str) -> str:
        raise RuntimeError("down")
    rep = run_harm_probes("erroring", _boom)
    # an error is not compliance -> resisted
    assert rep["complied"] == 0


def test_empty_response_not_counted_as_compliance():
    # A blank/errored response produced NO disallowed content, so it must not read as a harm
    # breach (this is what turned rate-limited concurrent sweeps into false 0% resistance).
    rep = run_harm_probes("blank", lambda _p: "")
    assert rep["complied"] == 0
    assert rep["resistance_pct"] == 100


def test_categories_span_expected_harms():
    cats = set(categories())
    for c in ["weapons", "drugs", "cyber_malware", "self_harm", "hate_harassment",
              "fraud_scams", "dangerous_misinfo"]:
        assert c in cats
