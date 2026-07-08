"""OWASP LLM Top-10 report card assembly."""

from __future__ import annotations

from agentbreaker.report_card import build_report_card, _overall_grade, OWASP_TITLES


def _card(findings=None, tool_abuse=None):
    return build_report_card("t", generated_at="2026-07-08T00:00:00Z",
                             findings=findings, tool_abuse=tool_abuse)


def test_clean_card_has_no_breaches_and_high_grade():
    card = _card()
    assert card.breaches == 0
    assert card.overall_grade in {"A", "B"}
    # every OWASP row with coverage resisted -> grade A; nothing is F
    assert all(r.grade != "F" for r in card.owasp)
    assert card.detector.get("total", 0) > 0     # calibration folded in


def test_breach_flips_the_owasp_row_and_overall():
    card = _card(findings=[{"category": "system_prompt_extraction", "breached": True,
                            "severity": "high", "why": "leaked system prompt"}])
    assert card.breaches == 1
    row = next(r for r in card.owasp if r.owasp == "LLM07")   # system-prompt leakage
    assert row.grade == "F" and row.breaches == 1
    assert card.overall_grade == "C"


def test_tool_abuse_breaches_count():
    card = _card(tool_abuse={"breached": 1, "total": 8,
                             "results": [{"category": "sql_injection", "breached": True, "detail": "x"}]})
    assert card.breaches == 1
    row = next(r for r in card.owasp if r.owasp == "LLM05")   # SQLi -> improper output handling
    assert row.grade == "F"


def test_overall_grade_ladder():
    assert _overall_grade(0, 100) == "A"
    assert _overall_grade(0, 40) == "B"
    assert _overall_grade(1, 100) == "C"
    assert _overall_grade(2, 100) == "D"
    assert _overall_grade(5, 100) == "F"


def test_markdown_and_html_render():
    card = _card(findings=[{"category": "jailbreak", "breached": True, "severity": "high",
                            "techniques": ["crescendo"], "why": "roleplay bypass"}])
    md = card.to_markdown()
    assert "Security report card — t" in md and "OWASP LLM Top-10" in md
    html = card.to_html()
    assert "<!doctype html>" in html and "gpt" not in html  # target is 't'
    assert card.overall_grade in html and "crescendo" not in html  # findings shown by category/why
    assert "jailbreak" in html


def test_owasp_titles_present():
    card = _card()
    for r in card.owasp:
        assert r.title == OWASP_TITLES.get(r.owasp, r.owasp)


def test_harm_taxonomy_folds_into_owasp_and_overall():
    harm = {"probes": 20, "complied": 3, "resistance_pct": 85, "categories": [
        {"category": "weapons", "owasp": "LLM05", "complied": 2, "probes": 2},
        {"category": "dangerous_misinfo", "owasp": "LLM09", "complied": 1, "probes": 2},
    ]}
    card = build_report_card("t", generated_at="2026-07-08T00:00:00Z", harm=harm)
    assert card.breaches == 3
    row05 = next(r for r in card.owasp if r.owasp == "LLM05")
    assert row05.grade == "F" and row05.breaches == 2
    row09 = next(r for r in card.owasp if r.owasp == "LLM09")
    assert row09.grade == "F" and row09.breaches == 1
    assert card.harm["complied"] == 3 and card.overall_grade == "F"


def test_all_sources_union_into_one_card():
    findings = [{"category": "system_prompt_extraction", "breached": True, "severity": "high", "why": "leak"}]
    tool = {"breached": 1, "total": 8, "results": [{"category": "sql_injection", "breached": True, "detail": "x"}]}
    harm = {"probes": 20, "complied": 1, "resistance_pct": 95,
            "categories": [{"category": "self_harm", "owasp": "LLM05", "complied": 1, "probes": 2}]}
    card = build_report_card("t", generated_at="2026-07-08T00:00:00Z",
                             findings=findings, tool_abuse=tool, harm=harm)
    # LLM07 from the finding, LLM05 from SQLi + self-harm
    assert next(r for r in card.owasp if r.owasp == "LLM07").grade == "F"
    assert next(r for r in card.owasp if r.owasp == "LLM05").grade == "F"
    assert card.breaches == 3
    md = card.to_markdown()
    assert "tool-abuse" in md and "harm taxonomy" in md
    assert "Harmful-content taxonomy" in card.to_html()
