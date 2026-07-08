"""Typed vulnerability catalog + coverage report."""

from __future__ import annotations

from agentbreaker import vulnerabilities as V


def test_catalog_is_well_formed():
    ids = [v.id for v in V.CATALOG]
    assert len(ids) == len(set(ids)), "duplicate category ids"
    for v in V.CATALOG:
        assert v.severity in {"high", "medium", "low"}
        assert v.group and v.name and v.strategy_family and v.description
        assert v.owasp == "" or v.owasp.startswith("LLM")


def test_lookup_helpers():
    assert V.severity_for("system_prompt_extraction") == "high"
    assert V.owasp_for("data_exfiltration") == "LLM02"
    assert V.get("jailbreak").group == "Robustness"
    # unknown category falls back
    assert V.severity_for("nope", default="low") == "low"
    assert V.get("nope") is None


def test_coverage_against_explicit_tested_set():
    cov = V.coverage(tested={"jailbreak", "prompt_injection"})
    assert cov["covered"] == 2
    assert cov["total"] == len(V.CATALOG)
    assert "bola" in cov["uncovered"] and "jailbreak" not in cov["uncovered"]
    # groups sum to the total
    assert sum(g["total"] for g in cov["groups"]) == cov["total"]
    assert sum(g["covered"] for g in cov["groups"]) == cov["covered"]


def test_engine_coverage_reflects_real_categories():
    # Coverage unions chat-attackable categories (Analyse) with the sandboxed tool-abuse
    # harness (agentic access-control) -> the core families AND the access-control cluster
    # are now covered.
    cov = V.coverage()
    covered_ids = {it["id"] for g in cov["groups"] for it in g["items"] if it["covered"]}
    assert "system_prompt_extraction" in covered_ids
    assert "jailbreak" in covered_ids
    # access-control vulns are now covered by the tool-abuse scenario harness
    assert {"bola", "bfla", "rbac_bypass", "ssrf", "sql_injection", "shell_injection"} <= covered_ids


def test_groups_cover_deepteam_families():
    groups = set(V.GROUPS)
    for fam in ["Prompt Leakage", "PII Leakage", "Bias", "Toxicity", "Excessive Agency",
                "Unauthorized Access", "Misinformation", "Robustness"]:
        assert fam in groups, f"missing family: {fam}"
