"""Compliance framework mappings: NIST AI RMF / MITRE ATLAS / EU AI Act / OWASP Agentic."""

from __future__ import annotations

from agentbreaker import frameworks as F
from agentbreaker.vulnerabilities import CATALOG


def test_all_four_frameworks_present():
    cov = F.coverage_by_framework()
    assert set(cov) == {"nist_ai_rmf", "mitre_atlas", "eu_ai_act", "owasp_agentic"}
    for d in cov.values():
        assert d["categories"] and d["name"]


def test_every_catalog_class_maps_to_at_least_one_framework():
    unmapped = [v.id for v in CATALOG if not F.vuln_frameworks(v.id)]
    assert not unmapped, f"classes mapped to no framework: {unmapped}"


def test_clean_scan_passes_all_frameworks():
    view = F.framework_view(set())
    assert all(d["status"] == "pass" and d["total_breaches"] == 0 for d in view.values())


def test_breach_fails_the_right_frameworks():
    # child_safety breach -> NIST 'Safe' + EU 'Prohibited Practices'
    view = F.framework_view({"child_safety"})
    assert view["nist_ai_rmf"]["status"] == "fail"
    assert view["eu_ai_act"]["status"] == "fail"
    nist_cats = {c["category"] for c in view["nist_ai_rmf"]["categories"] if c["breached"]}
    assert "Safe" in nist_cats


def test_agentic_breach_maps_to_owasp_agentic():
    view = F.framework_view({"tool_misuse"})
    assert view["owasp_agentic"]["status"] == "fail"
    cats = {c["category"] for c in view["owasp_agentic"]["categories"] if c["breached"]}
    assert "T2 Tool Misuse" in cats


def test_responsible_ai_classes_map_to_fairness_and_prohibited():
    fw = F.vuln_frameworks("fairness_treatment")
    # fairness shows up under NIST 'Fair' and EU non-discrimination
    assert "nist_ai_rmf" in fw and "eu_ai_act" in fw
