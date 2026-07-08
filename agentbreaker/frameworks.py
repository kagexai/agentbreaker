"""Compliance framework mappings — the "framework bundle" surface deepteam ships.

Each catalog vulnerability is mapped to the risk categories of four external frameworks:

- **NIST AI RMF** — the AI Risk Management Framework's trustworthiness characteristics
  (the Measure function tests these).
- **MITRE ATLAS** — adversarial ML tactics/techniques relevant to LLM systems.
- **EU AI Act** — the obligations (prohibited practices, transparency, data governance,
  accuracy/robustness/cybersecurity, non-discrimination) a provider must satisfy.
- **OWASP Agentic (Agentic Security Initiative)** — the agentic-threat taxonomy (T1–T15);
  only the agentic vulnerabilities map here (like deepteam, each framework covers a subset).

Mappings are keyed by the vulnerability's *group* (the deepteam-style family on each
``VulnType``) so they stay maintainable as the catalog grows. ``framework_view`` folds a set
of breached vulnerability ids into a per-framework, per-category compliance picture that the
report card and ``/api/frameworks`` surface.
"""

from __future__ import annotations

from typing import Any

from . import vulnerabilities as _vulns

# Framework metadata (id -> human-facing name + one-line description).
FRAMEWORKS: dict[str, dict[str, str]] = {
    "nist_ai_rmf": {
        "name": "NIST AI RMF",
        "description": "NIST AI Risk Management Framework — trustworthiness characteristics "
                       "exercised by the Measure function.",
    },
    "mitre_atlas": {
        "name": "MITRE ATLAS",
        "description": "Adversarial Threat Landscape for AI Systems — tactics & techniques "
                       "against ML/LLM systems.",
    },
    "eu_ai_act": {
        "name": "EU AI Act",
        "description": "European Union AI Act obligations for high-risk / general-purpose AI.",
    },
    "owasp_agentic": {
        "name": "OWASP Agentic (ASI)",
        "description": "OWASP Agentic Security Initiative — the agentic threat taxonomy (T1–T15).",
    },
}

# framework -> category title -> set of vulnerability GROUPS it covers. A group not listed
# under a framework simply isn't in that framework's scope (frameworks cover subsets).
_GROUP_MAP: dict[str, dict[str, list[str]]] = {
    "nist_ai_rmf": {
        "Valid & Reliable": ["Misinformation"],
        "Safe": ["Illegal Activity", "Responsible AI"],
        "Secure & Resilient": ["Robustness", "Unauthorized Access", "Prompt Leakage",
                               "Excessive Agency"],
        "Accountable & Transparent": ["Prompt Leakage", "Misinformation", "Competition"],
        "Privacy-Enhanced": ["PII Leakage", "Sensitive Info"],
        "Fair — Harmful Bias Managed": ["Bias", "Toxicity", "Responsible AI"],
    },
    "mitre_atlas": {
        "Reconnaissance (AML.TA0002)": ["Unauthorized Access"],
        "LLM Prompt Injection (AML.T0051)": ["Robustness"],
        "LLM Jailbreak (AML.T0054)": ["Illegal Activity"],
        "Extract LLM System Prompt (AML.T0056)": ["Prompt Leakage"],
        "LLM Data Leakage (AML.T0057)": ["Sensitive Info", "PII Leakage"],
        "LLM Plugin Compromise (AML.T0053)": ["Excessive Agency", "Unauthorized Access"],
    },
    "eu_ai_act": {
        "Prohibited Practices (Art. 5)": ["Responsible AI", "Illegal Activity"],
        "Transparency (Art. 50)": ["Misinformation", "Prompt Leakage", "Competition"],
        "Data Governance (Art. 10)": ["PII Leakage", "Sensitive Info"],
        "Accuracy, Robustness & Cybersecurity (Art. 15)": ["Robustness", "Unauthorized Access",
                                                           "Misinformation", "Excessive Agency"],
        "Non-Discrimination & Fundamental Rights (Art. 10 / Recital)": ["Bias", "Toxicity",
                                                                        "Responsible AI"],
        "IP & Copyright (Art. 53)": ["Intellectual Property"],
    },
    "owasp_agentic": {
        "T1 Memory Poisoning": ["Robustness"],       # incl. tool_metadata_poisoning / recursive
        "T2 Tool Misuse": ["Excessive Agency"],
        "T3 Privilege Compromise": ["Unauthorized Access"],
        "T6 Intent Breaking & Goal Manipulation": ["Prompt Leakage"],  # goal_theft
        "T9 Identity Spoofing / Impersonation": ["Misinformation"],    # deception
    },
}

# A few specific vuln ids belong to categories their group alone wouldn't capture.
_ID_OVERRIDES: dict[str, dict[str, list[str]]] = {
    "owasp_agentic": {
        "T1 Memory Poisoning": ["tool_metadata_poisoning", "recursive_hijacking",
                                "indirect_injection", "document_injection"],
        "T6 Intent Breaking & Goal Manipulation": ["goal_theft", "recursive_hijacking"],
        "T9 Identity Spoofing / Impersonation": ["deception"],
    },
}


def _catalog_ids() -> list[str]:
    return [v.id for v in _vulns.CATALOG]


def _category_ids(framework: str, category: str) -> set[str]:
    """The set of vulnerability ids a framework category covers (group map + id overrides)."""
    groups = set(_GROUP_MAP.get(framework, {}).get(category, []))
    ids = {v.id for v in _vulns.CATALOG if v.group in groups}
    ids |= set(_ID_OVERRIDES.get(framework, {}).get(category, []))
    # keep only ids that actually exist in the catalog
    valid = set(_catalog_ids())
    return {i for i in ids if i in valid}


def vuln_frameworks(vuln_id: str) -> dict[str, list[str]]:
    """Reverse lookup: which framework categories a single vulnerability maps to."""
    out: dict[str, list[str]] = {}
    for fw, cats in _GROUP_MAP.items():
        hit = [cat for cat in cats if vuln_id in _category_ids(fw, cat)]
        if hit:
            out[fw] = hit
    return out


def framework_view(breached_ids: set[str] | None = None) -> dict[str, Any]:
    """Per-framework, per-category compliance view. ``breached_ids`` are the vulnerability
    ids that actually broke in a scan; each category reports how many of its classes were
    covered by the catalog and how many were breached."""
    breached = set(breached_ids or [])
    result: dict[str, Any] = {}
    for fw, meta in FRAMEWORKS.items():
        cats = []
        fw_breaches = 0
        for cat in _GROUP_MAP.get(fw, {}):
            ids = _category_ids(fw, cat)
            cat_breaches = sorted(ids & breached)
            fw_breaches += len(cat_breaches)
            cats.append({
                "category": cat,
                "classes": len(ids),
                "breached": len(cat_breaches),
                "breached_ids": cat_breaches,
                "status": "fail" if cat_breaches else "pass",
            })
        result[fw] = {
            "name": meta["name"],
            "description": meta["description"],
            "categories": cats,
            "total_breaches": fw_breaches,
            "status": "fail" if fw_breaches else "pass",
        }
    return result


def coverage_by_framework() -> dict[str, Any]:
    """Static view (no scan): how many catalog classes each framework category maps."""
    return framework_view(breached_ids=set())


def to_markdown(view: dict[str, Any]) -> str:
    lines = ["# Framework compliance mapping", ""]
    for fw in FRAMEWORKS:
        d = view.get(fw, {})
        mark = "❌ FAIL" if d.get("status") == "fail" else "✅ pass"
        lines.append(f"## {d.get('name', fw)} — {mark}")
        lines.append("")
        lines.append("| Category | Classes | Breaches |")
        lines.append("|---|---|---|")
        for c in d.get("categories", []):
            lines.append(f"| {c['category']} | {c['classes']} | {c['breached']} |")
        lines.append("")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(prog="agentbreaker-frameworks",
                                 description="Map the vulnerability catalog to NIST / MITRE ATLAS / "
                                             "EU AI Act / OWASP Agentic frameworks.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    view = coverage_by_framework()
    if args.json:
        print(_json.dumps(view, indent=2))
    else:
        print(to_markdown(view))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
