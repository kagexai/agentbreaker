"""One scan covers the full surface: the campaign persists a harm + tool-abuse + safety
sweep, and the report card folds it in (deepteam red_team() parity, not just campaign cats)."""

from __future__ import annotations

import json
from types import SimpleNamespace

from agentbreaker.agents import runner as R
from agentbreaker import report_card as RC


def _patch_paths(monkeypatch, tmp_path):
    p = tmp_path / "supplemental_scans.json"
    monkeypatch.setattr("agentbreaker.artifact_paths.supplemental_scans_path",
                        lambda *a, **k: p)
    return p


def test_supplemental_sweep_persists_all_three(monkeypatch, tmp_path):
    p = _patch_paths(monkeypatch, tmp_path)
    monkeypatch.setattr("agentbreaker.harm_taxonomy.run_harm_scan",
                        lambda tid, cfg: {"complied": 1, "probes": 20, "resistance_pct": 95})
    monkeypatch.setattr("agentbreaker.tool_harness.run_all_scenarios",
                        lambda tid: [SimpleNamespace(breached=True, to_dict=lambda: {"id": "sqli"}),
                                     SimpleNamespace(breached=False, to_dict=lambda: {"id": "bola"})])
    monkeypatch.setattr("agentbreaker.model_safety.provider_callback", lambda tid, cfg: (lambda x: ""))
    monkeypatch.setattr("agentbreaker.model_safety.probe_model",
                        lambda tid, cb: SimpleNamespace(to_dict=lambda: {"resistance": 80}))

    R._run_supplemental_scans({}, "gpt-x", "cfg.yaml", None)

    data = json.loads(p.read_text())
    assert data["harm"]["complied"] == 1
    assert data["tool_abuse"]["breached"] == 1 and data["tool_abuse"]["total"] == 2
    assert data["safety"]["resistance"] == 80


def test_one_failing_scanner_does_not_sink_the_sweep(monkeypatch, tmp_path):
    p = _patch_paths(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise RuntimeError("no provider key")
    monkeypatch.setattr("agentbreaker.harm_taxonomy.run_harm_scan",
                        lambda tid, cfg: {"complied": 0, "probes": 20})
    monkeypatch.setattr("agentbreaker.tool_harness.run_all_scenarios", _boom)   # fails
    monkeypatch.setattr("agentbreaker.model_safety.provider_callback", lambda tid, cfg: (lambda x: ""))
    monkeypatch.setattr("agentbreaker.model_safety.probe_model",
                        lambda tid, cb: SimpleNamespace(to_dict=lambda: {"resistance": 90}))

    R._run_supplemental_scans({}, "gpt-x", "cfg.yaml", None)   # must not raise

    data = json.loads(p.read_text())
    assert "harm" in data and "safety" in data
    assert "tool_abuse" not in data           # the failing one is omitted, not fatal


def test_report_card_folds_persisted_sweep(monkeypatch, tmp_path):
    p = _patch_paths(monkeypatch, tmp_path)
    p.write_text(json.dumps({
        "harm": {"complied": 3, "probes": 20, "resistance_pct": 85,
                 "categories": [{"category": "weapons", "owasp": "LLM05", "complied": 1,
                                 "probes": 2, "severity": "high"}]},
        "tool_abuse": {"breached": 1, "total": 8, "results": []},
        "safety": {"resistance": 80, "grade": "B"},
    }))
    supp = RC._load_supplemental("gpt-x", None)
    assert supp["harm"]["complied"] == 3

    card = RC.build_report_card("gpt-x", generated_at="2026-01-01T00:00:00Z",
                                findings=[], tool_abuse=supp["tool_abuse"],
                                harm=supp["harm"], safety=supp["safety"])
    d = card.to_dict()
    # the sweep is reflected in the card (harm + tool-abuse present)
    assert d["harm"]["complied"] == 3
    assert d["tool_abuse"]["breached"] == 1
