"""Unit tests for the target discovery layer (agentbreaker/discovery).

Network sources are never hit here -- curated runs offline and the engine is fed a
stub source. Verifies the store/dedup, the engine's dedup against an existing config,
and the approval authorization gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentbreaker.discovery.base import Candidate, CandidateStore, dedupe_against_targets
from agentbreaker.discovery.sources.curated import CuratedSource
from agentbreaker.discovery.engine import DiscoveryEngine
from agentbreaker.discovery import approve as approve_mod
from agentbreaker.discovery.approve import approve_candidate, ApprovalError


# ---------------------------------------------------------------------------
# Candidate / store
# ---------------------------------------------------------------------------

def make_candidate(**kw) -> Candidate:
    base = dict(kind="ctf", name="Test CTF", source="t", url="https://example.com/c")
    base.update(kw)
    return Candidate(**base)


def test_candidate_id_is_stable_and_handle_based():
    a = make_candidate()
    b = make_candidate(name="Different name")  # same url -> same handle -> same id
    assert a.id == b.id
    c = make_candidate(url="https://example.com/other")
    assert c.id != a.id


def test_store_roundtrip_and_dedup(tmp_path):
    store = CandidateStore(tmp_path / "c.jsonl")
    cand = make_candidate()
    assert store.upsert(cand) is True
    assert store.upsert(cand) is False        # same id -> not added again
    store.save()

    reloaded = CandidateStore(tmp_path / "c.jsonl")
    assert reloaded.has(cand.id)
    assert reloaded.get(cand.id).name == "Test CTF"


def test_store_filter_by_status_and_kind(tmp_path):
    store = CandidateStore(tmp_path / "c.jsonl")
    store.upsert(make_candidate(url="https://a.com", status="new"))
    store.upsert(make_candidate(kind="model", model="gpt-x", status="registered"))
    assert len(store.filter(status="new")) == 1
    assert len(store.filter(kind="model")) == 1


def test_dedupe_against_targets_by_handle_and_id():
    cands = [
        make_candidate(url="https://known.com"),
        make_candidate(url="https://fresh.com"),
    ]
    out = dedupe_against_targets(cands, existing_target_ids=set(), existing_handles={"https://known.com"})
    urls = {c.url for c in out}
    assert urls == {"https://fresh.com"}


# ---------------------------------------------------------------------------
# Curated source (offline)
# ---------------------------------------------------------------------------

def test_curated_source_loads_registry():
    cands = CuratedSource({}).discover()
    assert cands, "curated registry should yield candidates"
    assert all(c.kind == "ctf" for c in cands)
    assert all(c.authorized_by_design for c in cands)


def test_curated_source_missing_registry_is_graceful(tmp_path):
    cands = CuratedSource({"registry_path": tmp_path / "nope.yaml"}).discover()
    assert cands == []


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _write_config(tmp_path: Path, targets: list[dict]) -> Path:
    cfg = {"targets": targets}
    p = tmp_path / "target_config.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def test_engine_dedups_against_existing_targets(tmp_path, monkeypatch):
    # Existing config already has a target whose env URL matches a curated entry.
    config = _write_config(tmp_path, [{
        "id": "gandalf-existing",
        "provider": "browser",
        "authorization": {"authorized_by": "me", "scope": "x"},
        "config": {"url": "https://gandalf.lakera.ai"},
    }])
    engine = DiscoveryEngine(
        config_path=config,
        store_path=tmp_path / "c.jsonl",
        sources=["curated"],
    )
    summary = engine.discover()
    new_urls = {c.url for c in summary["added"]}
    assert "https://gandalf.lakera.ai" not in new_urls   # deduped by handle
    assert summary["new"] >= 1                            # other curated entries still new


def test_engine_persists_and_is_idempotent(tmp_path):
    config = _write_config(tmp_path, [])
    store = tmp_path / "c.jsonl"
    first = DiscoveryEngine(config_path=config, store_path=store, sources=["curated"]).discover()
    assert first["new"] > 0
    # Second run finds the same candidates but adds nothing new.
    second = DiscoveryEngine(config_path=config, store_path=store, sources=["curated"]).discover()
    assert second["new"] == 0


def test_engine_source_error_is_isolated(tmp_path, monkeypatch):
    config = _write_config(tmp_path, [])

    class Boom:
        name = "boom"
        def __init__(self, cfg): pass
        def enabled(self): return True
        def discover(self): raise RuntimeError("kaboom")

    monkeypatch.setitem(__import__("agentbreaker.discovery.sources", fromlist=["ALL_SOURCES"]).ALL_SOURCES, "boom", Boom)
    engine = DiscoveryEngine(config_path=config, store_path=tmp_path / "c.jsonl", sources=["boom", "curated"])
    summary = engine.discover()
    assert "boom" in summary["errors"]
    assert summary["new"] > 0   # curated still succeeded


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------

def test_approve_authorized_by_design_ctf(tmp_path):
    config = _write_config(tmp_path, [])
    cand = make_candidate(url="https://newctf.example", authorized_by_design=True,
                          suggested_provider="browser")
    entry = approve_candidate(cand, config_path=config)
    assert entry["id"]
    saved = yaml.safe_load(config.read_text())
    ids = [t["id"] for t in saved["targets"]]
    assert entry["id"] in ids


def test_approve_requires_authorization_for_unverified(tmp_path):
    config = _write_config(tmp_path, [])
    cand = make_candidate(url="https://sketchy.example", authorized_by_design=False)
    with pytest.raises(ApprovalError):
        approve_candidate(cand, config_path=config)   # no authorized_by -> blocked
    # With explicit authorization it succeeds.
    entry = approve_candidate(cand, config_path=config, authorized_by="Pentest SOW #42")
    assert entry["id"]


def test_approve_model_requires_known_family(tmp_path, monkeypatch):
    config = _write_config(tmp_path, [])
    cand = Candidate(kind="model", name="Mystery", source="t", model="totally-unknown-xyz",
                     authorized_by_design=False)
    with pytest.raises(ApprovalError):
        approve_candidate(cand, config_path=config, authorized_by="me")


def test_approve_model_with_known_family(tmp_path):
    config = _write_config(tmp_path, [])
    cand = Candidate(kind="model", name="GPT", source="t", model="gpt-4o-mini")
    entry = approve_candidate(cand, config_path=config, authorized_by="Self assessment")
    assert entry["provider"] == "llm"
    assert entry["id"]
