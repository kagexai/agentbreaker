"""Regression test for the attack-id deadlock that stalled the staged engine at one id.

Bug: _append_result() dedup-guarded against the campaign DB while _next_attack_id()
allocates from results.tsv. When the DB had an id that results.tsv lacked (e.g. the TSV
was reset while campaign.db survived a prior same-tag run), _append_result early-returned
and never wrote the row, so _next_attack_id() handed out the same id forever.

The fix makes _append_result dedup against results.tsv (the id-allocation source), so the
row is always written when the id is new to the TSV -- independent of the DB.
"""

from __future__ import annotations

import importlib

import pytest

campaign = importlib.import_module("agentbreaker.campaign")


def _result(attack_id: str) -> dict:
    return {
        "attack_id": attack_id, "category": "prompt_injection", "technique": "completion_attack",
        "target_id": "t", "vulnerability": 0.0, "novelty": 0.0, "reliability": 0.0,
        "composite": 0.1, "asr": 0.0, "owasp_ref": "LLM01", "benchmark_ref": "",
        "description": "x", "response_gradient": 0.0,
    }


@pytest.fixture(autouse=True)
def _reset_id_high_water():
    # The in-process high-water mark persists across calls; reset it so tests that assert
    # absolute id values (ATK-00001, ...) are deterministic regardless of order.
    campaign._ID_HIGH_WATER = 0
    yield
    campaign._ID_HIGH_WATER = 0


@pytest.fixture
def tsv(tmp_path, monkeypatch):
    path = tmp_path / "results.tsv"
    path.write_text(campaign.RESULTS_HEADER)
    monkeypatch.setattr(campaign, "RESULTS_PATH", path)
    campaign._RESULTS_CACHE.update(mtime=None, size=None, rows=[])
    # No DB in this test -- exercise the file-based path directly.
    monkeypatch.setattr(campaign, "_get_campaign_db", lambda: None)
    return path


def _row_ids(path):
    import csv
    with path.open() as fh:
        return [r["attack_id"] for r in csv.DictReader(fh, delimiter="\t")]


def test_append_writes_even_when_db_claims_id_exists(tsv, monkeypatch):
    # Simulate the divergence: DB says ATK-00007 exists, but results.tsv does not.
    monkeypatch.setattr(campaign, "_existing_attack_ids", lambda: {"ATK-00007"})
    campaign._append_result(_result("ATK-00007"), "discard", "no-git")
    assert _row_ids(tsv) == ["ATK-00007"], "row must be written despite DB claiming it exists"


def test_append_is_idempotent_against_tsv(tsv):
    campaign._append_result(_result("ATK-00001"), "discard", "no-git")
    campaign._append_result(_result("ATK-00001"), "discard", "no-git")  # duplicate
    assert _row_ids(tsv) == ["ATK-00001"], "same id must not be appended twice"


def test_ids_advance_across_appends(tsv, monkeypatch):
    # Constrain the global id scan to our temp TSV so _next_attack_id is deterministic.
    monkeypatch.setattr(campaign, "_iter_result_files", lambda: [tsv])
    monkeypatch.setattr(campaign, "_iter_finding_files", lambda: [])
    monkeypatch.setattr(campaign, "_iter_audit_log_files", lambda: [])

    first = campaign._next_attack_id()
    campaign._append_result(_result(first), "discard", "no-git")
    second = campaign._next_attack_id()
    assert second != first, "id must advance once the prior result is recorded"
    campaign._append_result(_result(second), "discard", "no-git")
    third = campaign._next_attack_id()
    assert len({first, second, third}) == 3


def test_discards_advance_id_via_audit_log(tmp_path, monkeypatch):
    """The real bug: a run of refusals scores 'discard' and never reaches results.tsv, so
    without folding in the audit log the id never advances and distinct payloads reuse it.
    """
    # Nothing persisted (all discards) -> results.tsv and findings stay empty.
    monkeypatch.setattr(campaign, "_iter_result_files", lambda: [])
    monkeypatch.setattr(campaign, "_iter_finding_files", lambda: [])
    audit = tmp_path / "attack_log.jsonl"
    monkeypatch.setattr(campaign, "_iter_audit_log_files", lambda: [audit])

    first = campaign._next_attack_id()
    assert first == "ATK-00001"
    # The experiment writes its trials to the audit log under `first` (3 trials, one id).
    audit.write_text(
        f'{{"attack_id": "{first}", "trial": 1}}\n'
        f'{{"attack_id": "{first}", "trial": 2}}\n'
        f'{{"attack_id": "{first}", "trial": 0}}\n'
    )
    # Next payload must get a DIFFERENT id even though nothing was written to results.tsv.
    second = campaign._next_attack_id()
    assert second == "ATK-00002"
    assert first != second


def test_ids_unique_even_if_audit_log_not_yet_flushed(monkeypatch):
    """Belief-engine safety: rapid allocation must not collide even if the prior id's
    audit-log write isn't visible on disk yet (the in-process high-water guards this)."""
    monkeypatch.setattr(campaign, "_iter_result_files", lambda: [])
    monkeypatch.setattr(campaign, "_iter_finding_files", lambda: [])
    # Audit log always looks empty (simulates an unflushed / lagging write).
    monkeypatch.setattr(campaign, "_iter_audit_log_files", lambda: [])
    ids = [campaign._next_attack_id() for _ in range(5)]
    assert ids == ["ATK-00001", "ATK-00002", "ATK-00003", "ATK-00004", "ATK-00005"]
    assert len(set(ids)) == 5
