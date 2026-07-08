"""Shared test safety net.

Tests must never make a real LLM/API call (cost + flakiness). This autouse fixture
disables the low-level LLM client by default; tests that exercise agent reasoning
monkeypatch `_call_llm` with their own fake AFTER this fixture, which takes precedence.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_llm(monkeypatch):
    def _disabled(*args, **kwargs):
        raise RuntimeError("LLM calls are disabled in tests (see tests/conftest.py)")
    # raising=False so it's a no-op if the symbol isn't importable in a given test.
    monkeypatch.setattr("agentbreaker.attack_generator._call_llm", _disabled, raising=False)
