"""Lightweight LLM agent base for the staged pipeline.

An Agent is a role (system prompt) + the provider-agnostic LLM client already used by
the generator (`attack_generator._call_llm`), with structured JSON output. Agents are
optional: when no LLM/key is configured, `available()` is False and callers fall back to
their deterministic behavior, so the pipeline still runs offline.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class AgentUnavailable(Exception):
    """Raised when an agent cannot produce a usable LLM result (no key, parse failure)."""


def make_llm_config(config_path: str, target_id: str = "") -> Any | None:
    """Return a GeneratorConfig usable with `_call_llm`, or None if unavailable.

    Reuses the generator block of target_config.yaml (model/api/key/endpoint), so agents
    inherit the same provider-agnostic setup as the rest of the tool.
    """
    try:
        from ..attack_generator import load_generator
        gen = load_generator(config_path, target_id)
        return gen.config if gen is not None else None
    except Exception:
        logger.debug("make_llm_config failed", exc_info=True)
        return None


class Agent:
    """A single LLM role that returns structured JSON."""

    def __init__(self, name: str, system: str, llm_config: Any | None):
        self.name = name
        self.system = system
        self.llm = llm_config

    def available(self) -> bool:
        return self.llm is not None

    def reason_json(self, prompt: str, *, retries: int = 1) -> Any:
        """Call the LLM and return parsed JSON (dict or list). Raises AgentUnavailable
        if there's no LLM or no parseable JSON after `retries` repair attempts."""
        if self.llm is None:
            raise AgentUnavailable(f"{self.name}: no LLM configured")
        from ..attack_generator import _call_llm

        attempt_prompt = prompt
        for attempt in range(retries + 1):
            try:
                text, _pt, _rt = _call_llm(attempt_prompt, config=self.llm, system=self.system)
            except Exception as exc:
                raise AgentUnavailable(f"{self.name}: LLM call failed: {exc}") from exc
            data = _extract_json(text)
            if data is not None:
                return data
            # Repair pass: be explicit about format.
            attempt_prompt = prompt + "\n\nReturn ONLY valid JSON, no prose, no code fences."
        raise AgentUnavailable(f"{self.name}: no parseable JSON in response")


def _extract_json(text: str) -> Any | None:
    """Best-effort JSON extraction from an LLM response (object or array)."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    # Grab the first {...} or [...] span.
    for pattern in (r"\{.*\}", r"\[.*\]"):
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                continue
    return None
