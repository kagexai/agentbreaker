"""Model registry source.

Polls a public model catalog (OpenRouter by default; Hugging Face optional) for newly
released LLMs and proposes them as guardrail-assessment targets. A discovered model is
only attackable if the operator has API access and authorization, so candidates are
marked needs_verification=True (the operator confirms at approval time).
Offline-graceful.
"""

from __future__ import annotations

import logging
import time

from ..base import Candidate, DiscoverySource

logger = logging.getLogger(__name__)

_OPENROUTER_API = "https://openrouter.ai/api/v1/models"


class ModelRegistrySource(DiscoverySource):
    name = "models"

    def enabled(self) -> bool:
        return self.config.get("enabled", True)

    def discover(self) -> list[Candidate]:
        try:
            import requests
        except Exception:
            logger.warning("requests not available; models source disabled")
            return []

        since_days = int(self.config.get("since_days", 30))
        cutoff = int(time.time()) - since_days * 86400
        try:
            resp = requests.get(
                _OPENROUTER_API, timeout=int(self.config.get("timeout", 15)),
                headers={"User-Agent": "AgentBreaker-discovery/0.1"},
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception:
            logger.warning("OpenRouter models request failed", exc_info=True)
            return []

        models = payload.get("data", payload) if isinstance(payload, dict) else payload
        out: list[Candidate] = []
        for m in models if isinstance(models, list) else []:
            if not isinstance(m, dict):
                continue
            created = m.get("created")
            # Keep only recently-added models when a creation timestamp is present.
            if isinstance(created, (int, float)) and created < cutoff:
                continue
            model_id = str(m.get("id") or m.get("name") or "")
            if not model_id:
                continue
            # Normalize "vendor/model" -> "model" so detect_model_family can match.
            bare = model_id.split("/")[-1]
            out.append(Candidate(
                kind="model",
                name=str(m.get("name", model_id)),
                source=self.name,
                model=bare,
                description=(str(m.get("description", ""))[:280]),
                category="guardrail",
                tags=["model", "llm", "guardrail_assessment"],
                suggested_provider="llm",
                authorized_by_design=False,
                needs_verification=True,
                metadata={
                    "openrouter_id": model_id,
                    "context_length": m.get("context_length"),
                    "created": created,
                },
            ))
        return out
