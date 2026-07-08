"""Curated CTF registry source.

Reads the maintained ctf_registry.yaml of known public AI-security challenges. These
are public-by-design, so candidates are marked authorized_by_design=True. Deterministic
and offline -- no network required.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from ..base import Candidate, DiscoverySource

logger = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "data" / "ctf_registry.yaml"


class CuratedSource(DiscoverySource):
    name = "curated"

    def enabled(self) -> bool:
        return self.config.get("enabled", True)

    def discover(self) -> list[Candidate]:
        registry_path = Path(self.config.get("registry_path", _REGISTRY_PATH))
        if not registry_path.exists():
            logger.warning("Curated registry not found at %s", registry_path)
            return []
        try:
            data = yaml.safe_load(registry_path.read_text()) or {}
        except Exception:
            logger.warning("Failed to parse curated registry", exc_info=True)
            return []

        out: list[Candidate] = []
        for entry in data.get("challenges", []):
            if not isinstance(entry, dict) or not entry.get("url"):
                continue
            out.append(Candidate(
                kind="ctf",
                name=str(entry.get("name", entry["url"])),
                source=self.name,
                url=str(entry["url"]),
                description=str(entry.get("description", "")),
                category=str(entry.get("category", "prompt_injection")),
                tags=list(entry.get("tags", [])),
                suggested_provider=str(entry.get("provider", "")),
                authorized_by_design=True,
                needs_verification=False,
                metadata={"platform_match": bool(entry.get("platform_match", False))},
            ))
        return out
