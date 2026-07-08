"""Discovery orchestrator.

Runs the enabled sources, deduplicates discovered candidates against both the existing
target_config.yaml and previously-stored candidates, and persists newly-found ones. It
NEVER attacks -- producing candidates is the whole job; attacking requires explicit
approval (see approve.py).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .. import ROOT
from ..config_schema import active_targets
from .base import Candidate, CandidateStore, dedupe_against_targets
from .sources import ALL_SOURCES

logger = logging.getLogger(__name__)

DEFAULT_STORE_PATH = ROOT / "artifacts" / "discovery" / "candidates.jsonl"


class DiscoveryEngine:
    def __init__(
        self,
        *,
        config_path: Path | str = ROOT / "target_config.yaml",
        store_path: Path | str = DEFAULT_STORE_PATH,
        sources: list[str] | None = None,
        source_overrides: dict[str, dict[str, Any]] | None = None,
    ):
        self.config_path = Path(config_path)
        self.store = CandidateStore(Path(store_path))
        self.requested_sources = sources
        self.source_overrides = source_overrides or {}

    # ------------------------------------------------------------------

    def _existing_target_handles(self) -> tuple[set[str], set[str]]:
        """Return (target_ids, handles) already present in target_config.yaml."""
        try:
            config = yaml.safe_load(self.config_path.read_text()) or {}
        except Exception:
            logger.warning("Could not read target config for dedup", exc_info=True)
            return set(), set()

        ids: set[str] = set()
        handles: set[str] = set()
        for t in active_targets(config):
            tid = str(t.get("id", ""))
            if tid:
                ids.add(tid)
            cfg = t.get("config", {}) or {}
            # Collect any URL-ish / model-ish values to dedup against.
            for key in ("model", "url", "endpoint", "base_url"):
                v = cfg.get(key)
                if isinstance(v, str) and v:
                    handles.add(v)
            for v in (cfg.get("env", {}) or {}).values():
                if isinstance(v, str) and v.startswith("http"):
                    handles.add(v)
        return ids, handles

    def _build_sources(self) -> list:
        names = self.requested_sources or list(ALL_SOURCES.keys())
        built = []
        for name in names:
            cls = ALL_SOURCES.get(name)
            if cls is None:
                logger.warning("Unknown discovery source: %s", name)
                continue
            cfg = dict(self.source_overrides.get(name, {}))
            cfg.setdefault("config_path", str(self.config_path))
            src = cls(cfg)
            # An explicitly-requested source is force-enabled.
            if self.requested_sources is not None or src.enabled():
                built.append(src)
        return built

    # ------------------------------------------------------------------

    def discover(self) -> dict[str, Any]:
        """Run sources and persist new candidates. Returns a summary dict."""
        target_ids, handles = self._existing_target_handles()

        raw: list[Candidate] = []
        per_source: dict[str, int] = {}
        errors: dict[str, str] = {}
        for src in self._build_sources():
            try:
                found = src.discover()
            except Exception as exc:  # defensive: sources should not raise
                logger.warning("Source %s raised: %s", src.name, exc, exc_info=True)
                errors[src.name] = str(exc)
                found = []
            per_source[src.name] = len(found)
            raw.extend(found)

        # Dedup within this run by candidate id.
        by_id: dict[str, Candidate] = {}
        for c in raw:
            by_id.setdefault(c.id, c)

        # Dedup against registered targets.
        deduped = dedupe_against_targets(by_id.values(), target_ids, handles)

        # Persist only genuinely new candidates.
        added: list[Candidate] = []
        for c in deduped:
            if self.store.upsert(c):
                added.append(c)
        if added:
            self.store.save()

        return {
            "per_source": per_source,
            "errors": errors,
            "found_total": len(raw),
            "new": len(added),
            "added": added,
            "store_path": str(self.store.path),
        }
