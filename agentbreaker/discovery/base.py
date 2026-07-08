"""Core data structures for target discovery."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


def _slug(text: str) -> str:
    text = re.sub(r"^https?://", "", (text or "").strip().lower())
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "candidate"


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


# Candidate lifecycle states.
NEW = "new"
APPROVED = "approved"
REJECTED = "rejected"
REGISTERED = "registered"


@dataclass
class Candidate:
    """A discovered, not-yet-attacked target.

    `kind` is "ctf" (a public challenge with a URL) or "model" (an LLM to assess).
    `authorized_by_design` is True only for sources that are public-by-construction
    (a known CTF platform / your-own-API model); everything else needs the operator
    to confirm authorization at approval time.
    """
    kind: str                       # "ctf" | "model"
    name: str
    source: str                     # which DiscoverySource produced it
    url: str = ""                   # for ctf targets
    model: str = ""                 # for model targets
    description: str = ""
    category: str = ""              # e.g. prompt_injection, jailbreak, guardrail
    tags: list[str] = field(default_factory=list)
    suggested_provider: str = ""    # script | http | browser | llm
    metadata: dict[str, Any] = field(default_factory=dict)
    authorized_by_design: bool = False
    needs_verification: bool = False
    status: str = NEW
    discovered_at: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if not self.discovered_at:
            self.discovered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.id:
            self.id = self.compute_id()

    def compute_id(self) -> str:
        """Stable id derived from the identifying handle (url or model or name)."""
        handle = self.url or self.model or self.name
        return f"{self.kind}-{_slug(handle)[:40]}-{_short_hash(handle)}"

    @property
    def handle(self) -> str:
        return self.url or self.model or self.name

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Candidate":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


class CandidateStore:
    """Append-and-replace JSONL store of candidates, keyed by candidate id."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._items: dict[str, Candidate] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                cand = Candidate.from_dict(json.loads(line))
                self._items[cand.id] = cand
            except Exception:
                logger.debug("Skipping malformed candidate line", exc_info=True)

    def all(self) -> list[Candidate]:
        return list(self._items.values())

    def get(self, candidate_id: str) -> Candidate | None:
        return self._items.get(candidate_id)

    def filter(self, *, status: str | None = None, kind: str | None = None) -> list[Candidate]:
        out = self.all()
        if status:
            out = [c for c in out if c.status == status]
        if kind:
            out = [c for c in out if c.kind == kind]
        return out

    def has(self, candidate_id: str) -> bool:
        return candidate_id in self._items

    def upsert(self, candidate: Candidate) -> bool:
        """Insert a new candidate. Returns True if newly added, False if it existed."""
        if candidate.id in self._items:
            return False
        self._items[candidate.id] = candidate
        return True

    def update(self, candidate: Candidate) -> None:
        self._items[candidate.id] = candidate

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".jsonl.tmp")
        with tmp.open("w") as f:
            for cand in self._items.values():
                f.write(json.dumps(cand.to_dict()) + "\n")
        import os
        os.replace(tmp, self.path)


class DiscoverySource:
    """Base class for a discovery source. Subclasses must be offline-graceful:
    network/parse failures should be logged and yield an empty list, never raise."""

    name: str = "base"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def enabled(self) -> bool:
        return True

    def discover(self) -> list[Candidate]:  # pragma: no cover - abstract
        raise NotImplementedError


def dedupe_against_targets(
    candidates: Iterable[Candidate],
    existing_target_ids: set[str],
    existing_handles: set[str],
) -> list[Candidate]:
    """Drop candidates that already correspond to a registered target.

    Matches on either a derived target id collision or a known url/model handle.
    """
    out: list[Candidate] = []
    seen_handles = {h.lower() for h in existing_handles if h}
    for c in candidates:
        handle = c.handle.lower()
        # crude id overlap: a candidate whose slug already appears as a target id
        slug = _slug(c.handle)
        if any(slug and slug in tid for tid in existing_target_ids):
            continue
        if handle and handle in seen_handles:
            continue
        out.append(c)
    return out
