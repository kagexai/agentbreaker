"""Approve a discovered candidate -> register it as a target.

This is the ONLY path from discovery into the attack surface, and it is deliberately
explicit. Reuses the existing config_schema generators so a registered candidate is
indistinguishable from one added via `add-target`.

Authorization gate:
  - authorized_by_design candidates (curated public CTFs) get a sensible default.
  - everything else REQUIRES an explicit `authorized_by` -- approval is where the
    operator asserts they are allowed to test the target.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .. import ROOT
from ..config_schema import (
    detect_platform,
    detect_model_family,
    generate_platform_target,
    generate_llm_target,
    generate_target_entry,
    append_target_to_config,
)
from .base import Candidate, REGISTERED


class ApprovalError(Exception):
    pass


def _default_target_id(candidate: Candidate) -> str:
    base = candidate.model or candidate.name or candidate.url
    slug = re.sub(r"[^a-z0-9-]+", "-", base.lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or candidate.id


def approve_candidate(
    candidate: Candidate,
    *,
    config_path: Path | str = ROOT / "target_config.yaml",
    authorized_by: str | None = None,
    scope: str | None = None,
    target_id: str | None = None,
    user_inputs: dict[str, str] | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Build a target entry from a candidate and append it to target_config.yaml.

    Returns the generated entry (with its final id). Raises ApprovalError on missing
    authorization or when a model family cannot be resolved.
    """
    config_path = Path(config_path)

    # --- Authorization gate ---
    if not authorized_by:
        if candidate.authorized_by_design:
            authorized_by = "Self (public CTF -- open registration, no approval needed)"
        else:
            raise ApprovalError(
                f"Candidate '{candidate.id}' is not authorized-by-design; an explicit "
                f"--authorized-by is required to confirm you may test this target."
            )
    scope = scope or candidate.description or f"Assessment of {candidate.handle}"

    # --- Model candidate ---
    if candidate.kind == "model":
        family = detect_model_family(candidate.model)
        if family is None:
            raise ApprovalError(
                f"Could not detect a model family for '{candidate.model}'. Add a pattern "
                f"to platforms.yaml model_families or register it manually."
            )
        tid = target_id or _default_target_id(candidate)
        entry = generate_llm_target(
            model=candidate.model,
            family=family,
            system_prompt="",
            authorized_by=authorized_by,
            scope=scope,
            target_id=tid,
        )
        _append(entry, config_path)
        return entry

    # --- CTF candidate ---
    match = detect_platform(candidate.url) if candidate.url else None
    if match:
        entry = generate_platform_target(match, user_inputs=user_inputs or {})
        if target_id:
            entry["id"] = target_id
        if authorized_by:
            entry.setdefault("authorization", {})["authorized_by"] = authorized_by
        _append(entry, config_path)
        return entry

    # Unknown platform: build a generic entry the operator can refine.
    prov = provider or candidate.suggested_provider or "http"
    tid = target_id or _default_target_id(candidate)
    config: dict[str, Any] = {"url": candidate.url} if prov in ("http", "browser") else {}
    entry = generate_target_entry(
        target_id=tid,
        provider=prov,
        authorized_by=authorized_by,
        scope=scope,
        config=config,
        tags=list(candidate.tags) or ["discovered"],
    )
    _append(entry, config_path)
    return entry


def _append(entry: dict[str, Any], config_path: Path) -> None:
    try:
        append_target_to_config(entry, config_path)
    except ValueError as exc:
        raise ApprovalError(str(exc)) from exc


def mark_registered(candidate: Candidate, store) -> None:
    """Flip a candidate to REGISTERED in the store and persist."""
    candidate.status = REGISTERED
    store.update(candidate)
    store.save()
