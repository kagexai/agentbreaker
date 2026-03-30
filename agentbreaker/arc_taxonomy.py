from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import ROOT

TAXONOMY_PATH = ROOT / "taxonomy" / "arc_pi_taxonomy.json"
PRIMARY_DIMENSION_ORDER = ("inputs", "techniques", "evasions", "intents")
DERIVED_DIMENSION_ORDER = (
    "intent_playbooks",
    "intent_leaves",
    "technique_playbooks",
    "evasion_playbooks",
)
ARC_DIMENSION_ORDER = PRIMARY_DIMENSION_ORDER + DERIVED_DIMENSION_ORDER
_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "your",
    "their",
    "them",
    "model",
    "models",
    "using",
    "used",
    "attack",
    "attacks",
    "prompt",
    "prompts",
    "injection",
    "ai",
    "llm",
}


@lru_cache(maxsize=1)
def _precomputed_entry_tokens() -> dict[tuple[str, str], set[str]]:
    """Pre-tokenize every arc taxonomy entry once at load time.

    Key: (dimension, id).  Called lazily on first search so startup is free.
    """
    tokens: dict[tuple[str, str], set[str]] = {}
    for entry in arc_taxonomy_entries():
        fields = [
            entry.get("id", ""),
            entry.get("title", ""),
            entry.get("description", ""),
            entry.get("path_text", ""),
            " ".join(entry.get("path", [])),
            " ".join(entry.get("ideas", [])),
            " ".join(entry.get("attack_surfaces", [])),
            " ".join(entry.get("sample_prompt_injections", [])),
            " ".join(entry.get("defensive_notes", [])),
            " ".join(entry.get("examples", [])),
            " ".join(entry.get("attacks", [])),
            " ".join(entry.get("notes", [])),
            " ".join(entry.get("subsections", [])),
            entry.get("body", ""),
        ]
        haystack = " ".join(str(f or "") for f in fields)
        key = (entry.get("dimension", ""), entry.get("id", ""))
        tokens[key] = _tokenize(haystack, add_stems=True)
    return tokens


@lru_cache(maxsize=1)
def load_arc_taxonomy() -> dict[str, Any]:
    if not TAXONOMY_PATH.exists():
        return {"source": {}, "dimensions": {}, "derived_dimensions": {}, "counts": {}}
    data = json.loads(TAXONOMY_PATH.read_text())
    if not isinstance(data, dict):
        return {"source": {}, "dimensions": {}, "derived_dimensions": {}, "counts": {}}
    return data


def arc_taxonomy_source() -> dict[str, Any]:
    source = load_arc_taxonomy().get("source") or {}
    return source if isinstance(source, dict) else {}


def arc_taxonomy_counts() -> dict[str, int]:
    counts = load_arc_taxonomy().get("counts") or {}
    if isinstance(counts, dict) and counts:
        normalized: dict[str, int] = {}
        for key, value in counts.items():
            try:
                normalized[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        if normalized:
            return normalized
    return {
        dimension: len(arc_taxonomy_entries(dimension))
        for dimension in ARC_DIMENSION_ORDER
    }


def _normalize_text_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    items: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            items.append(text)
    return items


def _normalize_path(value: Any) -> tuple[list[str], str]:
    if isinstance(value, list):
        parts = [str(item or "").strip() for item in value if str(item or "").strip()]
    elif isinstance(value, str):
        parts = [part.strip() for part in value.split(">") if part.strip()]
    else:
        parts = []
    return parts, " > ".join(parts)


def _normalize_entry(entry: Any, dim: str) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    path, path_text = _normalize_path(entry.get("path") or entry.get("path_text"))
    normalized = {
        "dimension": dim,
        "id": str(entry.get("id", "") or ""),
        "title": str(entry.get("title", "") or ""),
        "description": str(entry.get("description", "") or ""),
        "ideas": _normalize_text_list(entry.get("ideas")),
        "path": path,
        "path_text": str(entry.get("path_text", "") or path_text),
        "attack_surfaces": _normalize_text_list(entry.get("attack_surfaces")),
        "sample_prompt_injections": _normalize_text_list(entry.get("sample_prompt_injections")),
        "defensive_notes": _normalize_text_list(entry.get("defensive_notes")),
        "examples": _normalize_text_list(entry.get("examples")),
        "attacks": _normalize_text_list(entry.get("attacks")),
        "notes": _normalize_text_list(entry.get("notes")),
        "subsections": _normalize_text_list(entry.get("subsections")),
        "body": str(entry.get("body", "") or ""),
    }
    return normalized


def arc_taxonomy_entries(dimension: str | None = None) -> list[dict[str, Any]]:
    data = load_arc_taxonomy()
    primary = data.get("dimensions") or {}
    derived = data.get("derived_dimensions") or {}

    if not isinstance(primary, dict):
        primary = {}
    if not isinstance(derived, dict):
        derived = {}

    def _collect(entries: Any, dim: str) -> list[dict[str, Any]]:
        if not isinstance(entries, list):
            return []
        normalized: list[dict[str, Any]] = []
        for entry in entries:
            item = _normalize_entry(entry, dim)
            if item:
                normalized.append(item)
        return normalized

    if dimension:
        if dimension in primary:
            return _collect(primary.get(dimension) or [], dimension)
        return _collect(derived.get(dimension) or [], dimension)

    flattened: list[dict[str, Any]] = []
    for dim in ARC_DIMENSION_ORDER:
        if dim in primary:
            flattened.extend(_collect(primary.get(dim) or [], dim))
        else:
            flattened.extend(_collect(derived.get(dim) or [], dim))
    return flattened


def _tokenize(text: str, *, add_stems: bool = True) -> set[str]:
    tokens: set[str] = set()
    for token in re.findall(r"[a-z0-9_]{3,}", text.lower()):
        if token in _STOPWORDS:
            continue
        tokens.add(token)
        if add_stems and token.endswith("s") and len(token) > 4:
            tokens.add(token[:-1])
    return tokens


def search_arc_taxonomy(
    query: str,
    *,
    dimension: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    query_lower = query.lower().strip()
    raw_query_tokens = _tokenize(query, add_stems=False)
    query_tokens = _tokenize(query, add_stems=True)
    if not raw_query_tokens:
        return []
    min_overlap = 2 if len(raw_query_tokens) >= 2 else 1

    precomputed = _precomputed_entry_tokens()
    ranked: list[tuple[int, dict[str, Any]]] = []
    for entry in arc_taxonomy_entries(dimension):
        entry_tokens = precomputed.get(
            (entry.get("dimension", ""), entry.get("id", "")), set()
        )
        raw_overlap = raw_query_tokens & entry_tokens
        overlap = query_tokens & entry_tokens
        # Substring fallback: build haystack_lower only when token overlap is insufficient
        if len(raw_overlap) < min_overlap:
            haystack_lower = " ".join([
                entry.get("id", ""), entry.get("title", ""), entry.get("description", ""),
                entry.get("path_text", ""), entry.get("body", ""),
            ]).lower()
            if query_lower not in haystack_lower:
                continue
        score = len(overlap) * 10
        for field_name in ("id", "title", "path_text"):
            value = str(entry.get(field_name, "") or "").lower()
            if value and query_lower in value:
                score += 12
            if value and value in query_lower:
                score += 8
        if any(query_lower in value.lower() for value in entry.get("subsections", [])):
            score += 6
        if entry.get("dimension") == "intent_leaves":
            score += 2
        item = dict(entry)
        item["match_score"] = score
        ranked.append((score, item))

    ranked.sort(
        key=lambda item: (
            item[0],
            item[1].get("dimension", ""),
            item[1].get("id", ""),
        ),
        reverse=True,
    )
    return [entry for _, entry in ranked[:limit]]


def relevant_arc_taxonomy(*texts: Any, limit_per_dim: int = 4) -> dict[str, list[dict[str, Any]]]:
    query = " ".join(str(text or "") for text in texts if str(text or "").strip())
    matches: dict[str, list[dict[str, Any]]] = {}
    for dimension in ARC_DIMENSION_ORDER:
        hits = search_arc_taxonomy(query, dimension=dimension, limit=limit_per_dim)
        if hits:
            matches[dimension] = hits
    return matches


def _entry_label(entry: dict[str, Any]) -> str:
    path_text = str(entry.get("path_text", "") or "").strip()
    if path_text:
        return path_text
    return str(entry.get("title", "") or entry.get("id", "") or "").strip()


def format_arc_taxonomy_matches(
    matches: dict[str, list[dict[str, Any]]],
    *,
    include_descriptions: bool = False,
) -> str:
    if not matches:
        return "(no strong direct Arc PI taxonomy matches)"

    lines: list[str] = []
    for dimension in ARC_DIMENSION_ORDER:
        entries = matches.get(dimension) or []
        if not entries:
            continue
        if include_descriptions:
            joined = " | ".join(
                f"{entry['id']} ({_entry_label(entry)}): {entry.get('description', '')}"
                for entry in entries
            )
        else:
            joined = "; ".join(
                f"{entry['id']} ({_entry_label(entry)})"
                for entry in entries
            )
        lines.append(f"{dimension}: {joined}")
    return "\n".join(lines)


def arc_taxonomy_reference_text(*, include_descriptions: bool = False) -> str:
    lines: list[str] = []
    for dimension in ARC_DIMENSION_ORDER:
        entries = arc_taxonomy_entries(dimension)
        if not entries:
            continue
        if include_descriptions:
            lines.append(f"{dimension}:")
            lines.extend(
                f"- {entry['id']} ({_entry_label(entry)}): {entry.get('description', '')}"
                for entry in entries
            )
            continue
        joined = "; ".join(
            f"{entry['id']} ({_entry_label(entry)})"
            for entry in entries
        )
        lines.append(f"{dimension}: {joined}")
    return "\n".join(lines)
