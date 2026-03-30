from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_FLAG_PATTERNS = (
    re.compile(r"\b(?:WIZ_CTF|FLAG)\{[^}\n]{3,300}\}", re.IGNORECASE),
    re.compile(r"\b[A-Z][A-Z0-9_]{2,32}\{[^}\n]{3,300}\}"),
)
_LOW_CONFIDENCE_MARKERS = (
    "atk-",
    "canary",
    "placeholder",
    "example",
    "dummy",
    "sample",
    "redacted",
    "_extracted",
    "_test",
)
_HIGH_CONFIDENCE_MARKERS = (
    "wiz_ctf{",
    "flag{",
    "challenge_",
)
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _walk_strings(value: Any) -> list[str]:
    out: list[str] = []
    if value is None:
        return out
    if isinstance(value, str):
        out.append(value)
        return out
    if isinstance(value, dict):
        for item in value.values():
            out.extend(_walk_strings(item))
        return out
    if isinstance(value, (list, tuple, set)):
        for item in value:
            out.extend(_walk_strings(item))
        return out
    out.append(str(value))
    return out


def extract_flag_candidates(*values: Any) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for value in values:
        for text in _walk_strings(value):
            for pattern in _FLAG_PATTERNS:
                for match in pattern.findall(text):
                    flag = str(match).strip()
                    lowered = flag.lower()
                    if lowered in seen:
                        continue
                    seen.add(lowered)
                    candidates.append(flag)
    return candidates


def flag_stage_number(flag: str) -> int | None:
    lowered = str(flag or "").strip().lower()
    if not lowered:
        return None
    match = re.search(r"challenge[_-](\d+)", lowered)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def flag_confidence(flag: str, attack_id: str = "") -> tuple[str, list[str]]:
    lowered = flag.lower().strip()
    reasons: list[str] = []

    if attack_id and attack_id.lower() in lowered:
        reasons.append("contains_attack_id")
    if any(marker in lowered for marker in _LOW_CONFIDENCE_MARKERS):
        reasons.append("synthetic_marker")
    if any(marker in lowered for marker in _HIGH_CONFIDENCE_MARKERS):
        reasons.append("ctf_flag_pattern")

    if "synthetic_marker" in reasons:
        return "low", reasons
    if "ctf_flag_pattern" in reasons:
        return "high", reasons
    return "medium", reasons


def load_state(path: Path, target_id: str) -> dict[str, Any]:
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except Exception:
            data = {}
    else:
        data = {}

    if not isinstance(data, dict):
        data = {}

    data.setdefault("target_id", target_id)
    data.setdefault("updated_at", _now())
    data.setdefault("current_challenge", {})
    data.setdefault("challenge_history", [])
    data.setdefault("challenges", {})
    data.setdefault("flags", [])
    return data


def save_state(path: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = _now()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=False) + "\n")


def observe_challenge(state: dict[str, Any], challenge: dict[str, Any], *, source: str = "provider") -> None:
    challenge_id = challenge.get("id")
    if challenge_id in (None, ""):
        return

    challenge_key = str(challenge_id)
    challenges = state.setdefault("challenges", {})
    entry = challenges.setdefault(
        challenge_key,
        {
            "id": challenge_id,
            "title": "",
            "description": "",
            "first_seen_at": _now(),
            "last_seen_at": _now(),
            "sources": [],
            "discovered_flags": [],
            "submitted_flags": [],
        },
    )
    entry["id"] = challenge_id
    entry["title"] = str(challenge.get("title") or entry.get("title") or "")
    entry["description"] = str(challenge.get("description") or entry.get("description") or "")
    entry["last_seen_at"] = _now()
    if source and source not in entry["sources"]:
        entry["sources"].append(source)

    state["current_challenge"] = {
        "id": challenge_id,
        "title": entry["title"],
        "description": entry["description"],
        "observed_at": entry["last_seen_at"],
    }
    history = state.setdefault("challenge_history", [])
    if challenge_key not in history:
        history.append(challenge_key)


def remember_flag(
    state: dict[str, Any],
    flag: str,
    *,
    attack_id: str = "",
    challenge_id: Any = None,
    source: str = "response",
    confidence: str | None = None,
    confidence_reasons: list[str] | None = None,
) -> dict[str, Any]:
    flags = state.setdefault("flags", [])
    existing = next((item for item in flags if item.get("value") == flag), None)
    if existing is None:
        existing = {
            "value": flag,
            "first_seen_at": _now(),
            "last_seen_at": _now(),
            "sources": [],
            "attack_ids": [],
            "challenge_ids": [],
            "confidence": "low",
            "confidence_reasons": [],
            "submitted": False,
            "submission_attempts": [],
        }
        flags.append(existing)

    existing["last_seen_at"] = _now()
    if source and source not in existing["sources"]:
        existing["sources"].append(source)
    if attack_id and attack_id not in existing["attack_ids"]:
        existing["attack_ids"].append(attack_id)
    if challenge_id not in (None, ""):
        challenge_key = str(challenge_id)
        if challenge_key not in existing["challenge_ids"]:
            existing["challenge_ids"].append(challenge_key)
        challenge_entry = state.setdefault("challenges", {}).setdefault(
            challenge_key,
            {
                "id": challenge_id,
                "title": "",
                "description": "",
                "first_seen_at": _now(),
                "last_seen_at": _now(),
                "sources": [],
                "discovered_flags": [],
                "submitted_flags": [],
            },
        )
        if flag not in challenge_entry["discovered_flags"]:
            challenge_entry["discovered_flags"].append(flag)

    confidence = confidence or existing.get("confidence") or "low"
    confidence_reasons = confidence_reasons or []
    if _CONFIDENCE_RANK.get(confidence, 0) >= _CONFIDENCE_RANK.get(existing.get("confidence", "low"), 0):
        existing["confidence"] = confidence
        existing["confidence_reasons"] = confidence_reasons

    return existing


def pending_flags(state: dict[str, Any], *, min_confidence: str = "high") -> list[dict[str, Any]]:
    threshold = _CONFIDENCE_RANK.get(min_confidence, 2)
    pending: list[dict[str, Any]] = []
    for flag in state.get("flags", []):
        if flag.get("submitted"):
            continue
        if _CONFIDENCE_RANK.get(str(flag.get("confidence", "low")), 0) < threshold:
            continue
        pending.append(flag)
    return pending


def mark_flag_submission(
    state: dict[str, Any],
    flag: str,
    *,
    accepted: bool,
    response_excerpt: str = "",
    challenge_before: Any = None,
    challenge_after: Any = None,
) -> dict[str, Any] | None:
    entry = next((item for item in state.get("flags", []) if item.get("value") == flag), None)
    if entry is None:
        return None

    submission = {
        "ts": _now(),
        "accepted": accepted,
        "response_excerpt": response_excerpt[:400],
        "challenge_before": challenge_before,
        "challenge_after": challenge_after,
    }
    entry.setdefault("submission_attempts", []).append(submission)
    if accepted:
        entry["submitted"] = True
        entry["submitted_at"] = submission["ts"]
        for challenge_id in entry.get("challenge_ids", []):
            challenge_entry = state.get("challenges", {}).get(str(challenge_id))
            if challenge_entry and flag not in challenge_entry.get("submitted_flags", []):
                challenge_entry.setdefault("submitted_flags", []).append(flag)
    return entry


def state_summary(state: dict[str, Any]) -> dict[str, Any]:
    current = state.get("current_challenge") or {}
    flags = state.get("flags") or []
    submitted = sum(1 for item in flags if item.get("submitted"))
    pending = sum(
        1
        for item in flags
        if not item.get("submitted") and item.get("confidence") == "high"
    )
    return {
        "current_challenge": {
            "id": current.get("id"),
            "title": current.get("title", ""),
            "description": current.get("description", ""),
        },
        "challenge_count": len(state.get("challenges") or {}),
        "flag_count": len(flags),
        "submitted_flag_count": submitted,
        "pending_high_confidence_flags": pending,
    }
