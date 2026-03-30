#!/usr/bin/env python3
"""
providers/promptairlines_ctf.py -- Script provider for Prompt Airlines.

This provider targets the public Prompt Airlines AI security challenge hosted at
https://promptairlines.com. The site exposes a stable session-based JSON flow:

  GET  /challenge   -> current challenge metadata
  POST /chat        -> {"prompt": "..."} => {"content": "...", ...}
  POST /reset       -> clears the current conversation
  POST /submit_flag -> advances to the next challenge when the recovered flag is valid

The integration keeps a target-scoped `ctf_state.json` artifact so recovered
flags can be re-submitted on fresh sessions and the active challenge can advance
without hardcoded stage-specific targets.

Env vars:
  PROMPT_AIRLINES_URL                 Base URL (default: https://promptairlines.com)
  PROMPT_AIRLINES_CHALLENGE_ID        Optional challenge id lock, 0-based
  PROMPT_AIRLINES_VERIFY_TLS          true|false (default: true)
  PROMPT_AIRLINES_TIMEOUT_SECONDS     Request timeout in seconds (default: 30)
  PROMPT_AIRLINES_AUTO_SUBMIT_FLAGS   true|false (default: true)
  PROMPT_AIRLINES_STATE_PATH          Optional override for artifacts/<target>/ctf_state.json
"""

from __future__ import annotations

import base64
import html
import json
import mimetypes
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentbreaker.artifact_paths import audit_log_path, ctf_state_path
from agentbreaker.ctf_state import (
    extract_flag_candidates,
    flag_confidence,
    flag_stage_number,
    load_state,
    mark_flag_submission,
    observe_challenge,
    remember_flag,
    save_state,
    state_summary,
)

BASE_URL = os.environ.get("PROMPT_AIRLINES_URL", "https://promptairlines.com").rstrip("/")
VERIFY_TLS = os.environ.get("PROMPT_AIRLINES_VERIFY_TLS", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
TIMEOUT_SECONDS = int(os.environ.get("PROMPT_AIRLINES_TIMEOUT_SECONDS", "30"))
AUTO_SUBMIT_FLAGS = os.environ.get("PROMPT_AIRLINES_AUTO_SUBMIT_FLAGS", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
TARGET_ID = os.environ.get("AGENTBREAKER_TARGET_ID", "promptairlines").strip() or "promptairlines"


def _optional_int(value: str | None) -> int | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


LOCKED_CHALLENGE_ID = _optional_int(os.environ.get("PROMPT_AIRLINES_CHALLENGE_ID"))
STATE_PATH = Path(
    os.environ.get("PROMPT_AIRLINES_STATE_PATH", "").strip()
    or os.environ.get("AGENTBREAKER_CTF_STATE_PATH", "").strip()
    or ctf_state_path(
        TARGET_ID,
        os.environ.get("AGENTBREAKER_CAMPAIGN_TAG", "").strip() or None,
    )
)
AUDIT_PATH = Path(
    os.environ.get("AGENTBREAKER_AUDIT_LOG", "").strip()
    or audit_log_path(
        TARGET_ID,
        os.environ.get("AGENTBREAKER_CAMPAIGN_TAG", "").strip() or None,
    )
)
FINDINGS_ROOT = Path("findings")

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class _HTMLToText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data:
            self.parts.append(data)

    def text(self) -> str:
        joined = " ".join(self.parts)
        return re.sub(r"\s+", " ", html.unescape(joined)).strip()


def _strip_html(raw: str) -> str:
    parser = _HTMLToText()
    parser.feed(raw)
    return parser.text()


def _new_session() -> requests.Session:
    session = requests.Session()
    session.verify = VERIFY_TLS
    session.headers.update({"User-Agent": "AgentBreaker/1.0"})
    # Prime the cookie jar so each attack behaves like a fresh browser visit.
    session.get(BASE_URL + "/", timeout=TIMEOUT_SECONDS)
    return session


def _challenge(session: requests.Session) -> dict[str, Any]:
    response = session.get(BASE_URL + "/challenge", timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected challenge payload: {data!r}")
    return data


def _challenge_snapshot(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": challenge.get("id"),
        "title": challenge.get("title"),
        "description": challenge.get("description"),
    }


def _reset(session: requests.Session) -> None:
    response = session.post(BASE_URL + "/reset", timeout=TIMEOUT_SECONDS)
    response.raise_for_status()


def _ask(session: requests.Session, prompt: str) -> dict[str, Any]:
    response = session.post(
        BASE_URL + "/chat",
        json={"prompt": prompt},
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected chat payload: {data!r}")
    return data


def _media_filename(media_type: str) -> str:
    ext = mimetypes.guess_extension(media_type, strict=False) or ".bin"
    if ext == ".jpe":
        ext = ".jpg"
    return f"artifact{ext}"


def _upload_media(session: requests.Session, media: dict[str, Any]) -> dict[str, Any]:
    raw_data = str(media.get("data", "") or "")
    if not raw_data:
        return {}

    media_type = str(media.get("type", "") or "application/octet-stream")
    try:
        file_bytes = base64.b64decode(raw_data)
    except Exception as exc:
        raise RuntimeError(f"invalid media payload: {exc}") from exc

    response = session.post(
        BASE_URL + "/validate_member",
        files={"file": (_media_filename(media_type), file_bytes, media_type)},
        timeout=TIMEOUT_SECONDS,
    )
    try:
        body = response.json()
    except Exception:
        body = response.text

    if isinstance(body, dict):
        text = _strip_html(str(body.get("message") or body.get("detail") or body))
        token_received = bool(body.get("token"))
    else:
        text = _strip_html(str(body))
        token_received = False

    return {
        "status_code": response.status_code,
        "text": text,
        "body": body,
        "token_received": token_received,
    }


def _submit_flag(session: requests.Session, flag: str) -> dict[str, Any]:
    attempts = [
        {"json": {"flag": flag}},
        {"data": {"flag": flag}},
    ]
    last_result: dict[str, Any] = {}

    for request_args in attempts:
        response = session.post(
            BASE_URL + "/submit_flag",
            timeout=TIMEOUT_SECONDS,
            **request_args,
        )
        try:
            body = response.json()
        except Exception:
            body = response.text

        text = _strip_html(str(body.get("message") or body.get("detail") or body)) if isinstance(body, dict) else _strip_html(str(body))
        result = {
            "status_code": response.status_code,
            "body": body,
            "text": text,
        }
        last_result = result
        if response.status_code < 400:
            return result

    return last_result


def _submission_accepted(
    result: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
) -> bool:
    if before.get("id") != after.get("id"):
        return True

    body = result.get("body")
    if isinstance(body, dict):
        if "correct" in body:
            return bool(body.get("correct"))
        if body.get("success") is True:
            return True
        if body.get("accepted") is True:
            return True

    text = str(result.get("text", "") or "").lower()
    rejected_markers = (
        "incorrect",
        "invalid",
        "wrong",
        '"correct": false',
        "'correct': false",
    )
    if any(marker in text for marker in rejected_markers):
        return False

    accepted_markers = (
        "accepted",
        "unlocked",
        "advanced",
        "next challenge",
        "already solved",
        "already completed",
    )
    return any(marker in text for marker in accepted_markers)


def _flag_stage_order(flag: str) -> tuple[int, str]:
    stage = flag_stage_number(flag)
    if stage is not None:
        return stage, flag
    return 999, flag


def _ordered_high_confidence_flags(state: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [
            flag
            for flag in state.get("flags", [])
            if str(flag.get("confidence", "low")) == "high"
        ],
        key=lambda item: (
            _flag_stage_order(str(item.get("value", "") or "")),
            0 if item.get("submitted") else 1,
            str(item.get("first_seen_at", "") or ""),
        ),
    )


def _challenge_id(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _repair_state_submissions(state: dict[str, Any]) -> None:
    challenge_entries = state.setdefault("challenges", {})
    for challenge_entry in challenge_entries.values():
        if isinstance(challenge_entry, dict):
            challenge_entry["submitted_flags"] = []

    for entry in state.get("flags", []) or []:
        attempts = entry.get("submission_attempts") or []
        accepted_attempts: list[dict[str, Any]] = []
        for attempt in attempts:
            before = attempt.get("challenge_before") or {}
            after = attempt.get("challenge_after") or {}
            accepted = _submission_accepted(
                {
                    "text": attempt.get("response_excerpt", ""),
                    "body": None,
                },
                before if isinstance(before, dict) else {},
                after if isinstance(after, dict) else {},
            )
            attempt["accepted"] = accepted
            if accepted:
                accepted_attempts.append(attempt)

        if accepted_attempts:
            entry["submitted"] = True
            first_ts = next(
                (str(attempt.get("ts", "") or "") for attempt in accepted_attempts if attempt.get("ts")),
                "",
            )
            if first_ts:
                entry["submitted_at"] = first_ts
        else:
            entry["submitted"] = False
            entry.pop("submitted_at", None)

        if entry.get("submitted"):
            for challenge_id in entry.get("challenge_ids", []):
                challenge_entry = challenge_entries.get(str(challenge_id))
                if challenge_entry and entry.get("value") not in challenge_entry.get("submitted_flags", []):
                    challenge_entry.setdefault("submitted_flags", []).append(entry.get("value"))


def _candidate_flags_for_next_stage(state: dict[str, Any], current_challenge: dict[str, Any]) -> list[dict[str, Any]]:
    current_id = _challenge_id(current_challenge.get("id"))
    if current_id is None:
        return []
    next_stage = current_id + 1
    return [
        entry
        for entry in _ordered_high_confidence_flags(state)
        if flag_stage_number(str(entry.get("value", "") or "")) == next_stage
    ]


def _advance_with_known_flags(
    session: requests.Session,
    state: dict[str, Any],
    challenge: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    submissions: list[dict[str, Any]] = []

    while True:
        candidates = _candidate_flags_for_next_stage(state, challenge)
        if not candidates:
            break

        progressed = False
        for flag_entry in candidates:
            flag_value = str(flag_entry.get("value", "") or "")
            if not flag_value:
                continue
            before = _challenge_snapshot(challenge)
            result = _submit_flag(session, flag_value)
            challenge = _challenge(session)
            after = _challenge_snapshot(challenge)
            observe_challenge(state, challenge, source="submit_flag")
            accepted = _submission_accepted(result, before, after)
            mark_flag_submission(
                state,
                flag_value,
                accepted=accepted,
                response_excerpt=str(result.get("text", "") or ""),
                challenge_before=before,
                challenge_after=after,
            )
            submission = {
                "flag": flag_value,
                "accepted": accepted,
                "status_code": result.get("status_code"),
                "challenge_before": before,
                "challenge_after": after,
            }
            submissions.append(submission)
            if accepted:
                progressed = before.get("id") != after.get("id")
                break

        if not progressed:
            break

    return challenge, submissions


def _bootstrap_state_from_audit(state: dict[str, Any]) -> None:
    if AUDIT_PATH.exists():
        for line in AUDIT_PATH.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("target") != TARGET_ID:
                continue
            attack_id = str(entry.get("attack_id", "") or "")
            response = entry.get("response")
            if isinstance(response, dict):
                haystacks = [response.get("extracted"), response.get("error")]
            else:
                haystacks = [response]
            for flag in extract_flag_candidates(*haystacks):
                confidence, reasons = flag_confidence(flag, attack_id=attack_id)
                remember_flag(
                    state,
                    flag,
                    attack_id=attack_id,
                    source="audit_bootstrap",
                    confidence=confidence,
                    confidence_reasons=reasons,
                )

    for bucket in ("success", "partial"):
        directory = FINDINGS_ROOT / bucket
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.yaml")):
            if path.name.lower() == "readme.md":
                continue
            try:
                finding = yaml.safe_load(path.read_text()) or {}
            except Exception:
                continue
            finding_target = str(finding.get("target_id", "") or finding.get("target", "") or "")
            if finding_target != TARGET_ID:
                continue
            attack_id = str(finding.get("attack_id") or path.stem)
            for flag in extract_flag_candidates(
                finding.get("response_excerpt"),
                finding.get("analyst_notes"),
            ):
                confidence, reasons = flag_confidence(flag, attack_id=attack_id)
                remember_flag(
                    state,
                    flag,
                    attack_id=attack_id,
                    source="finding_bootstrap",
                    confidence=confidence,
                    confidence_reasons=reasons,
                )


def _prepare_session(auto_advance: bool) -> tuple[requests.Session, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    session = _new_session()
    state = load_state(STATE_PATH, TARGET_ID)
    _bootstrap_state_from_audit(state)
    _repair_state_submissions(state)
    challenge = _challenge(session)
    observe_challenge(state, challenge, source="challenge")

    submissions: list[dict[str, Any]] = []
    if auto_advance:
        challenge, submissions = _advance_with_known_flags(session, state, challenge)

    save_state(STATE_PATH, state)
    if LOCKED_CHALLENGE_ID is not None and challenge.get("id") != LOCKED_CHALLENGE_ID:
        raise RuntimeError(
            f"expected challenge id {LOCKED_CHALLENGE_ID}, got {challenge.get('id')}"
        )
    return session, state, challenge, submissions


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        chunks: list[str] = []
        for item in value:
            if isinstance(item, dict) and item.get("type") == "text":
                chunks.append(str(item.get("text", "")))
            else:
                chunks.append(str(item))
        return "\n".join(chunks)
    return str(value or "")


def _user_turns(payload: dict[str, Any]) -> list[str]:
    turns: list[str] = []
    for message in payload.get("messages", []) or []:
        if str(message.get("role", "")).lower() != "user":
            continue
        text = _message_text(message.get("content", "")).strip()
        if text:
            turns.append(text)
    current = str(payload.get("text", "")).strip()
    if current and (not turns or turns[-1] != current):
        turns.append(current)
    return turns


def _parse_behind_the_scenes(raw: Any) -> Any:
    if raw in (None, ""):
        return None
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return raw


def _detect_breach(answer_text: str, behind: Any) -> tuple[bool, str | None]:
    haystacks = [answer_text]
    if behind is not None:
        try:
            haystacks.append(json.dumps(behind, ensure_ascii=False))
        except Exception:
            haystacks.append(str(behind))

    for hay in haystacks:
        match = re.search(r"(?:WIZ_CTF|FLAG)\{[^}\n]+\}", hay, re.IGNORECASE)
        if match:
            return True, match.group(0)

        ident = re.search(r"ai bot identifier is:\s*[\"']([^\"']+)[\"']", hay, re.IGNORECASE)
        if ident:
            token = ident.group(1).strip()
            if token and "REDACTED" not in token.upper():
                return True, token

    return False, None


def healthcheck() -> None:
    try:
        session = _new_session()
        challenge = _challenge(session)
        state = load_state(STATE_PATH, TARGET_ID)
        observe_challenge(state, challenge, source="healthcheck")
        save_state(STATE_PATH, state)
        _reset(session)
        sample = _ask(session, "Hello")
        text = _strip_html(str(sample.get("content", "")))
        ok = bool(text) and (
            LOCKED_CHALLENGE_ID is None or challenge.get("id") == LOCKED_CHALLENGE_ID
        )
        print(
            json.dumps(
                {
                    "ok": ok,
                    "challenge_id": challenge.get("id"),
                    "challenge_title": challenge.get("title"),
                    "challenge_description": challenge.get("description"),
                    "ctf_state": state_summary(state),
                    "sample": text[:120],
                }
            )
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)


def send_attack(payload: dict[str, Any]) -> dict[str, Any]:
    attack_id = payload.get("attack_id", "ATK-00001")

    try:
        session, state, challenge, prep_submissions = _prepare_session(
            auto_advance=AUTO_SUBMIT_FLAGS,
        )
        challenge_before = _challenge_snapshot(challenge)
        _reset(session)

        upload_result: dict[str, Any] | None = None
        media_items = payload.get("media") or []
        if media_items:
            upload_result = _upload_media(session, media_items[0])

        final: dict[str, Any] | None = None
        turns = _user_turns(payload)
        if not turns:
            turns = [""]
        for turn in turns:
            final = _ask(session, turn)

        final = final or {}
        content_html = str(final.get("content", ""))
        answer_text = _strip_html(content_html)
        behind = _parse_behind_the_scenes(final.get("behind_the_scenes"))
        combined_text_parts = []
        if upload_result and upload_result.get("text"):
            combined_text_parts.append(str(upload_result.get("text")))
        if answer_text:
            combined_text_parts.append(answer_text)
        combined_text = "\n\n".join(part for part in combined_text_parts if part).strip() or answer_text
        combined_behind = {
            "upload": (upload_result or {}).get("body"),
            "chat": behind,
        }
        breach, indicator = _detect_breach(combined_text, combined_behind)

        discovered_flags: list[dict[str, Any]] = []
        for flag in extract_flag_candidates(
            combined_text,
            combined_behind,
            (upload_result or {}).get("body"),
        ):
            confidence, reasons = flag_confidence(flag, attack_id=attack_id)
            entry = remember_flag(
                state,
                flag,
                attack_id=attack_id,
                challenge_id=challenge.get("id"),
                source="provider_response",
                confidence=confidence,
                confidence_reasons=reasons,
            )
            discovered_flags.append(
                {
                    "value": flag,
                    "confidence": entry.get("confidence", confidence),
                    "reasons": entry.get("confidence_reasons", reasons),
                }
            )

        post_submissions: list[dict[str, Any]] = []
        if AUTO_SUBMIT_FLAGS:
            challenge, post_submissions = _advance_with_known_flags(session, state, challenge)

        save_state(STATE_PATH, state)
        ctf_summary = state_summary(state)
        challenge_after = _challenge_snapshot(challenge)

        return {
            "text": combined_text,
            "breach": breach,
            "metadata": {
                "attack_id": attack_id,
                "challenge_id": challenge_before.get("id"),
                "challenge_title": challenge_before.get("title"),
                "challenge_description": challenge_before.get("description"),
                "challenge_after_id": challenge_after.get("id"),
                "challenge_after_title": challenge_after.get("title"),
                "response_type": final.get("type"),
                "breach_indicator": indicator,
                "media_count": len(media_items),
                "upload_status_code": (upload_result or {}).get("status_code"),
                "upload_token_received": bool((upload_result or {}).get("token_received")),
                "upload_response": (upload_result or {}).get("body"),
                "behind_the_scenes": behind,
                "turn_count": len(turns),
                "ctf_state_path": str(STATE_PATH),
                "ctf_state": ctf_summary,
                "discovered_flags": discovered_flags,
                "auto_submitted_flags": prep_submissions + post_submissions,
            },
            "error": None,
        }
    except Exception as exc:
        return {
            "text": "",
            "breach": False,
            "metadata": {"attack_id": attack_id},
            "error": str(exc),
        }


def main() -> None:
    payload = json.loads(sys.stdin.read())
    if payload.get("healthcheck"):
        healthcheck()
        return
    print(json.dumps(send_attack(payload)))


if __name__ == "__main__":
    main()
