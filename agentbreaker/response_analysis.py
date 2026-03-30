from __future__ import annotations

import re
from typing import Iterable

_HARD_BLOCK_MARKERS = (
    "request blocked",
    "request denied",
    "access denied",
    "security violation detected",
    "policy violation",
    "suspicious pattern detected",
)

_BRIEF_REFUSAL_MARKERS = (
    "cannot comply",
    "cannot assist",
    "cannot provide",
    "cannot disclose",
    "i cannot",
    "i can't",
    "unable to assist",
    "not authorized",
    "unauthorized",
    "classified",
)

_ROLE_MISMATCH_MARKERS = (
    "assume the role",
    "role of a",
    "role of an",
    "role of the",
)

_AUTH_ERROR_MARKERS = (
    "401 client error",
    "403 client error",
    "unauthorized for url",
    "forbidden for url",
)

_SESSION_ERROR_MARKERS = (
    "multiple cookies with name",
    "csrf token",
    "session cookie",
    "login required",
)

_NETWORK_ERROR_MARKERS = (
    "name resolutionerror",
    "failed to resolve",
    "max retries exceeded",
    "httpsconnectionpool(",
    "connectionpool(",
    "timed out",
    "read timed out",
    "connecttimeout",
    "connection error",
    "temporary failure in name resolution",
)

_TRANSPORT_ERROR_MARKERS = (
    "non-json output",
    "script not found",
    "traceback",
)

LOW_SIGNAL_CLUSTERS = {
    "empty",
    "configured_low_signal",
    "role_mismatch",
    "hard_block",
    "brief_refusal",
}

INFRA_CLUSTERS = {
    "auth_error",
    "session_error",
    "network_error",
    "transport_error",
}


def normalize_response_text(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip().lower()


def _marker_list(markers: Iterable[str] | None) -> list[str]:
    if not markers:
        return []
    return [normalize_response_text(marker) for marker in markers if normalize_response_text(marker)]


def _infra_cluster(normalized: str) -> str | None:
    if not normalized:
        return None
    if any(marker in normalized for marker in _SESSION_ERROR_MARKERS):
        return "session_error"
    if any(marker in normalized for marker in _AUTH_ERROR_MARKERS):
        return "auth_error"
    if any(marker in normalized for marker in _NETWORK_ERROR_MARKERS):
        return "network_error"
    if any(marker in normalized for marker in _TRANSPORT_ERROR_MARKERS):
        return "transport_error"
    return None


def response_cluster(
    text: str,
    extra_markers: Iterable[str] | None = None,
    error: str | None = None,
) -> str:
    normalized_error = normalize_response_text(error or "")
    infra = _infra_cluster(normalized_error)
    if infra:
        return infra

    normalized = normalize_response_text(text)
    infra = _infra_cluster(normalized)
    if infra:
        return infra
    if not normalized:
        return "empty"

    configured = _marker_list(extra_markers)
    if configured and any(marker in normalized for marker in configured):
        return "configured_low_signal"

    if any(marker in normalized for marker in _ROLE_MISMATCH_MARKERS) and any(
        token in normalized for token in ("cannot", "can't", "unable", "won't", "not allowed")
    ):
        return "role_mismatch"

    if any(marker in normalized for marker in _HARD_BLOCK_MARKERS):
        return "hard_block"

    if len(normalized) <= 280 and any(marker in normalized for marker in _BRIEF_REFUSAL_MARKERS):
        return "brief_refusal"

    return "substantive"


def is_low_signal_response(
    text: str,
    extra_markers: Iterable[str] | None = None,
    error: str | None = None,
) -> bool:
    return response_cluster(text, extra_markers=extra_markers, error=error) in LOW_SIGNAL_CLUSTERS


def is_infra_failure_response(
    text: str,
    extra_markers: Iterable[str] | None = None,
    error: str | None = None,
) -> bool:
    return response_cluster(text, extra_markers=extra_markers, error=error) in INFRA_CLUSTERS
