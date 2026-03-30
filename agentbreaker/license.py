"""
license.py -- Enterprise license key validation for AgentBreaker.

Reads AGENTBREAKER_LICENSE_KEY from the environment. Valid keys follow the
format AB-ENT-<8+ uppercase alphanumeric chars>. The result is cached in
process memory after the first check.
"""

from __future__ import annotations

import os
import re

_PATTERN = re.compile(r"^AB-ENT-[A-Z0-9]{8,}$")
_cached: bool | None = None


def is_enterprise_licensed() -> bool:
    """Return True if a valid enterprise license key is present in the environment."""
    global _cached
    if _cached is None:
        key = os.environ.get("AGENTBREAKER_LICENSE_KEY", "").strip()
        _cached = bool(key and _PATTERN.match(key))
    return _cached


def license_tier() -> str:
    """Return 'enterprise' or 'community' based on the current license state."""
    return "enterprise" if is_enterprise_licensed() else "community"
