"""Scan orchestration: enumerate a server (read-only) then run the hygiene scanner."""

from __future__ import annotations

from .client import MCPClient
from .hygiene import HygieneReport, scan_surface


def scan(client: MCPClient) -> HygieneReport:
    """Enumerate the server via `client` and return its hygiene report.

    The client does read-only enumeration only (tools/resources/prompts list). No tool is
    ever executed here -- that is Phase 1b's sandboxed path.
    """
    surface = client.enumerate()
    return scan_surface(surface)
