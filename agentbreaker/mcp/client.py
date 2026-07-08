"""MCP client seam.

The hygiene scanner works on an `MCPServerSurface`, so it never needs a live server. The
client's only job is to *enumerate* (read-only) that surface:

- `StaticSurfaceClient` — wraps a surface we already have (tests, fixtures, cached scans).
- `http_client(url)` — connects to a real HTTP MCP server via the official `mcp` SDK
  (optional extra `agentbreaker[mcp]`), lists tools/resources/prompts, fills the surface.

Enumeration is read-only: `tools/list`, `resources/list`, `prompts/list`. We never call a
tool here. Tool *execution* (Phase 1b) is a separate, sandboxed path.
"""

from __future__ import annotations

import logging
from typing import Protocol

from .surface import MCPServerSurface, MCPTool, MCPResource, MCPPrompt

logger = logging.getLogger(__name__)


class MCPClient(Protocol):
    def enumerate(self) -> MCPServerSurface: ...


class StaticSurfaceClient:
    """An MCPClient backed by an already-known surface (tests / cached scans)."""

    def __init__(self, surface: MCPServerSurface):
        self._surface = surface

    def enumerate(self) -> MCPServerSurface:
        return self._surface


def http_client(url: str, *, headers: dict[str, str] | None = None, timeout: float = 20.0) -> MCPClient:
    """Return a read-only enumeration client for a real HTTP MCP server.

    Uses the official `mcp` SDK (install with `pip install agentbreaker[mcp]`). Kept behind
    a lazy import so the core package has no hard MCP dependency.
    """
    try:
        import anyio  # noqa: F401  (the mcp SDK is async; we bridge with anyio)
        from mcp.client.session import ClientSession  # type: ignore
        from mcp.client.streamable_http import streamablehttp_client  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only when extra is installed
        raise RuntimeError(
            "The MCP HTTP client needs the optional dependency. Install with: "
            "pip install 'agentbreaker[mcp]'"
        ) from exc

    class _HTTPClient:
        def enumerate(self) -> MCPServerSurface:
            import anyio

            async def _run() -> MCPServerSurface:
                auth_required = False
                surface = MCPServerSurface(server=url, transport="http")
                try:
                    async with streamablehttp_client(url, headers=headers or {}) as (read, write, _):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            for t in getattr(tools, "tools", []) or []:
                                surface.tools.append(MCPTool(
                                    name=getattr(t, "name", ""),
                                    description=getattr(t, "description", "") or "",
                                    input_schema=getattr(t, "inputSchema", {}) or {},
                                ))
                            try:
                                res = await session.list_resources()
                                for r in getattr(res, "resources", []) or []:
                                    surface.resources.append(MCPResource(
                                        uri=str(getattr(r, "uri", "")),
                                        name=getattr(r, "name", "") or "",
                                        description=getattr(r, "description", "") or "",
                                        mime_type=getattr(r, "mimeType", "") or "",
                                    ))
                            except Exception:
                                logger.debug("resources/list unsupported", exc_info=True)
                            try:
                                pr = await session.list_prompts()
                                for p in getattr(pr, "prompts", []) or []:
                                    surface.prompts.append(MCPPrompt(
                                        name=getattr(p, "name", ""),
                                        description=getattr(p, "description", "") or "",
                                    ))
                            except Exception:
                                logger.debug("prompts/list unsupported", exc_info=True)
                except Exception as exc:
                    # An auth challenge is signal, not a crash: record it and return what we have.
                    msg = str(exc).lower()
                    if "401" in msg or "unauthorized" in msg or "forbidden" in msg or "auth" in msg:
                        auth_required = True
                        surface.notes.append(f"enumeration blocked by auth: {exc}")
                    else:
                        raise
                surface.auth_required = auth_required
                return surface

            return anyio.run(_run)

    return _HTTPClient()
