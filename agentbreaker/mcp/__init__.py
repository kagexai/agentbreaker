"""MCP / agent red-team wedge.

Phase 1a: a deterministic **server hygiene scanner** for Model Context Protocol (MCP)
servers. It connects (read-only), enumerates the server's tools/resources/prompts, and
flags risky surface: dangerous tools without auth, unsanitized external content that can
carry indirect prompt injection, over-broad scopes, sensitive resources.

No LLM. No tool execution. Fully offline-testable over a static surface. This is the safe,
shippable half of the wedge; the reference-agent exploitability harness is Phase 1b.

See docs/designs/mcp-agent-redteam.md.
"""

from __future__ import annotations

from .surface import MCPTool, MCPResource, MCPPrompt, MCPServerSurface
from .hygiene import HygieneFinding, HygieneReport, scan_surface
from .client import MCPClient, StaticSurfaceClient
from .scanner import scan
from .leaderboard import Leaderboard, LeaderboardEntry, scan_many
from .exploit import (
    SandboxBroker, ReferenceAgent, ExploitResult, Decision, ToolCall,
    run_indirect_injection, build_injection, canary_tool,
    surface_tools_to_dicts, reference_llm_config, exploit_server,
    CANARY_TOOL_NAME, REFERENCE_SYSTEM_R,
)

__all__ = [
    "MCPTool",
    "MCPResource",
    "MCPPrompt",
    "MCPServerSurface",
    "HygieneFinding",
    "HygieneReport",
    "scan_surface",
    "MCPClient",
    "StaticSurfaceClient",
    "scan",
    "Leaderboard",
    "LeaderboardEntry",
    "scan_many",
    "SandboxBroker",
    "ReferenceAgent",
    "ExploitResult",
    "Decision",
    "ToolCall",
    "run_indirect_injection",
    "build_injection",
    "canary_tool",
    "surface_tools_to_dicts",
    "reference_llm_config",
    "exploit_server",
    "CANARY_TOOL_NAME",
    "REFERENCE_SYSTEM_R",
]
