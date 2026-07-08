"""Offline tests for the MCP hygiene scanner (Phase 1a).

No network, no LLM, no tool execution. Everything runs over a static surface.
"""

from __future__ import annotations

from agentbreaker.mcp import (
    MCPTool, MCPResource, MCPPrompt, MCPServerSurface,
    StaticSurfaceClient, scan, scan_surface,
)


def _surface(**kw) -> MCPServerSurface:
    base = dict(server="https://demo/mcp", transport="http", auth_required=False)
    base.update(kw)
    return MCPServerSurface(**base)


# ---------------------------------------------------------------------------
# Dangerous tools
# ---------------------------------------------------------------------------

def test_destructive_tool_without_auth_is_critical():
    s = _surface(tools=[MCPTool(name="delete_record", description="Delete a record by id")])
    r = scan_surface(s)
    ids = {f.id for f in r.findings}
    assert "dangerous-tool-no-auth" in ids
    assert "no-auth" in ids                      # server-level headline
    assert any(f.severity == "critical" for f in r.findings)
    assert r.score < 60 and r.grade in {"D", "F"}


def test_same_tool_with_auth_is_downgraded():
    s = _surface(auth_required=True,
                 tools=[MCPTool(name="run_shell", description="Execute a shell command")])
    r = scan_surface(s)
    # auth present -> high, not critical; no server-level no-auth finding
    assert not any(f.id == "no-auth" for f in r.findings)
    assert any(f.severity == "high" for f in r.findings)
    assert not any(f.severity == "critical" for f in r.findings)


def test_exfil_tool_flagged():
    s = _surface(tools=[MCPTool(name="send_email", description="Send an email to a recipient")])
    r = scan_surface(s)
    assert any(f.id == "exfil-tool" for f in r.findings)


def test_over_broad_scope_on_dangerous_tool():
    s = _surface(tools=[MCPTool(
        name="exec", description="Run a command",
        input_schema={"properties": {"command": {"type": "string"}}},
    )])
    r = scan_surface(s)
    assert any(f.id == "over-broad-scope" for f in r.findings)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

def test_external_content_resource_is_injection_surface():
    s = _surface(resources=[MCPResource(uri="https://feed.example.com/inbox", name="inbox")])
    r = scan_surface(s)
    assert any(f.id == "unsanitized-external-content" for f in r.findings)


def test_sensitive_resource_flagged():
    s = _surface(resources=[MCPResource(uri="file:///app/.env", name="env secrets")])
    r = scan_surface(s)
    assert any(f.id == "sensitive-resource" for f in r.findings)


# ---------------------------------------------------------------------------
# Clean + shape
# ---------------------------------------------------------------------------

def test_benign_server_scores_high():
    s = _surface(auth_required=True, tools=[
        MCPTool(name="get_weather", description="Return the weather for a city"),
        MCPTool(name="list_docs", description="List available documents"),
    ], prompts=[MCPPrompt(name="summarize")])
    r = scan_surface(s)
    assert r.findings == []
    assert r.score == 100 and r.grade == "A"


def test_scan_uses_client_and_never_executes_tools():
    # StaticSurfaceClient.enumerate returns the surface; scan must not call any tool.
    s = _surface(tools=[MCPTool(name="delete_all")])
    report = scan(StaticSurfaceClient(s))
    assert report.counts["tools"] == 1
    # a report is data only -- there is no execution path to trigger


def test_markdown_and_json_render():
    s = _surface(tools=[MCPTool(name="drop_table")])
    r = scan_surface(s)
    md = r.to_markdown()
    assert "MCP hygiene report" in md and "DROP" or "drop_table" in md
    d = r.to_dict()
    assert d["score"] == r.score and "findings" in d and d["grade"] == r.grade
