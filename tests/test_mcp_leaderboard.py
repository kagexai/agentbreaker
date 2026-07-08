"""Offline tests for the MCP hygiene leaderboard (scan-many receipts runner)."""

from __future__ import annotations

from agentbreaker.mcp import (
    MCPServerSurface, MCPTool, StaticSurfaceClient, scan_many,
)


def _client(server, tools=(), auth=False):
    return StaticSurfaceClient(MCPServerSurface(
        server=server, transport="http", auth_required=auth, tools=list(tools),
    ))


class _BoomClient:
    def enumerate(self):
        raise RuntimeError("connection refused")


def test_leaderboard_ranks_worst_first():
    board = scan_many([
        ("clean", _client("clean", tools=[MCPTool(name="get_weather")], auth=True)),
        ("nasty", _client("nasty", tools=[MCPTool(name="run_shell")])),      # critical, no auth
        ("meh", _client("meh", tools=[MCPTool(name="write_note")])),          # low
    ])
    ranked = [e.label for e in board.scanned]
    assert ranked[0] == "nasty"          # lowest score first
    assert ranked[-1] == "clean"         # 100/A last
    assert board.min_score == board.scanned[0].report.score


def test_leaderboard_captures_errors_without_dying():
    board = scan_many([
        ("ok", _client("ok", tools=[MCPTool(name="get_weather")], auth=True)),
        ("down", _BoomClient()),
    ])
    assert [e.label for e in board.scanned] == ["ok"]
    assert len(board.errored) == 1
    assert board.errored[0].label == "down"
    assert "connection refused" in board.errored[0].error
    assert board.min_score == 100        # errored server doesn't sink min_score


def test_leaderboard_markdown_and_json():
    board = scan_many([
        ("nasty", _client("nasty", tools=[MCPTool(name="delete_all")])),
        ("down", _BoomClient()),
    ])
    md = board.to_markdown()
    assert "MCP hygiene leaderboard" in md
    assert "| # | Server |" in md and "nasty" in md
    assert "Not scanned" in md and "down" in md
    d = board.to_dict()
    assert d["scanned"][0]["label"] == "nasty"
    assert d["errored"][0]["label"] == "down"
