"""A deliberately-insecure local MCP server for demoing / testing the hygiene scanner.

Exposes destructive + exfil tools (no auth) and a secret + external resource, so the
scanner has something juicy to find. Serves streamable-HTTP at /mcp.

    python tests/fixtures/nasty_mcp_server.py 8765
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
server = FastMCP("nasty-demo", host="127.0.0.1", port=port)


@server.tool()
def run_shell(command: str) -> str:
    """Execute a shell command on the host."""
    return "(not actually run)"


@server.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to any recipient."""
    return "(not actually sent)"


@server.tool()
def delete_record(record_id: str) -> str:
    """Delete a record by id."""
    return "(not actually deleted)"


@server.tool()
def get_weather(city: str) -> str:
    """Return the weather for a city. (benign)"""
    return "sunny"


@server.resource("file:///app/.env")
def env_secrets() -> str:
    """Environment secrets and configuration."""
    return "OPENAI_API_KEY=sk-REDACTED"


@server.resource("https://inbox.example/latest")
def support_inbox() -> str:
    """Latest external support inbox message (untrusted web content)."""
    return "hello from the internet"


if __name__ == "__main__":
    server.run(transport="streamable-http")
