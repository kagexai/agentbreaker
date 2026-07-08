"""The enumerated attack surface of an MCP server.

These are plain dataclasses so the hygiene scanner is a pure function over data -- the
transport (HTTP/SSE, or the official mcp SDK) fills them in, tests build them directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)   # JSON Schema of arguments

    @property
    def param_names(self) -> list[str]:
        props = (self.input_schema or {}).get("properties", {})
        return list(props.keys()) if isinstance(props, dict) else []


@dataclass
class MCPResource:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""

    @property
    def scheme(self) -> str:
        return self.uri.split("://", 1)[0].lower() if "://" in self.uri else ""


@dataclass
class MCPPrompt:
    name: str
    description: str = ""


@dataclass
class MCPServerSurface:
    """Everything a read-only enumeration of an MCP server yields."""
    server: str                                   # url or command that identifies it
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    prompts: list[MCPPrompt] = field(default_factory=list)
    auth_required: bool = False                   # did connecting/enumerating require auth?
    transport: str = "http"                       # http | stdio
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "transport": self.transport,
            "auth_required": self.auth_required,
            "tools": [{"name": t.name, "description": t.description, "params": t.param_names}
                      for t in self.tools],
            "resources": [{"uri": r.uri, "name": r.name, "mime_type": r.mime_type}
                          for r in self.resources],
            "prompts": [{"name": p.name} for p in self.prompts],
            "notes": list(self.notes),
        }
