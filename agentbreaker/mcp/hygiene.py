"""Deterministic MCP server hygiene scanner.

Pure function over an enumerated `MCPServerSurface` -> `HygieneReport`. No LLM, no network,
no tool execution. Every finding is a fact you can point at (this tool, this resource), so
the score is reproducible and not confounded by a judge model -- unlike agent-exploitability
(Phase 1b), a breach here is a property of the *server*, which is why this can be a public
leaderboard.

Checks:
  1. dangerous tool (destructive / exec / exfil) -- worse without auth
  2. unsanitized external content resource -> indirect-injection surface
  3. sensitive resource (secrets/env/credentials) exposed
  4. over-broad tool scope (free-form command/code/path arg on a dangerous tool)
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .surface import MCPServerSurface, MCPTool, MCPResource

# ---------------------------------------------------------------------------
# Signal dictionaries (kept explicit so findings are auditable, not a black box)
# ---------------------------------------------------------------------------

# Destructive / code-exec verbs -> the scariest tools.
_EXEC_VERBS = {
    "exec", "execute", "shell", "run", "spawn", "eval", "system", "sudo",
    "command", "cmd", "bash", "sh", "powershell", "process",
}
_DESTRUCTIVE_VERBS = {
    "delete", "destroy", "drop", "remove", "wipe", "truncate", "rm",
    "purge", "erase", "kill", "terminate", "reset", "revoke",
}
# Data can leave the building.
_EXFIL_VERBS = {
    "send", "email", "mail", "sms", "post", "publish", "transfer", "pay",
    "purchase", "charge", "checkout", "webhook", "upload", "export", "share",
    "fetch", "curl", "request", "http", "browse", "download",
}
# Mutating but less catastrophic.
_WRITE_VERBS = {"write", "put", "update", "set", "create", "patch", "modify", "insert", "edit"}
# Sensitive read targets.
_SECRET_HINTS = {
    "secret", "credential", "password", "passwd", "token", "api_key", "apikey",
    "private_key", "privatekey", "env", "environment", "config", "keychain", "vault",
}
# Free-form params that make a dangerous tool arbitrary.
_ARBITRARY_PARAMS = {"command", "cmd", "code", "script", "query", "sql", "path", "url", "expr", "shell"}

# Resource content that comes from outside the trust boundary (indirect-injection risk).
_EXTERNAL_SCHEMES = {"http", "https", "ftp", "ws", "wss"}
_EXTERNAL_HINTS = {"web", "url", "fetch", "external", "remote", "user", "upload", "inbox", "email", "rss", "feed"}

_SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}


@dataclass
class HygieneFinding:
    id: str                       # stable slug, e.g. "dangerous-tool-no-auth"
    severity: str                 # critical | high | medium | low | info
    target: str                   # tool/resource this is about
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HygieneReport:
    server: str
    score: int                    # 0-100, higher = cleaner
    findings: list[HygieneFinding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)   # tools/resources/prompts
    auth_required: bool = False

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server, "score": self.score, "grade": self.grade,
            "auth_required": self.auth_required, "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# MCP hygiene report — {self.server}",
            "",
            f"**Score: {self.score}/100 (grade {self.grade})** · "
            f"auth_required={self.auth_required} · "
            f"tools={self.counts.get('tools', 0)} resources={self.counts.get('resources', 0)} "
            f"prompts={self.counts.get('prompts', 0)}",
            "",
        ]
        if not self.findings:
            lines.append("No hygiene issues found. ✅")
            return "\n".join(lines)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(self.findings, key=lambda x: order.get(x.severity, 9)):
            lines += [
                f"### [{f.severity.upper()}] {f.title}",
                f"- **target:** `{f.target}`",
                f"- {f.detail}",
                f"- **fix:** {f.remediation}",
                "",
            ]
        return "\n".join(lines)


def _verbs(text: str) -> set[str]:
    import re
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _tool_findings(tool: MCPTool, auth_required: bool) -> list[HygieneFinding]:
    words = _verbs(tool.name) | _verbs(tool.description)
    out: list[HygieneFinding] = []

    is_exec = bool(words & (_EXEC_VERBS | _DESTRUCTIVE_VERBS))
    is_exfil = bool(words & _EXFIL_VERBS)
    is_write = bool(words & _WRITE_VERBS)

    if is_exec:
        sev = "critical" if not auth_required else "high"
        out.append(HygieneFinding(
            id="dangerous-tool-no-auth" if not auth_required else "dangerous-tool",
            severity=sev, target=tool.name,
            title="Destructive / code-execution tool exposed" + ("" if auth_required else " without auth"),
            detail=(f"Tool `{tool.name}` looks capable of executing code or destroying data. "
                    + ("The server did not require auth to enumerate it, so it may be callable by anyone."
                       if not auth_required else "It is high-impact if an agent can be coerced into calling it.")),
            remediation="Require auth; gate this tool behind explicit human approval; scope its inputs.",
        ))
    elif is_exfil:
        out.append(HygieneFinding(
            id="exfil-tool", severity="high" if not auth_required else "medium", target=tool.name,
            title="Data-egress / side-effecting tool exposed",
            detail=f"Tool `{tool.name}` can send data or take external actions; an injected instruction could exfiltrate through it.",
            remediation="Require auth; validate destinations; add an allowlist; require confirmation for outbound actions.",
        ))
    elif is_write:
        out.append(HygieneFinding(
            id="write-tool", severity="low", target=tool.name,
            title="Mutating tool exposed",
            detail=f"Tool `{tool.name}` mutates state; lower risk than exec/exfil but still abusable.",
            remediation="Scope writes; require auth for state-changing operations.",
        ))

    # Over-broad scope: a dangerous tool that takes a free-form command/code/path arg.
    if (is_exec or is_exfil) and (set(p.lower() for p in tool.param_names) & _ARBITRARY_PARAMS):
        out.append(HygieneFinding(
            id="over-broad-scope", severity="high", target=tool.name,
            title="Dangerous tool accepts a free-form argument",
            detail=f"Tool `{tool.name}` takes an arbitrary argument ({', '.join(tool.param_names)}); "
                   "there is no schema constraint stopping an injected value.",
            remediation="Replace free-form args with a constrained enum/schema; reject shell metacharacters.",
        ))
    return out


def _resource_findings(res: MCPResource) -> list[HygieneFinding]:
    words = _verbs(res.name) | _verbs(res.description) | _verbs(res.uri)
    out: list[HygieneFinding] = []

    external = res.scheme in _EXTERNAL_SCHEMES or bool(words & _EXTERNAL_HINTS)
    if external:
        out.append(HygieneFinding(
            id="unsanitized-external-content", severity="medium", target=res.uri or res.name,
            title="Resource carries external content into the agent's context",
            detail=(f"Resource `{res.uri or res.name}` appears to pull external/user content. If an agent "
                    "reads it, embedded instructions can drive indirect prompt injection."),
            remediation="Treat resource content as untrusted data; strip/escape instructions before it enters the prompt; label provenance.",
        ))
    if words & _SECRET_HINTS:
        out.append(HygieneFinding(
            id="sensitive-resource", severity="high", target=res.uri or res.name,
            title="Sensitive resource exposed",
            detail=f"Resource `{res.uri or res.name}` looks like it exposes secrets/credentials/config.",
            remediation="Do not expose secrets as MCP resources; require auth; redact.",
        ))
    return out


def scan_surface(surface: MCPServerSurface) -> HygieneReport:
    """Score a server's enumerated surface. Deterministic, offline, no tool execution."""
    findings: list[HygieneFinding] = []
    for tool in surface.tools:
        findings.extend(_tool_findings(tool, surface.auth_required))
    for res in surface.resources:
        findings.extend(_resource_findings(res))

    # Server-level: dangerous tools reachable with no auth is its own headline.
    if not surface.auth_required and any(f.id == "dangerous-tool-no-auth" for f in findings):
        findings.insert(0, HygieneFinding(
            id="no-auth", severity="high", target=surface.server,
            title="Server exposes dangerous tools without authentication",
            detail="Enumeration succeeded without credentials and destructive tools are present.",
            remediation="Put the server behind authentication (OAuth for HTTP MCP).",
        ))

    penalty = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)
    return HygieneReport(
        server=surface.server,
        score=score,
        findings=findings,
        counts={"tools": len(surface.tools), "resources": len(surface.resources),
                "prompts": len(surface.prompts)},
        auth_required=surface.auth_required,
    )
