# MCP hygiene scanner

Deterministic, read-only security hygiene scan of a Model Context Protocol (MCP) server.
No LLM. No tool execution. It enumerates the server's tools/resources/prompts and flags
risky surface (destructive/exec tools, especially without auth, data-egress tools,
over-broad free-form arguments, sensitive resources, and unsanitized external content that
can carry indirect prompt injection).

## Install

```bash
pip install 'agentbreaker[mcp]'
```

## Scan one server

```bash
python -m agentbreaker.mcp https://your-mcp-server/mcp            # markdown report
python -m agentbreaker.mcp https://your-mcp-server/mcp --json     # JSON
agentbreaker-mcp https://your-mcp-server/mcp --fail-under 75      # exit 1 if score < 75
```

Auth:

```bash
python -m agentbreaker.mcp https://server/mcp --header 'Authorization: Bearer TOKEN'
```

## Leaderboard (scan many)

`servers.txt` (one URL per line, `#` comments):

```
https://a.example/mcp
https://b.example/mcp
```

```bash
python -m agentbreaker.mcp --targets servers.txt            # ranked hygiene table
python -m agentbreaker.mcp --targets servers.txt --json
```

Per-server failures (unreachable, auth-walled, not MCP) are listed, not fatal.

## GitHub Action (agent security in CI)

```yaml
# .github/workflows/mcp-hygiene.yml
name: MCP hygiene
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: kagexai/agentbreaker/.github/actions/mcp-hygiene@main
        with:
          server: https://your-mcp-server/mcp
          fail-under: "75"
```

Badge:

```markdown
![MCP hygiene](https://github.com/OWNER/REPO/actions/workflows/mcp-hygiene.yml/badge.svg)
```

## Scoring

Start at 100, subtract per finding: critical −40, high −25, medium −10, low −3. Grade:
A ≥90, B ≥75, C ≥60, D ≥40, else F. The score is a property of the **server** (intrinsic,
reproducible), not an agent's behavior. Agent-exploitability (does an agent actually get
coerced into calling a bad tool) is a separate, sandboxed scan (roadmap Phase 1b).

## Responsible use

Only scan servers you own or are authorized to test. Enumeration is read-only, but you
still touch someone else's endpoint. See `docs/designs/mcp-agent-redteam.md`.
