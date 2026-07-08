# Design: MCP / Agent Red-Team Wedge

Status: REVIEWED (eng review folded in — validity/safety/sequencing hardened)
Author: kagexai
Date: 2026-07-07

## Context

AgentBreaker is an agentic red-team engine (recon → analyse → attack → report). It is
strong at *outcome-driven extraction* but invisible on GitHub, and it competes with
mature, prompt-focused tools (DeepTeam, PromptFoo, Garak).

The wedge: **red-teaming MCP servers and tool-using agents.** MCP (Model Context
Protocol, the standard that lets an LLM call external tools/resources) exploded, everyone
is shipping MCP servers and tool-using agents, and security is an afterthought. Almost
nobody owns "red-team my agent's tools." DeepTeam attacks prompts; this attacks *agents
with tools*. Clean white space, and it plays to our one real advantage: AgentBreaker is
already an agent that reasons about capabilities and chains attacks. Agent-attacking-agent
is on-brand and screenshots itself.

This is the eyeball bet. It is delivered **open-core, thin**: a single-purpose installable
OSS runner (the magnet) alongside the web control plane (the upsell). We are NOT bringing
back the old operator CLI. One command, one job.

## Goals

- Point AgentBreaker at (a) a **user's tool-using agent** (endpoint/callback) or (b) a
  **raw MCP server** (we stand a reference agent around it), and red-team it.
- Detect the agent-specific failure classes: **tool misuse**, **indirect prompt injection**
  (poison data the agent reads → it obeys), **excessive agency**, **confused deputy**,
  **secret/credential exfiltration via tools**, **unauthorized data access**.
- Produce a crisp report: which tools are abusable, the transcript, the fix.
- Ship a one-command OSS runner + a GitHub Action, so it spreads on GitHub.

## Non-goals

- Not rebuilding DeepEval-style quality metrics.
- Not a general MCP client/framework — only the red-team path.
- Not re-exposing the full old CLI. One narrow entrypoint.

## Open-core boundary

| OSS (the magnet) | Web control plane (the upsell) |
|---|---|
| `agentbreaker mcp <target>` one-command runner | Campaigns, history, dashboards |
| MCP adapter + agent-abuse objectives + injection harness | Team features, scheduling, findings DB UI |
| Single-run report (markdown/JSON) | Trend/regression tracking, multi-target fleets |
| GitHub Action | Hosted runs, auth, RBAC |

The OSS runner reuses the exact recon→analyse→attack→report agents; the web app adds
persistence, orchestration, and team surface. Same engine, two front doors.

## Two things that will bite (design them in first)

These two came out of the eng review. They are load-bearing; get them wrong and the whole
wedge is either dishonest or dangerous.

### Validity: a breach is a property of (server + client agent), not the server alone
If we stand a reference agent around a server and it misbehaves, we measured *our agent +
the server*, not the server. A gullible harness LLM makes every server "insecure"; a
hardened one makes none. So we split the claim into two measurements:

1. **Server hygiene (deterministic, no LLM).** Read-only enumeration facts: does a
   dangerous tool (`run_shell`, `write_file`, `delete_*`, `send_*`) exist with no auth?
   Does the server return external/unsanitized content into context? Over-broad resource
   scopes? This is reproducible, cheap, and *already a shareable leaderboard* ("MCP server
   hygiene report"). No confounding.
2. **Agent-exploitability with reference agent R (LLM harness).** We publish the exact
   reference config R (named model + a standard, documented agent scaffold + system prompt)
   and report "with reference agent R, server X enabled attack Y." Honest, reproducible,
   still shareable. Never "server X is insecure" full stop.

The hygiene score is the more defensible leaderboard AND the cheaper one. It ships first.

### Safety: never actually execute a side-effecting tool
The harness will try to make the agent call tools. If it succeeds on a real public server
with `delete_record` / `send_email` / `run_shell`, we just did damage. So tool execution is
**sandboxed / dry-run by default**: intercept the tool call, decide breach from the
*attempted* call (tool name + args + injected intent), and DO NOT execute side-effecting
tools. Real execution is opt-in and only against a consented sandbox. This is
non-negotiable for a tool that points at other people's servers, and it is what keeps us
from becoming the attack.

## Architecture

Reuse the existing pipeline. Add: an MCP **target adapter**, a deterministic **hygiene
scanner**, new **attack objectives**, and a **sandboxed reference-agent + injection harness**.

```
  MCP server (stdio/HTTP)                 user agent endpoint
        │  tools/resources/prompts               │
        ▼                                         ▼
  ┌──────────────────────── Target adapter ────────────────────────┐
  │  MCPProvider: enumerate tools/resources/prompts (MCP introspec) │
  │  Reference-agent harness (LLM + MCP client)  OR  proxy to agent │
  └───────────────────────────────┬────────────────────────────────┘
                                  ▼
     recon(enumerate surface) → analyse(objectives) → attack(agent) → report
```

### 1. MCP target adapter (`agentbreaker/providers/mcp.py`)
- New provider kind `mcp` in the existing `ProviderRouter` (`target.py`). Slots into the
  provider abstraction like `script`/`http`/`browser`.
- **Transport: use a maintained MCP client lib, pinned. Do not hand-roll the protocol**
  (MCP is Layer 2 — new and moving fast). Phase 1 targets **HTTP/SSE** (safer for a hosted
  receipts engine, no running of arbitrary server code). **stdio** (spawn the server as a
  subprocess = run their code = supply-chain risk) is Phase 1b, local-only, opt-in. Handle
  MCP **auth** (HTTP servers increasingly require OAuth) — enumeration may need creds.
- Uses MCP introspection (`tools/list`, `resources/list`, `prompts/list`) to enumerate the
  attack surface. Each tool → a `target_field` (category `tool_misuse`); each resource →
  an indirect-injection surface.
- Two run modes:
  - **(b) Reference-agent mode:** stand a *documented reference agent R* (named model +
    standard scaffold) around the server so we can red-team any public server without the
    owner's agent. We report "(server + R)" outcomes, never "server is insecure" (see
    Validity above). Tool execution is **sandboxed** (see Safety above).
  - **(a) Proxy mode:** target is a user's existing agent endpoint (`model_callback`-style);
    we drive it and observe the tool calls it makes.

### 2. Agent-abuse objectives (extend `agents/stages/analyse.py`)
Add objective categories + capability gates (only when the server exposes tools/resources):
- `tool_misuse` — coax the agent into calling a dangerous/destructive tool.
- `indirect_injection` — hidden instructions in a resource/tool-result the agent reads.
- `excessive_agency` — agent takes actions beyond the user's request.
- `confused_deputy` — agent uses its privileges on the attacker's behalf.
- `secret_exfil_via_tool` — leak credentials/env/config through a tool.
- `unauthorized_data_access` — read resources the caller shouldn't reach.

The Analyse agent already reasons over capabilities → it now reasons over *tools*: "this
server has a `run_shell` tool and a `read_file` tool, so command-injection and secret-exfil
are the high-value objectives."

### 3. Indirect-injection harness (the killer demo)
The money attack. Poison the data the agent *reads*, then check whether it obeys.

**Breach = ground truth from the tool-call trace, not an LLM guess.** We inject an
instruction that names a **canary/honeytoken tool** the agent should never call (or canary
args, e.g. an out-of-band URL only the attacker knows). Breach is deterministic: the trace
shows the agent called the canary tool / used the canary args. This mirrors the existing
canary pattern for text leaks. The **breach critic is the fallback for fuzzy cases only**
(a real destructive tool with no clean canary), not the primary signal. Cheaper, and not
confounded by a gullible judge.

- In reference-agent mode we control the loop, so we inject payloads into resource content /
  tool outputs the agent fetches, capture the full tool-call trace, and match against the
  canary. Side-effecting tools are **sandboxed** (Safety section) — we decide breach from
  the *attempted* call, we do not run it.
- The Attack agent (`agents/stages/attack_agent.py`) crafts the injected instruction,
  reads the trace, reflects on the failure mode, and chains.

### 4. Report
Reuse the Report agent. Add tool-call evidence: which tool was abused, the injected
payload, the agent's tool-call trace, severity, and a concrete remediation (e.g., "gate
`run_shell` behind human approval", "sanitize resource content before it enters context").

## Reuse map (and the one real integration cost)
- **Providers / ProviderRouter** (`target.py`, `providers/`) — MCP is a new provider kind.
- **recon → analyse → attack → report agents** (`agents/`) — unchanged control flow; new
  objective categories + tool-aware recon.
- **Belief + findings + Report agent** — reused; add tool-call evidence to findings.
- **Breach signal — NOT free reuse.** The existing breach path is built for *text
  extraction* (`_audit_semantic_breach`, `matched_fragment`, `matched_secret`, canaries in
  text). A **tool-call breach is a different signal.** We thread a `tool_calls` trace
  through `ExperimentScores`/audit and add a `tool_call_breach` detector (canary-tool match)
  alongside the text detector. Budget this as real work, not a one-line reuse.
- **Control plane** — a new target kind + campaign type; the web app gets MCP campaigns
  once the provider + breach signal exist.

## Phased plan (reordered by the eng review: safe + deterministic ships first)

**Phase 1a — server hygiene scanner (build FIRST — no LLM, no tool execution, no confounding).**
- MCP provider over HTTP/SSE (pinned client lib) + tool/resource/prompt enumeration.
- Deterministic hygiene checks: dangerous-tool-without-auth, unsanitized-external-content
  surfaces, over-broad scopes → a **hygiene score + report**.
- One-command OSS runner: `agentbreaker mcp <server>` → hygiene report (markdown/JSON).
- This alone is a shippable, safe, reproducible, shareable leaderboard. Fastest path to a
  real artifact with zero validity/safety landmines.

**Phase 1b — reference-agent exploitability harness (the harder, riskier half).**
- Reference agent R (documented config) + MCP client loop, **sandboxed tool execution**.
- `tool_misuse` + `indirect_injection` objectives; **canary-tool ground-truth** breach.
- Tool-call breach signal threaded through `ExperimentScores`/audit.
- Reports "(server + R) enabled attack Y", never "server is insecure".

**Phase 2 — the eyeball engine.**
- "MCP server hygiene leaderboard" (from 1a) + exploitability receipts (from 1b).
- **GitHub Action** ("agent security in CI", README badge = viral loop).
- Short **MCP red-team methodology** doc people link to.
- **Publish pipeline: PyPI release + GitHub Action** so `pip install agentbreaker` actually
  works. Code nobody can install gets no stars — this is scope, not a follow-up.

**Phase 3 — the upsell.**
- Web control plane surfaces MCP campaigns, history, and regression tracking.

## Test coverage (plan-stage — build alongside the code)
```
[Phase 1a] hygiene scanner (deterministic, offline mock MCP server)
  ├── [★★★] enumerate tools/resources/prompts from mock server
  ├── [★★★] dangerous-tool-without-auth → flagged
  ├── [★★★] no tools / empty server → clean report, no crash
  └── [★★★] transport error / auth required → infra-failure path, clear error
[Phase 1b] reference-agent + injection (LLM + MCP mocked)
  ├── [★★★] injection → canary-tool call → deterministic breach
  ├── [★★★] SANDBOX: a side-effecting tool is NEVER executed (assert no real call)
  ├── [★★★] agent refuses injection → not a breach; chain a different framing
  ├── [★★]  critic fallback only fires on fuzzy (no-canary) case
  └── [→EVAL] reference-agent faithfulness: R behaves like a plausible real agent
```
`conftest.py` already blocks real LLM calls; MCP server is a local mock fixture. No live
network in unit tests.

## Data-flow shadow paths (Phase 1)
- Server exposes **no tools** → recon yields empty tool surface → report "no tool attack
  surface" (not a crash).
- Tool call **errors / times out** → treat as infra failure (existing exclusion path), do
  not count as breach.
- Agent **refuses** the injected instruction → not a breach; critic confirms; chain a
  different framing.
- MCP connection **fails** → clear error, no partial/hung run.

## Risks (post-review)
- **Confounding (P0, mitigated):** breach = server + agent. Mitigation: split into
  deterministic hygiene (server-intrinsic) + "(server + reference agent R)" exploitability.
- **Live-fire damage (P0, mitigated):** the harness could execute destructive tools on real
  servers. Mitigation: sandboxed/dry-run tool execution by default; real execution only
  against a consented sandbox.
- **Reuse mismatch (P1):** tool-call breach is a new signal, not free reuse of the text-leak
  path. Budgeted in the reuse map.
- **Protocol churn (P1):** MCP moves fast. Pin a maintained client lib; do not hand-roll.
- **Narrower reach; bets on MCP staying hot.** Named as a bet.

## NOT in scope (Phase 1)
- stdio transport / running arbitrary server code (Phase 1b, opt-in, local-only).
- Executing real side-effecting tools (sandboxed only until a consented sandbox exists).
- Multi-turn agent memory attacks beyond single injection→action chains.
- Web control plane MCP UI (Phase 3).
- A public hosted leaderboard service (content/receipts first, hosting later).

## Verification (end to end)
1. **Phase 1a:** mock MCP server with a `read_file` + a `delete_record` (no-auth) tool.
   `agentbreaker mcp ./mock` → enumerate 2 tools, flag `delete_record` as dangerous-no-auth,
   emit a hygiene report. No LLM, no tool execution.
2. **Phase 1b:** mock server + poisoned resource + a canary tool. Reference agent R reads the
   resource, the trace shows a canary-tool *attempt*, breach is confirmed deterministically,
   and an assertion proves the side-effecting tool was **not** actually executed.
3. Unit suite (LLM + MCP mocked, offline) per the coverage diagram above.
4. One real public HTTP MCP server (consented / clearly public) → first hygiene receipt.

## GTM hooks (why this gets eyeballs)
- Receipts on **named** public MCP servers = recurring, shareable content.
- GitHub Action + README badge = self-propagating distribution.
- Methodology doc = the reference people cite.
- Narrative: "watch an AI autonomously red-team another AI's tools." On-brand, viral-shaped.
