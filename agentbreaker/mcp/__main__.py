"""One-command MCP hygiene scan: `python -m agentbreaker.mcp <http-mcp-url>`.

The thin OSS wedge. Read-only. No tool execution. Prints a markdown report (or JSON with
--json). A real HTTP scan needs the optional extra: `pip install 'agentbreaker[mcp]'`.
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import http_client
from .scanner import scan
from .leaderboard import scan_many


def _read_targets(path: str) -> list[str]:
    urls: list[str] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentbreaker.mcp",
        description="Deterministic hygiene scan of MCP server(s). Read-only, no tool execution.",
    )
    p.add_argument("server", nargs="?", help="HTTP MCP server URL (e.g. https://host/mcp)")
    p.add_argument("--targets", metavar="FILE",
                   help="File of MCP server URLs (one per line, # comments) -> hygiene leaderboard.")
    p.add_argument("--header", action="append", default=[], metavar="K:V",
                   help="Extra HTTP header (repeatable), e.g. --header 'Authorization: Bearer …'")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    p.add_argument("--fail-under", type=int, default=None,
                   help="Exit non-zero if a hygiene score is below this (for CI).")
    p.add_argument("--exploit", action="store_true",
                   help="Also run the sandboxed indirect-injection exploit (needs OPENAI_API_KEY; "
                        "runs a real reference-agent LLM; tools are never executed).")
    p.add_argument("--model", default=None, help="Reference-agent model for --exploit (default gpt-4o).")
    args = p.parse_args(argv)

    if not args.server and not args.targets:
        p.error("provide a server URL or --targets FILE")

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    # ── Leaderboard mode (scan many) ──
    if args.targets:
        try:
            urls = _read_targets(args.targets)
        except OSError as exc:
            print(f"error: cannot read --targets {args.targets}: {exc}", file=sys.stderr)
            return 2
        board = scan_many((u, http_client(u, headers=headers)) for u in urls)
        print(json.dumps(board.to_dict(), indent=2) if args.json else board.to_markdown())
        if args.fail_under is not None and board.min_score is not None and board.min_score < args.fail_under:
            print(f"\n[fail] lowest score {board.min_score} < --fail-under {args.fail_under}", file=sys.stderr)
            return 1
        return 0

    # ── Single-server mode ──
    try:
        client = http_client(args.server, headers=headers)
        report = scan(client)
    except RuntimeError as exc:   # missing optional dep, or transport error
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report.to_dict(), indent=2) if args.json else report.to_markdown())

    if args.exploit:
        from .exploit import exploit_server
        try:
            result = exploit_server(http_client(args.server, headers=headers), model=args.model)
        except RuntimeError as exc:
            print(f"\nerror: {exc}", file=sys.stderr)
            return 2
        print("\n" + (json.dumps(result.to_dict(), indent=2) if args.json else result.to_markdown()))

    if args.fail_under is not None and report.score < args.fail_under:
        print(f"\n[fail] score {report.score} < --fail-under {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
