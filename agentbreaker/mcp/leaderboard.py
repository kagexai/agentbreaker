"""Scan-many: the MCP hygiene leaderboard (the receipts engine).

Scan a set of servers, rank them by hygiene score, render a shareable table. Per-server
errors (unreachable, auth-walled, no MCP) are recorded, not fatal -- one bad server never
sinks the run. Still read-only, still no tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .client import MCPClient
from .hygiene import HygieneReport
from .scanner import scan


@dataclass
class LeaderboardEntry:
    label: str
    report: HygieneReport | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.report is not None

    def _count(self, sev: str) -> int:
        return sum(1 for f in self.report.findings if f.severity == sev) if self.report else 0


@dataclass
class Leaderboard:
    entries: list[LeaderboardEntry] = field(default_factory=list)

    @property
    def scanned(self) -> list[LeaderboardEntry]:
        # ranked worst-first (lowest score first -- the receipts are about who's leaky)
        return sorted((e for e in self.entries if e.ok), key=lambda e: e.report.score)

    @property
    def errored(self) -> list[LeaderboardEntry]:
        return [e for e in self.entries if not e.ok]

    @property
    def min_score(self) -> int | None:
        oks = [e.report.score for e in self.entries if e.ok]
        return min(oks) if oks else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": [{"label": e.label, **e.report.to_dict()} for e in self.scanned],
            "errored": [{"label": e.label, "error": e.error} for e in self.errored],
        }

    def to_markdown(self) -> str:
        lines = ["# MCP hygiene leaderboard", ""]
        ok = self.scanned
        if ok:
            lines += [
                "| # | Server | Score | Grade | Critical | High | Top issue |",
                "|---|--------|-------|-------|----------|------|-----------|",
            ]
            for i, e in enumerate(ok, 1):
                top = ""
                if e.report.findings:
                    worst = min(e.report.findings,
                                key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                                .get(f.severity, 9))
                    top = worst.title
                lines.append(
                    f"| {i} | {e.label} | {e.report.score} | {e.report.grade} | "
                    f"{e._count('critical')} | {e._count('high')} | {top} |"
                )
            lines.append("")
        if self.errored:
            lines += ["## Not scanned", ""]
            lines += [f"- `{e.label}` — {e.error}" for e in self.errored]
            lines.append("")
        return "\n".join(lines)


def scan_many(targets: Iterable[tuple[str, MCPClient]]) -> Leaderboard:
    """Scan `(label, client)` pairs into a leaderboard. Per-target failures are captured."""
    board = Leaderboard()
    for label, client in targets:
        try:
            board.entries.append(LeaderboardEntry(label=label, report=scan(client)))
        except Exception as exc:
            board.entries.append(LeaderboardEntry(label=label, error=str(exc)))
    return board
