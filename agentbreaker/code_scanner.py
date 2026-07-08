"""Static code + trace scanner — the CodeGuard / deepteam-code_scanner / garak-packagehallucination gap.

LLM output isn't just prose: agents write code and call tools. This scans two surfaces:
- ``scan_code(code)`` — LLM-generated source for hardcoded secrets, dangerous exec, unsafe
  deserialization, SQL/command injection, weak crypto, path traversal, and unverified imports
  (possible package hallucination — the supply-chain risk garak probes).
- ``scan_trace(spans)`` — recorded tool/LLM spans (from ``tracing``) for secrets in tool args,
  SSRF-y internal URLs, and injection payloads forwarded into tool calls.

Deterministic regex/keyword rules with stable IDs so findings are diffable across runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class CodeFinding:
    rule_id: str
    severity: str
    line: int
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "severity": self.severity, "line": self.line,
                "title": self.title, "detail": self.detail}


# (rule_id, severity, title, compiled_regex)
_CODE_RULES: list[tuple[str, str, str, re.Pattern]] = [
    ("CG-CRED-001", "critical", "Hardcoded credential",
     re.compile(r"(?i)(api[_-]?key|secret|passwo?rd|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("CG-CRED-002", "critical", "Hardcoded cloud/private key",
     re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9]{20,})")),
    ("CG-EXEC-001", "high", "Dynamic code execution",
     re.compile(r"\b(eval|exec)\s*\(")),
    ("CG-EXEC-002", "high", "Shell execution / command injection risk",
     re.compile(r"(os\.system\s*\(|subprocess\.[a-z]+\([^)]*shell\s*=\s*True|`[^`]+`)")),
    ("CG-DESER-001", "high", "Unsafe deserialization",
     re.compile(r"(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|marshal\.loads?\s*\()")),
    ("CG-SQLI-001", "high", "SQL built by string formatting",
     re.compile(r"(?i)(execute|executemany)\s*\(\s*(f['\"]|['\"][^'\"]*%[sd]|['\"][^'\"]*\+|['\"][^'\"]*\.format)")),
    ("CG-CRYPTO-001", "medium", "Weak cryptography",
     re.compile(r"(?i)(hashlib\.(md5|sha1)\s*\(|\bDES\b|Random\(\)\.random|math\.random)")),
    ("CG-PATH-001", "medium", "Possible path traversal",
     re.compile(r"open\s*\(\s*[^)]*(\.\./|request\.|input\(|argv)")),
    ("CG-SSRF-001", "medium", "Request to a raw/user-controlled URL",
     re.compile(r"(requests|urllib|httpx)\.[a-z]+\(\s*[^)]*(input\(|request\.|argv|\+\s*)")),
]

# Package-hallucination heuristic: imports outside stdlib + a small allowlist are flagged as
# "unverified" (can't confirm existence offline, but supply-chain risk if the model invented it).
_STDLIB = set(__import__("sys").stdlib_module_names) if hasattr(__import__("sys"), "stdlib_module_names") else set()
_COMMON_PKGS = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy",
    "boto3", "openai", "anthropic", "httpx", "aiohttp", "pytest", "yaml", "dotenv", "redis",
    "celery", "torch", "transformers", "sklearn", "scipy", "matplotlib", "pillow", "PIL",
    "bs4", "lxml", "click", "rich", "tqdm", "jinja2", "cryptography", "jwt", "bcrypt",
    "psycopg2", "pymongo", "langchain", "llama_index", "tiktoken", "qrcode",
}
_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z_][\w]*)", re.MULTILINE)


def scan_code(code: str, *, language: str = "python") -> list[CodeFinding]:
    """Scan a code string; returns findings sorted most-severe first."""
    findings: list[CodeFinding] = []
    lines = (code or "").splitlines()

    def _line_of(pos: int) -> int:
        return code.count("\n", 0, pos) + 1

    for rule_id, sev, title, rx in _CODE_RULES:
        for m in rx.finditer(code or ""):
            findings.append(CodeFinding(rule_id, sev, _line_of(m.start()), title,
                                        f"matched: {m.group(0)[:80]!r}"))

    if language == "python":
        for m in _IMPORT_RE.finditer(code or ""):
            mod = m.group(1)
            if mod in _STDLIB or mod in _COMMON_PKGS:
                continue
            findings.append(CodeFinding("CG-PKG-001", "medium", _line_of(m.start()),
                                        "Unverified import (possible package hallucination)",
                                        f"import of '{mod}' is not stdlib or a known common package"))

    findings.sort(key=lambda f: (_SEV.get(f.severity, 9), f.line))
    return findings


def scan_code_report(code: str, *, language: str = "python") -> dict[str, Any]:
    fs = scan_code(code, language=language)
    return {"language": language, "findings": [f.to_dict() for f in fs],
            "count": len(fs),
            "by_severity": {s: sum(1 for f in fs if f.severity == s)
                            for s in ("critical", "high", "medium", "low")}}


# ── Trace scanner (tool/LLM spans) ────────────────────────────────────────────

@dataclass
class TraceFinding:
    rule_id: str
    severity: str
    span: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "severity": self.severity, "span": self.span,
                "title": self.title, "detail": self.detail}


_INTERNAL_URL_RE = re.compile(r"(169\.254\.169\.254|localhost|127\.0\.0\.1|\.internal\b|10\.\d+\.\d+\.\d+|metadata\.google)")
_INJECTION_RE = re.compile(r"(?i)('\s*or\s*1\s*=\s*1|;\s*drop\s+table|\$\(|\|\s*sh\b|&&\s*rm\b|<script)")
_SECRET_RE = re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN)")


def scan_trace(spans: list[Any]) -> list[TraceFinding]:
    """Scan recorded spans/tool-calls. Accepts tracing.Span objects or dicts with
    name/input/output/attributes (tool args may live in attributes['args'])."""
    out: list[TraceFinding] = []
    for sp in spans or []:
        name = getattr(sp, "name", None) or (sp.get("name") if isinstance(sp, dict) else "span")
        blobs = []
        for attr in ("input", "output"):
            v = getattr(sp, attr, None) if not isinstance(sp, dict) else sp.get(attr)
            if isinstance(v, str):
                blobs.append(v)
        attrs = getattr(sp, "attributes", None) if not isinstance(sp, dict) else sp.get("attributes")
        if isinstance(attrs, dict):
            blobs.append(str(attrs.get("args", "")))
        text = " ".join(blobs)
        if _SECRET_RE.search(text):
            out.append(TraceFinding("TR-SECRET-001", "critical", str(name),
                                    "Secret in tool/LLM span", "credential-like token in span data"))
        if _INTERNAL_URL_RE.search(text):
            out.append(TraceFinding("TR-SSRF-001", "high", str(name),
                                    "Internal/metadata URL in span", "possible SSRF target in span data"))
        if _INJECTION_RE.search(text):
            out.append(TraceFinding("TR-INJ-001", "high", str(name),
                                    "Injection payload forwarded", "SQLi/command/script marker in span data"))
    return out


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json as _json
    import sys
    ap = argparse.ArgumentParser(prog="agentbreaker-codescan",
                                 description="Statically scan (LLM-generated) code for security issues.")
    ap.add_argument("file", nargs="?", help="path to code file (or read stdin)")
    ap.add_argument("--language", default="python")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    code = open(args.file).read() if args.file else sys.stdin.read()
    report = scan_code_report(code, language=args.language)
    if args.json:
        print(_json.dumps(report, indent=2))
    else:
        print(f"{report['count']} finding(s): {report['by_severity']}\n")
        for f in report["findings"]:
            print(f"  {f['severity']:8s} {f['rule_id']}  L{f['line']}: {f['title']} — {f['detail']}")
    return 1 if report["by_severity"].get("critical") or report["by_severity"].get("high") else 0


if __name__ == "__main__":
    raise SystemExit(_main())
