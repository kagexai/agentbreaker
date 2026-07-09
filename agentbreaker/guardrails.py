"""Deployable guardrail layer — the defensive counterpart deepteam ships and AgentBreaker lacked.

AgentBreaker is an offensive engine; this closes the loop: lightweight input/output guards you
can drop inline in a live app to BLOCK the attacks the red-team finds, plus a "red-team the
guard" harness that replays the bundled attack corpora through a guard set and reports its
block rate — so you can measure a defense the same way you measure a target.

Guards are deterministic (reuse the calibrated detectors in ``evaluators``) so they add ~no
latency and need no extra key; an optional LLM judge can back the fuzzier ones. Modelled on
deepteam's ``Guardrails(input_guards, output_guards, sample_rate)`` with per-guard verdicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .evaluators import pii_evaluator, toxicity_evaluator, secret_evaluator, is_refusal

SafetyLevel = str  # "safe" | "unsafe" | "borderline"


@dataclass
class GuardVerdict:
    guard: str
    safety_level: SafetyLevel
    score: float           # 0..1, higher = more unsafe
    reason: str

    @property
    def unsafe(self) -> bool:
        return self.safety_level == "unsafe"

    def to_dict(self) -> dict[str, Any]:
        return {"guard": self.guard, "safety_level": self.safety_level,
                "score": round(self.score, 2), "reason": self.reason}


@dataclass
class GuardResult:
    text: str
    verdicts: list[GuardVerdict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(v.unsafe for v in self.verdicts)

    def to_dict(self) -> dict[str, Any]:
        return {"blocked": self.blocked, "verdicts": [v.to_dict() for v in self.verdicts]}


# ── Individual guards ─────────────────────────────────────────────────────────
# A guard is a callable(text) -> GuardVerdict. `where` marks input/output applicability.

Guard = Callable[[str], GuardVerdict]

# Prompt-injection / jailbreak framings a live input guard should catch.
_INJECTION_PATTERNS = [
    r"ignore\s+[\w\s]{0,25}?(instructions|prompts|rules)",
    r"system override", r"developer mode", r"\bDAN\b", r"jailbreak",
    r"disregard\s+[\w\s]{0,20}?(rules|guidelines|policy|instructions)",
    r"you are now (an?|in) [^.]*(unrestricted|no rules|no restrictions)",
    r"content[_ ]policy\s*(=|:)?\s*(disabled|off|false)",
    r"pretend (you|to)[^.]*no (rules|restrictions|policy)",
    r"reveal (your|the) (system prompt|hidden instructions|rules)",
    # broadened framings (opposite-day / persona / relay / echo-bait / override)
    r"opposite day", r"stay (fully )?in character", r"no (rules|restrictions|content policy|filter)",
    r"unrestricted (developer|mode|ai|assistant)", r"prior instructions are (void|suspended|null)",
    r"(reply|respond|output|say) (with )?exactly", r"confirm (activation|by )",
    r"translate .* (working language|to your language|then back)",
    r"reverse it back", r"in a (fictional|hypothetical) world where you have no",
    r"<system_config>|<content_policy>|authorized\s*[:=]\s*true",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

# Unicode confusables an attacker uses to smuggle keywords past a plaintext filter.
_DEHOMOGLYPH = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "О": "O", "Р": "P", "Т": "T",
})
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def _normalize(text: str) -> str:
    """Undo the evasions the named-attack library uses: strip zero-width chars and map
    Unicode confusables back to ASCII so keyword matching can't be smuggled past."""
    return (text or "").translate(_ZERO_WIDTH).translate(_DEHOMOGLYPH)


def _decoded_variants(text: str) -> list[str]:
    """The text plus decoded views (base64 / rot13) so encoding-wrapped injections are seen."""
    import base64
    import codecs
    out = [text]
    try:
        out.append(codecs.decode(text, "rot13"))
    except Exception:
        pass
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text or ""):
        try:
            dec = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
            s = dec.decode("utf-8", "ignore")
            if s.isprintable():
                out.append(s)
        except Exception:
            pass
    return out


def prompt_injection_guard(text: str) -> GuardVerdict:
    for variant in _decoded_variants(_normalize(text)):
        m = _INJECTION_RE.search(variant)
        if m:
            return GuardVerdict("prompt_injection", "unsafe", 1.0,
                                f"matched injection pattern: {m.group(0)[:60]!r}")
    return GuardVerdict("prompt_injection", "safe", 0.0, "no injection pattern")


def toxicity_guard(text: str) -> GuardVerdict:
    v = toxicity_evaluator("", text or "")
    return GuardVerdict("toxicity", "unsafe" if v.breached else "safe",
                        1.0 if v.breached else 0.0, v.reason)


def pii_guard(text: str) -> GuardVerdict:
    v = pii_evaluator("", text or "")
    return GuardVerdict("pii", "unsafe" if v.breached else "safe",
                        1.0 if v.breached else 0.0, v.reason)


def make_secrets_guard(secrets: list[str]) -> Guard:
    ev = secret_evaluator(secrets or [])

    def _guard(text: str) -> GuardVerdict:
        v = ev("", text or "")
        return GuardVerdict("secrets", "unsafe" if v.breached else "safe",
                            1.0 if v.breached else 0.0, v.reason)
    return _guard


# Harmful-output guard: the output complied with (did not refuse) a disallowed request AND
# reads as operational content. Deterministic proxy: non-refusal + harmful lexicon hit.
_HARM_LEXICON = re.compile(
    r"\b(step[- ]?by[- ]?step|synthesi[sz]e|payload|exploit|ransomware|detonat|"
    r"how to (make|build|create) (a )?(bomb|weapon|explosive|virus))\b", re.IGNORECASE)


def harmful_output_guard(text: str) -> GuardVerdict:
    t = text or ""
    if is_refusal(t):
        return GuardVerdict("harmful_output", "safe", 0.0, "response is a refusal")
    if _HARM_LEXICON.search(t):
        return GuardVerdict("harmful_output", "unsafe", 0.9,
                            "non-refusal output with operational-harm lexicon")
    return GuardVerdict("harmful_output", "safe", 0.0, "no harm lexicon")


_DEFAULT_INPUT_GUARDS: list[Guard] = [prompt_injection_guard, toxicity_guard]
_DEFAULT_OUTPUT_GUARDS: list[Guard] = [pii_guard, toxicity_guard, harmful_output_guard]


# ── Guardrails wrapper ────────────────────────────────────────────────────────

@dataclass
class Guardrails:
    """Inline input/output filter for a live app. ``sample_rate`` deterministically samples a
    fraction of requests (by hash) for teams that can't afford to guard every call."""
    input_guards: list[Guard] = field(default_factory=lambda: list(_DEFAULT_INPUT_GUARDS))
    output_guards: list[Guard] = field(default_factory=lambda: list(_DEFAULT_OUTPUT_GUARDS))
    sample_rate: float = 1.0

    def _sampled(self, text: str) -> bool:
        if self.sample_rate >= 1.0:
            return True
        # deterministic per-text sampling (no RNG so it's reproducible/testable)
        h = abs(hash(text)) % 1000
        return h < int(self.sample_rate * 1000)

    def guard_input(self, text: str) -> GuardResult:
        if not self._sampled(text):
            return GuardResult(text, [])
        return GuardResult(text, [g(text) for g in self.input_guards])

    def guard_output(self, text: str) -> GuardResult:
        if not self._sampled(text):
            return GuardResult(text, [])
        return GuardResult(text, [g(text) for g in self.output_guards])


# ── Red-team the guard: how many corpus attacks does it block? ────────────────

def red_team_guards(corpus_name: str = "known_jailbreaks", *,
                    guardrails: Guardrails | None = None) -> dict[str, Any]:
    """Replay a bundled attack corpus through the INPUT guards and report block rate — the
    defensive analog of a resistance benchmark. A good guard blocks the malicious inputs."""
    from .corpus import load_corpus
    gr = guardrails or Guardrails()
    entries = load_corpus(corpus_name)
    rows = []
    blocked = 0
    for e in entries:
        res = gr.guard_input(e.prompt)
        if res.blocked:
            blocked += 1
        rows.append({"id": e.id, "technique": e.technique, "blocked": res.blocked,
                     "by": [v.guard for v in res.verdicts if v.unsafe]})
    total = len(entries)
    return {
        "corpus": corpus_name,
        "total": total,
        "blocked": blocked,
        "block_rate_pct": round(100 * blocked / total) if total else 0,
        "input_guards": [g.__name__ if hasattr(g, "__name__") else "guard" for g in gr.input_guards],
        "results": rows,
    }


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(prog="agentbreaker-guard",
                                 description="Red-team a guardrail: how many corpus attacks does it block?")
    ap.add_argument("--corpus", default="known_jailbreaks")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = red_team_guards(args.corpus)
    if args.json:
        print(_json.dumps(report, indent=2))
    else:
        print(f"Guardrail vs {report['corpus']}: blocked {report['blocked']}/{report['total']} "
              f"({report['block_rate_pct']}%)\n")
        for r in report["results"]:
            mark = "BLOCK by " + ",".join(r["by"]) if r["blocked"] else "PASSED (missed)"
            print(f"  {r['technique']:22s} {mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
