"""Lightweight span tracing — the observability seam deepeval ships (@observe + OTel).

A dependency-free span recorder: decorate any callable with ``@observe(name)`` or wrap a block
in ``span(name)`` and every call is captured (name, truncated input/output, duration, error).
Spans are collected in-process for offline inspection (``get_spans`` / ``spans_to_jsonl``) and,
if ``opentelemetry`` is installed, mirrored to a real OTLP tracer — otherwise that's a silent
no-op so this import never forces the dependency.
"""

from __future__ import annotations

import functools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

# monotonic() is available (unlike time.time / Date.now); durations only, no wall-clock needed.
_LOCK = threading.Lock()
_SPANS: list["Span"] = []


@dataclass
class Span:
    name: str
    input: str = ""
    output: str = ""
    duration_ms: float = 0.0
    error: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "input": self.input[:300], "output": self.output[:300],
                "duration_ms": round(self.duration_ms, 1), "error": self.error,
                "attributes": self.attributes}


def _record(span: Span) -> None:
    with _LOCK:
        _SPANS.append(span)
    _otel_export(span)


def get_spans() -> list[Span]:
    with _LOCK:
        return list(_SPANS)


def clear_spans() -> None:
    with _LOCK:
        _SPANS.clear()


def spans_to_jsonl() -> str:
    import json
    return "\n".join(json.dumps(s.to_dict()) for s in get_spans())


class span:
    """Context manager: ``with span('recon') as s: ...`` — records duration + optional output."""

    def __init__(self, name: str, **attributes: Any):
        self.span = Span(name=name, attributes=dict(attributes))
        self._t0 = 0.0

    def __enter__(self) -> Span:
        self._t0 = time.monotonic()
        return self.span

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.span.duration_ms = (time.monotonic() - self._t0) * 1000
        if exc is not None:
            self.span.error = f"{exc_type.__name__}: {exc}"
        _record(self.span)
        return False  # never suppress


def observe(name: str | None = None) -> Callable[[Callable], Callable]:
    """Decorator that records a span per call. Captures first str arg as input, return as output."""
    def _decorate(fn: Callable) -> Callable:
        span_name = name or getattr(fn, "__name__", "span")

        @functools.wraps(fn)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            s = Span(name=span_name)
            first_str = next((a for a in args if isinstance(a, str)), "")
            s.input = first_str
            t0 = time.monotonic()
            try:
                out = fn(*args, **kwargs)
                s.output = out if isinstance(out, str) else str(out)
                return out
            except Exception as exc:
                s.error = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                s.duration_ms = (time.monotonic() - t0) * 1000
                _record(s)
        return _wrapped
    return _decorate


# ── Optional OpenTelemetry mirror (graceful) ─────────────────────────────────

_OTEL_TRACER = None
_OTEL_TRIED = False


def _otel_export(s: Span) -> None:
    global _OTEL_TRACER, _OTEL_TRIED
    if not _OTEL_TRIED:
        _OTEL_TRIED = True
        try:  # pragma: no cover - only when opentelemetry is installed
            from opentelemetry import trace as _t
            _OTEL_TRACER = _t.get_tracer("agentbreaker")
        except Exception:
            _OTEL_TRACER = None
    if _OTEL_TRACER is None:
        return
    try:  # pragma: no cover
        with _OTEL_TRACER.start_as_current_span(s.name) as otel_span:
            otel_span.set_attribute("agentbreaker.duration_ms", s.duration_ms)
            if s.error:
                otel_span.set_attribute("agentbreaker.error", s.error)
    except Exception:
        pass
