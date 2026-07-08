"""Bring-your-own-target adapters + one-call red_team() — the framework-integration gap.

deepteam/deepeval/promptfoo all let you red-team an arbitrary function or an existing
framework object (LangChain runnable, an agent's ``.invoke``); AgentBreaker's live engine was
provider-config-only. This module adapts any of those into the ``Callable[[str], str]`` the
corpus / suite / guardrail runners already consume, and exposes a single ``red_team()`` entry
that mirrors deepteam's ergonomics.

Zero hard dependencies — adapters duck-type common framework interfaces (``.invoke`` /
``.run`` / ``.predict`` / ``.chat``) so importing this never requires LangChain et al.
"""

from __future__ import annotations

from typing import Any, Callable

CallbackT = Callable[[str], str]


def _coerce_text(out: Any) -> str:
    """Normalize a framework's return value to a string."""
    if out is None:
        return ""
    if isinstance(out, str):
        return out
    # LangChain messages / responses commonly expose `.content`
    content = getattr(out, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(out, dict):
        for k in ("output", "text", "content", "answer", "result", "response"):
            v = out.get(k)
            if isinstance(v, str):
                return v
    return str(out)


def as_callback(target: Any) -> CallbackT:
    """Adapt a target into a red-team callback ``str -> str``.

    Accepts, in order: a plain callable; a LangChain-style runnable/chain/LLM exposing
    ``.invoke`` / ``.run`` / ``.predict``; or a client exposing ``.chat`` / ``.complete``.
    """
    if target is None:
        raise ValueError("target is required")

    if callable(target) and not hasattr(target, "invoke") and not hasattr(target, "run"):
        return lambda prompt: _coerce_text(target(prompt))

    for method in ("invoke", "run", "predict", "chat", "complete", "__call__"):
        fn = getattr(target, method, None)
        if callable(fn):
            return lambda prompt, _fn=fn: _coerce_text(_fn(prompt))

    raise TypeError(f"don't know how to call target of type {type(target).__name__}; "
                    "pass a callable or an object with .invoke/.run/.predict")


def from_langchain(runnable: Any) -> CallbackT:
    """Adapt a LangChain runnable/chain/LLM (anything with ``.invoke``) to a callback."""
    invoke = getattr(runnable, "invoke", None) or getattr(runnable, "run", None)
    if not callable(invoke):
        raise TypeError("expected a LangChain object with .invoke/.run")
    return lambda prompt: _coerce_text(invoke(prompt))


def from_callable(fn: Callable[[str], Any]) -> CallbackT:
    return lambda prompt: _coerce_text(fn(prompt))


def red_team(target: Any, *, corpus: str = "known_jailbreaks",
             secrets: list[str] | None = None, trace: bool = False) -> dict[str, Any]:
    """One call: red-team any target (callable / framework object / configured provider name)
    against a bundled corpus. Mirrors deepteam's ``red_team(model_callback=...)``.

    If ``target`` is a str it is treated as a configured target id (live provider). Set
    ``trace=True`` to record a span per attack (see ``tracing``).
    """
    from .corpus import run_corpus

    if isinstance(target, str):
        from .harm_taxonomy import provider_callback
        cb: CallbackT = provider_callback(target, "target_config.yaml")
    else:
        cb = as_callback(target)

    if trace:
        from .tracing import observe
        cb = observe("attack")(cb)

    return run_corpus(corpus, cb, secrets=secrets)
