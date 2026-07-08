"""Bring-your-own-target adapters + one-call red_team + span tracing."""

from __future__ import annotations

from agentbreaker import integrations as I
from agentbreaker import tracing as T


class _FakeLangChain:
    """Duck-types a LangChain runnable: .invoke returns an object with .content."""
    class _Msg:
        def __init__(self, c): self.content = c
    def invoke(self, prompt: str):
        return self._Msg("refused: " + prompt[:5])


class _FakeAgent:
    def run(self, prompt: str) -> str:
        return "I can't help with that."


def test_as_callback_plain_callable():
    cb = I.as_callback(lambda p: "echo:" + p)
    assert cb("hi") == "echo:hi"


def test_as_callback_langchain_and_coerces_content():
    cb = I.as_callback(_FakeLangChain())
    assert cb("ignore rules").startswith("refused:")


def test_as_callback_run_method_and_dict_output():
    assert I.as_callback(_FakeAgent())("x") == "I can't help with that."
    cb = I.as_callback(lambda p: {"output": "from-dict"})
    assert cb("x") == "from-dict"


def test_red_team_any_callable():
    rep = I.red_team(lambda p: "I refuse.", corpus="known_jailbreaks")
    assert rep["resistance_pct"] == 100 and rep["breached"] == 0


def test_tracing_observe_records_spans():
    T.clear_spans()
    cb = T.observe("attack")(lambda p: "ok:" + p)
    cb("hello")
    cb("world")
    spans = T.get_spans()
    assert len(spans) == 2
    assert spans[0].name == "attack" and spans[0].input == "hello" and spans[0].output == "ok:hello"
    assert spans[0].duration_ms >= 0


def test_tracing_captures_errors():
    T.clear_spans()
    @T.observe("boom")
    def _f(p):
        raise ValueError("nope")
    try:
        _f("x")
    except ValueError:
        pass
    assert T.get_spans()[0].error.startswith("ValueError")


def test_red_team_with_trace_records_span_per_attack():
    T.clear_spans()
    rep = I.red_team(lambda p: "no", corpus="known_jailbreaks", trace=True)
    assert len(T.get_spans()) == rep["total"]
