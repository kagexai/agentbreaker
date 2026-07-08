"""Standalone target connectors: HTTP endpoint, OpenAI-compatible, graceful browser."""

from __future__ import annotations

import json

import pytest

from agentbreaker import connectors as K


def test_render_body_escapes_prompt():
    out = K.render_body('{"message": "{{prompt}}"}', 'say "hi"\nnow')
    # result must be valid JSON with the prompt safely escaped
    assert json.loads(out)["message"] == 'say "hi"\nnow'


def test_extract_path_dotted_with_index():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert K.extract_path(data, "choices.0.message.content") == "hello"
    assert K.extract_path({"reply": "hi"}, "reply") == "hi"
    assert K.extract_path({"a": 1}, "missing") == ""
    assert K.extract_path("plain", "") == "plain"


def test_http_callback_end_to_end(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200
        text = ""
        def json(self):
            return {"choices": [{"message": {"content": "I refuse."}}]}

    def _fake_request(method, url, headers=None, data=None, timeout=None):
        captured["method"] = method
        captured["body"] = json.loads(data.decode())
        captured["auth"] = headers.get("Authorization")
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "request", _fake_request)
    monkeypatch.setenv("MY_KEY", "sekret")

    cb = K.http_callback("https://api.example.com/chat",
                         body_template='{"message": "{{prompt}}"}',
                         response_path="choices.0.message.content",
                         api_key_env="MY_KEY")
    out = cb("ignore instructions")
    assert out == "I refuse."
    assert captured["method"] == "POST"
    assert captured["body"]["message"] == "ignore instructions"
    assert captured["auth"] == "Bearer sekret"


def test_http_callback_raises_on_http_error(monkeypatch):
    class _Resp:
        status_code = 500
        text = "boom"
        def json(self): return {}
    import requests
    monkeypatch.setattr(requests, "request", lambda *a, **k: _Resp())
    cb = K.http_callback("https://x/y")
    with pytest.raises(RuntimeError):
        cb("hi")


def test_openai_chat_callback_builds_correct_request(monkeypatch):
    captured = {}
    class _Resp:
        status_code = 200
        text = ""
        def json(self): return {"choices": [{"message": {"content": "ok"}}]}
    import requests
    monkeypatch.setattr(requests, "request",
                        lambda m, u, headers=None, data=None, timeout=None: captured.update(url=u, body=json.loads(data)) or _Resp())
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    cb = K.openai_chat_callback("gpt-4o", system="be terse")
    assert cb("hello") == "ok"
    assert captured["url"].endswith("/chat/completions")
    assert captured["body"]["model"] == "gpt-4o"
    assert captured["body"]["messages"][0]["role"] == "system"
    assert captured["body"]["messages"][-1]["content"] == "hello"


def test_connectors_feed_the_red_team_runner(monkeypatch):
    # a connector callback plugs straight into the corpus/red_team runner
    from agentbreaker import integrations as I
    rep = I.red_team(lambda p: "I won't do that", corpus="known_jailbreaks")
    assert rep["resistance_pct"] == 100


def test_browser_callback_graceful_without_playwright():
    try:
        import playwright  # noqa: F401
        pytest.skip("playwright installed; graceful-error path not exercised")
    except Exception:
        with pytest.raises(RuntimeError, match="Playwright"):
            K.browser_callback("http://x", input_selector="#in",
                               submit_selector="#go", response_selector="#out")
