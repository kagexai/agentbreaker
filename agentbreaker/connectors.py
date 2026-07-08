"""Standalone target connectors — point the red-team at anything, no config file.

``integrations.as_callback`` already red-teams any Python callable; this adds the connectors
teams actually need for a *deployed* target (PyRIT's http_target / browser_target analog):

- ``http_callback(url, …)`` — turn any chat HTTP endpoint into a red-team callback: templated
  request body (``{{prompt}}``), header/auth, and a JSON path to pluck the reply out of the
  response. Works with the corpus / suite / red_team runners immediately.
- ``openai_chat_callback(model, base_url=…)`` — one-liner for any OpenAI-compatible
  ``/chat/completions`` endpoint (OpenAI, Groq, Together, local vLLM, Ollama-openai, …).
- ``browser_callback(url, selectors…)`` — drive a deployed chat *UI* via Playwright when it's
  installed; otherwise raises with the install hint (no hard dependency).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

CallbackT = Callable[[str], str]


def render_body(template: str, prompt: str) -> str:
    """Substitute {{prompt}} into a JSON body template, JSON-escaping the prompt."""
    escaped = json.dumps(prompt)[1:-1]  # drop the surrounding quotes; keep escapes
    return template.replace("{{prompt}}", escaped)


def extract_path(data: Any, path: str) -> str:
    """Pluck a value out of parsed JSON via a dotted path with numeric indices.
    e.g. 'choices.0.message.content'. Empty path returns the whole thing stringified."""
    if not path:
        return data if isinstance(data, str) else json.dumps(data)
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return ""
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
        if cur is None:
            return ""
    return cur if isinstance(cur, str) else json.dumps(cur)


def http_callback(url: str, *, method: str = "POST",
                  headers: dict[str, str] | None = None,
                  body_template: str = '{"message": "{{prompt}}"}',
                  response_path: str = "", timeout: float = 30.0,
                  api_key_env: str | None = None,
                  auth_header: str = "Authorization",
                  auth_prefix: str = "Bearer ") -> CallbackT:
    """Build a red-team callback for any chat HTTP endpoint."""
    import requests

    hdrs = {"Content-Type": "application/json", **(headers or {})}
    if api_key_env:
        key = os.environ.get(api_key_env, "")
        if key:
            hdrs[auth_header] = f"{auth_prefix}{key}"

    def _send(prompt: str) -> str:
        body = render_body(body_template, prompt)
        resp = requests.request(method.upper(), url, headers=hdrs, data=body.encode(), timeout=timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return extract_path(resp.json(), response_path)
        except ValueError:
            return resp.text

    return _send


def openai_chat_callback(model: str, *, base_url: str = "https://api.openai.com/v1",
                         api_key_env: str = "OPENAI_API_KEY", system: str = "") -> CallbackT:
    """One-liner for any OpenAI-compatible /chat/completions endpoint."""
    msgs = ([{"role": "system", "content": system}] if system else [])
    body_template = json.dumps({
        "model": model,
        "messages": msgs + [{"role": "user", "content": "{{prompt}}"}],
    })
    return http_callback(
        f"{base_url.rstrip('/')}/chat/completions",
        body_template=body_template,
        response_path="choices.0.message.content",
        api_key_env=api_key_env,
    )


def browser_callback(url: str, *, input_selector: str, submit_selector: str,
                     response_selector: str, timeout_ms: int = 15000) -> CallbackT:
    """Drive a deployed chat UI via Playwright. Requires ``pip install playwright`` +
    ``playwright install chromium``; raises a clear error if unavailable (no hard dep)."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        raise RuntimeError(
            "browser_callback needs Playwright: `pip install playwright && playwright install chromium`")

    def _send(prompt: str) -> str:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:  # pragma: no cover - requires a real browser
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            try:
                page.goto(url, timeout=timeout_ms)
                page.fill(input_selector, prompt)
                page.click(submit_selector)
                page.wait_for_selector(response_selector, timeout=timeout_ms)
                return page.text_content(response_selector) or ""
            finally:
                browser.close()

    return _send
