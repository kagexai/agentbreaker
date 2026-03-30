from __future__ import annotations

import re


_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b")


def redact_llm_secrets(text: str) -> str:
    """Mask common API-key patterns from provider error messages."""
    redacted = _ANTHROPIC_KEY_RE.sub("sk-ant-<redacted>", text)
    redacted = _OPENAI_KEY_RE.sub("sk-<redacted>", redacted)
    redacted = _GOOGLE_KEY_RE.sub("AIza<redacted>", redacted)
    return redacted


def infer_endpoint_provider(api: str, endpoint: str | None = None) -> str | None:
    """Infer the concrete provider behind a generic API/endpoint pair."""
    endpoint_lower = str(endpoint or "").lower()
    api_lower = str(api or "").lower()

    if api_lower == "anthropic":
        return "anthropic"
    if api_lower == "openai":
        return "openai"
    if api_lower != "openai-compatible":
        return None

    if not endpoint_lower or "api.openai.com" in endpoint_lower:
        return "openai"
    if "anthropic.com" in endpoint_lower:
        return "anthropic"
    if "generativelanguage.googleapis.com" in endpoint_lower:
        return "google"
    if "localhost" in endpoint_lower or "127.0.0.1" in endpoint_lower:
        return None
    return None


def _provider_display_name(provider: str | None) -> str:
    mapping = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "google": "Google",
    }
    return mapping.get(str(provider or "").lower(), str(provider or "LLM"))


def _indefinite_article(word: str) -> str:
    return "an" if word[:1].lower() in {"a", "e", "i", "o", "u"} else "a"


def detect_api_key_provider(api_key: str | None) -> str | None:
    """Best-effort provider detection from an API-key prefix."""
    if not api_key:
        return None
    if str(api_key).startswith("sk-ant-"):
        return "anthropic"
    if str(api_key).startswith("sk-"):
        return "openai"
    if str(api_key).startswith("AIza"):
        return "google"
    return None


def api_key_mismatch_warning(
    *,
    api: str,
    endpoint: str | None = None,
    api_key_env: str | None = None,
    api_key: str | None = None,
    role: str = "LLM",
) -> str | None:
    """Return a human-friendly warning if the configured key looks mismatched."""
    expected = infer_endpoint_provider(api, endpoint)
    actual = detect_api_key_provider(api_key)
    if not expected or not actual or expected == actual:
        return None

    env_name = api_key_env or "configured API key"
    actual_label = _provider_display_name(actual)
    expected_label = _provider_display_name(expected)
    return (
        f"{role} provider/key mismatch: {env_name} looks like {_indefinite_article(actual_label)} "
        f"{actual_label} key, but this engine is configured for {expected_label}."
    )


def describe_llm_exception(
    exc: Exception,
    *,
    api: str,
    model: str,
    endpoint: str | None = None,
    api_key_env: str | None = None,
    api_key: str | None = None,
    role: str = "LLM",
) -> str:
    """Turn raw provider exceptions into concise operator-facing diagnostics."""
    provider = infer_endpoint_provider(api, endpoint) or str(api or "llm")
    provider_label = _provider_display_name(provider)
    raw = redact_llm_secrets(f"{type(exc).__name__}: {exc}")
    lowered = raw.lower()

    mismatch = api_key_mismatch_warning(
        api=api,
        endpoint=endpoint,
        api_key_env=api_key_env,
        api_key=api_key,
        role=role,
    )
    if mismatch:
        env_name = api_key_env or "the configured key"
        return (
            f"{mismatch} Update {env_name} or switch the {role.lower()} provider "
            f"before calling {provider_label}/{model}."
        )

    env_name = api_key_env or "the configured API key"

    if (
        "incorrect api key provided" in lowered
        or "invalid_api_key" in lowered
        or ("401" in lowered and "unauthorized" in lowered)
    ):
        return (
            f"{role} authentication failed for {provider_label}/{model}: {env_name} is invalid, "
            "expired, or unauthorized for this endpoint."
        )

    if (
        "insufficient_quota" in lowered
        or "exceeded your current quota" in lowered
        or "billing" in lowered
    ):
        return (
            f"{role} quota exhausted for {provider_label}/{model}: the API key appears valid, "
            "but the account has no remaining quota or billing access."
        )

    if "429" in lowered or "rate limit" in lowered or "too many requests" in lowered:
        return (
            f"{role} rate limited by {provider_label}/{model}: wait and retry, or lower request volume."
        )

    if (
        "context_length_exceeded" in lowered
        or "maximum context length" in lowered
        or "too many tokens" in lowered
        or "prompt is too long" in lowered
    ):
        return (
            f"{role} token/context limit exceeded on {provider_label}/{model}: reduce payload size "
            "or lower max token settings."
        )

    if "unsupported parameter" in lowered and "max_tokens" in lowered:
        return (
            f"{role} request config mismatch for {provider_label}/{model}: this model does not accept "
            "max_tokens. Use max_completion_tokens instead."
        )

    if "timeout" in lowered or "timed out" in lowered:
        return (
            f"{role} request timed out for {provider_label}/{model}: the endpoint may be slow or unreachable."
        )

    if (
        "connection error" in lowered
        or "connecterror" in lowered
        or "name or service not known" in lowered
        or "temporary failure in name resolution" in lowered
        or "nodename nor servname provided" in lowered
        or "connection refused" in lowered
    ):
        return (
            f"{role} connection failed for {provider_label}/{model}: the endpoint is unreachable or misconfigured."
        )

    return f"{role} call failed for {provider_label}/{model}: {raw}"
