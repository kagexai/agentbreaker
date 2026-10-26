"""Switch the judge or generator model without rewriting the rest of the config.

The pipeline follows the Hermes shape: resolve the provider plugin, pick a
model (explicit or the builtin default), then write only that role's binding.
"""

from __future__ import annotations

import re
from typing import Any

from ..llm_error_utils import normalize_openai_base_url
from .registry import require_provider

_MODEL_RE = re.compile(r"^[A-Za-z0-9._:@/+\-]{1,128}$")
_ROLES = {"judge", "generator", "both"}


def switch_model(
    config: dict[str, Any],
    *,
    role: str,
    provider: str,
    model: str = "",
    endpoint: str = "",
) -> dict[str, Any]:
    selected_role = (role or "").strip().lower()
    if selected_role not in _ROLES:
        raise ValueError("role must be one of: judge, generator, both.")
    plugin = require_provider(provider)
    chosen_model = (model or plugin.default_model).strip()
    if not _MODEL_RE.fullmatch(chosen_model):
        raise ValueError(
            "model must be 1-128 characters of letters, numbers, and . _ : @ / + -"
        )
    if endpoint.strip():
        chosen_endpoint = normalize_openai_base_url(endpoint)
        if not chosen_endpoint:
            raise ValueError("endpoint must be an http(s) base URL.")
    else:
        chosen_endpoint = normalize_openai_base_url(plugin.endpoint)

    roles = ["judge", "generator"] if selected_role == "both" else [selected_role]
    for role_name in roles:
        block = config.setdefault(role_name, {})
        if not isinstance(block, dict):
            block = {}
            config[role_name] = block
        block["provider"] = "llm"
        block_cfg = block.get("config")
        if not isinstance(block_cfg, dict):
            block_cfg = {}
            block["config"] = block_cfg
        block_cfg["api"] = plugin.api
        block_cfg["model"] = chosen_model
        if plugin.api_key_env:
            block_cfg["api_key_env"] = plugin.api_key_env
        else:
            block_cfg.pop("api_key_env", None)
        if chosen_endpoint:
            block_cfg["endpoint"] = chosen_endpoint
        else:
            block_cfg.pop("endpoint", None)

    return {
        "role": selected_role,
        "provider": plugin.id,
        "label": plugin.label,
        "model": chosen_model,
        "api": plugin.api,
        "endpoint": chosen_endpoint,
        "api_key_env": plugin.api_key_env,
        "roles": roles,
        "builtin": plugin.builtin,
    }
