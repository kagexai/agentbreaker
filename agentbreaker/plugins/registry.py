"""Discover bundled provider plugins and expose one registry."""

from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache

from .api import PluginAPI, PluginRegistry, ProviderPlugin
from . import builtins as builtins_package


@lru_cache(maxsize=1)
def load_registry() -> PluginRegistry:
    registry = PluginRegistry()
    api = PluginAPI(registry)
    for module_info in pkgutil.iter_modules(builtins_package.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{builtins_package.__name__}.{module_info.name}")
        register = getattr(module, "register", None)
        if not callable(register):
            continue
        register(api)
    return registry


def list_providers() -> list[ProviderPlugin]:
    return load_registry().all()


def get_provider(key: str) -> ProviderPlugin | None:
    return load_registry().get(key)


def require_provider(key: str) -> ProviderPlugin:
    return load_registry().require(key)


def provider_presets() -> dict[str, dict[str, object]]:
    return {plugin.id: plugin.as_preset() for plugin in list_providers()}


def provider_catalog() -> list[dict[str, object]]:
    return [plugin.public_record() for plugin in list_providers()]


def match_provider(api: str, api_key_env: str | None, endpoint: str | None) -> str | None:
    from ..llm_error_utils import normalize_openai_base_url

    wanted_endpoint = normalize_openai_base_url(endpoint)
    wanted_env = api_key_env or None
    for plugin in list_providers():
        if plugin.api != api:
            continue
        if (plugin.api_key_env or None) != wanted_env:
            continue
        if normalize_openai_base_url(plugin.endpoint) == wanted_endpoint:
            return plugin.id
    return None
