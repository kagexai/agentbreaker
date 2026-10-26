"""Plugin registration surface for built-in model providers.

Builtins call ``register(api)`` and use ``api.register_provider(...)``. The rest
of AgentBreaker reads the registry instead of hardcoding provider tables.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderPlugin:
    """One model provider, bundled or later dropped in as a builtin module."""

    id: str
    label: str
    api: str
    default_model: str
    api_key_env: str | None = None
    endpoint: str | None = None
    models: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    order: int = 100
    builtin: bool = True

    def as_preset(self) -> dict[str, object]:
        return {
            "label": self.label,
            "api": self.api,
            "api_key_env": self.api_key_env,
            "endpoint": self.endpoint,
            "default_model": self.default_model,
            "models": list(self.models),
            "aliases": list(self.aliases),
            "builtin": self.builtin,
        }

    def public_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "key": self.id,
            "label": self.label,
            "api": self.api,
            "api_key_env": self.api_key_env,
            "endpoint": self.endpoint,
            "default_model": self.default_model,
            "models": list(self.models or (self.default_model,)),
            "aliases": list(self.aliases),
            "builtin": self.builtin,
        }


@dataclass
class PluginRegistry:
    providers: dict[str, ProviderPlugin] = field(default_factory=dict)

    def add(self, plugin: ProviderPlugin) -> None:
        key = plugin.id.strip().lower()
        if not key:
            raise ValueError("Provider plugin id is required.")
        if key in self.providers:
            raise ValueError(f"Provider plugin '{key}' is already registered.")
        self.providers[key] = plugin

    def all(self) -> list[ProviderPlugin]:
        return sorted(self.providers.values(), key=lambda item: (item.order, item.id))

    def get(self, key: str) -> ProviderPlugin | None:
        cleaned = (key or "").strip().lower()
        if not cleaned:
            return None
        direct = self.providers.get(cleaned)
        if direct is not None:
            return direct
        for plugin in self.providers.values():
            if cleaned in {alias.lower() for alias in plugin.aliases}:
                return plugin
        return None

    def require(self, key: str) -> ProviderPlugin:
        plugin = self.get(key)
        if plugin is None:
            known = ", ".join(plugin.id for plugin in self.all())
            raise ValueError(f"Unknown provider '{key}'. Builtins: {known}.")
        return plugin


class PluginAPI:
    """The object passed to each builtin's ``register`` function."""

    def __init__(self, registry: PluginRegistry) -> None:
        self._registry = registry

    def register_provider(self, plugin: ProviderPlugin) -> None:
        self._registry.add(plugin)
