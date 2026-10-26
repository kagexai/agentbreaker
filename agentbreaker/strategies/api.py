"""Plugin registration surface for attack strategies.

Builtins call ``register(api)`` and use ``api.register_strategy(...)``. The
attack runner reads the registry instead of a hardcoded strategy table.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


Builder = Callable[[], Any]


@dataclass(frozen=True)
class StrategyPlugin:
    """One attack strategy family."""

    id: str
    category: str
    technique: str
    owasp_ref: str
    benchmark_ref: str
    description: str
    builder: Builder
    aliases: tuple[str, ...] = ()
    order: int = 100
    short_prompts: tuple[str, ...] = ()
    combo_overlay: bool = False
    builtin: bool = True

    def public_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "key": self.id,
            "category": self.category,
            "technique": self.technique,
            "owasp_ref": self.owasp_ref,
            "benchmark_ref": self.benchmark_ref,
            "description": self.description,
            "aliases": list(self.aliases),
            "order": self.order,
            "short_prompts": list(self.short_prompts),
            "combo_overlay": self.combo_overlay,
            "builtin": self.builtin,
        }


@dataclass
class StrategyRegistry:
    strategies: dict[str, StrategyPlugin] = field(default_factory=dict)

    def add(self, plugin: StrategyPlugin) -> None:
        key = plugin.id.strip().lower()
        if not key:
            raise ValueError("Strategy plugin id is required.")
        if key in self.strategies:
            raise ValueError(f"Strategy plugin '{key}' is already registered.")
        self.strategies[key] = plugin

    def all(self) -> list[StrategyPlugin]:
        return sorted(self.strategies.values(), key=lambda item: (item.order, item.id))

    def get(self, key: str) -> StrategyPlugin | None:
        cleaned = (key or "").strip().lower()
        if not cleaned:
            return None
        direct = self.strategies.get(cleaned)
        if direct is not None:
            return direct
        for plugin in self.strategies.values():
            if cleaned in {alias.lower() for alias in plugin.aliases}:
                return plugin
            if cleaned == plugin.technique.lower():
                return plugin
        return None

    def require(self, key: str) -> StrategyPlugin:
        plugin = self.get(key)
        if plugin is None:
            known = ", ".join(item.id for item in self.all())
            raise ValueError(f"Unknown strategy '{key}'. Builtins: {known}.")
        return plugin


class StrategyAPI:
    """The object passed to each strategy builtin's ``register`` function."""

    def __init__(self, registry: StrategyRegistry) -> None:
        self._registry = registry

    def register_strategy(self, plugin: StrategyPlugin) -> None:
        self._registry.add(plugin)
