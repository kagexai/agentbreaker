"""Discover bundled strategy plugins and expose one registry."""

from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache

from .api import StrategyAPI, StrategyPlugin, StrategyRegistry
from . import builtins as builtins_package


@lru_cache(maxsize=1)
def load_registry() -> StrategyRegistry:
    registry = StrategyRegistry()
    api = StrategyAPI(registry)
    for module_info in pkgutil.iter_modules(builtins_package.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{builtins_package.__name__}.{module_info.name}")
        register = getattr(module, "register", None)
        if not callable(register):
            continue
        register(api)
    return registry


def list_strategies() -> list[StrategyPlugin]:
    return load_registry().all()


def get_strategy(key: str) -> StrategyPlugin | None:
    return load_registry().get(key)


def require_strategy(key: str) -> StrategyPlugin:
    return load_registry().require(key)


def strategy_catalog() -> list[dict[str, object]]:
    return [plugin.public_record() for plugin in list_strategies()]


def combo_overlay_ids() -> set[str]:
    return {plugin.id for plugin in list_strategies() if plugin.combo_overlay}
