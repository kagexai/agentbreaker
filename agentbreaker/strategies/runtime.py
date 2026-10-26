"""Bound context for strategy builders while an attack process is running."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..domain_helpers import DomainContext
from ..seed_manager import SeedManager


@dataclass
class StrategyRuntime:
    attack_id: str
    target_id: str
    variant_index: int
    ctx: DomainContext
    seeds: SeedManager
    attack_spec: dict[str, Any] = field(default_factory=dict)
    generated_payload: str = ""
    anchor_payload: str = ""


_RUNTIME: StrategyRuntime | None = None


def bind(runtime: StrategyRuntime) -> StrategyRuntime:
    global _RUNTIME
    _RUNTIME = runtime
    return runtime


def clear() -> None:
    global _RUNTIME
    _RUNTIME = None


def current() -> StrategyRuntime:
    if _RUNTIME is None:
        raise RuntimeError("Strategy runtime is not bound. Call strategies.bind(...) first.")
    return _RUNTIME
