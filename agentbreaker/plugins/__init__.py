"""Built-in provider plugins and model switching."""

from .model_switch import switch_model
from .registry import (
    get_provider,
    list_providers,
    load_registry,
    match_provider,
    provider_catalog,
    provider_presets,
    require_provider,
)

__all__ = [
    "get_provider",
    "list_providers",
    "load_registry",
    "match_provider",
    "provider_catalog",
    "provider_presets",
    "require_provider",
    "switch_model",
]
