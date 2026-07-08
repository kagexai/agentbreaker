"""Discovery source connectors.

Sources are curated (offline, public-by-design CTFs) and model registries (OpenRouter).
The earlier web_search source was removed: with no live web access it hallucinated URLs.
The CTFtime source was removed: prompt-injection CTFs are rarely listed there.
"""

from __future__ import annotations

from .curated import CuratedSource
from .models import ModelRegistrySource

# Registry: name -> class. The engine instantiates the enabled ones.
ALL_SOURCES = {
    CuratedSource.name: CuratedSource,
    ModelRegistrySource.name: ModelRegistrySource,
}

__all__ = [
    "CuratedSource",
    "ModelRegistrySource",
    "ALL_SOURCES",
]
