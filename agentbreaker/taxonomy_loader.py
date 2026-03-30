"""
taxonomy/taxonomy_loader.py -- Unified taxonomy access for AgentBreaker.

Loads agentbreaker_taxonomy.yaml (categories → subcategories → optional seeds → strategies)
and optionally merges with arc_pi_taxonomy.json for deeper technique/evasion context.

Used by:
  - attack.py / campaign.py  → strategy selection, seed mapping
  - attack_generator.py      → full taxonomy context for LLM-based generation
  - agentbreaker.py           → `taxonomy` CLI command
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SubcategoryInfo:
    """A single subcategory within a category."""
    id: str                           # e.g., "direct.instruction_override"
    description: str
    seeds: list[str]                  # optional paths relative to repo root
    arc_techniques: list[str]
    arc_evasions: list[str]
    strategies: list[str]
    requires: str | None = None       # capability gate (e.g., "has_vision")


@dataclass
class CategoryInfo:
    """A top-level attack category."""
    id: str                           # e.g., "prompt_injection"
    owasp: list[str]                  # e.g., ["LLM01"]
    difficulty: tuple[int, int]       # (min, max)
    benchmarks: list[str]
    description: str
    subcategories: dict[str, SubcategoryInfo]
    requires: str | None = None       # category-level capability gate


@dataclass
class StrategyMapping:
    """Reverse mapping from strategy ID to categories."""
    strategy_id: str
    categories: list[str]
    primary_category: str


@dataclass
class ArcEntry:
    """A single entry from the Arc PI taxonomy."""
    dimension: str     # inputs | techniques | evasions | intents | ...
    id: str
    title: str
    description: str
    ideas: list[str]


# ---------------------------------------------------------------------------
# Taxonomy loader
# ---------------------------------------------------------------------------

from . import ROOT as _ROOT

_TAXONOMY_PATH = _ROOT / "taxonomy" / "agentbreaker_taxonomy.yaml"
_ARC_TAXONOMY_PATH = _ROOT / "taxonomy" / "arc_pi_taxonomy.json"
_ENTERPRISE_TAXONOMY_PATH = _ROOT / "attack_seeds_enterprise" / "enterprise_taxonomy_extension.yaml"

_cached_taxonomy: dict | None = None
_cached_arc: dict | None = None


def _merge_taxonomy_extension(base: dict, ext: dict) -> dict:
    """Deep-merge enterprise taxonomy extension into the base taxonomy."""
    for cat_id, cat_data in (ext.get("categories") or {}).items():
        if cat_id not in base.setdefault("categories", {}):
            base["categories"][cat_id] = cat_data
        else:
            base_cat = base["categories"][cat_id]
            for sub_id, sub_data in (cat_data.get("subcategories") or {}).items():
                base_cat.setdefault("subcategories", {})[sub_id] = sub_data
    for strat_id, strat_data in (ext.get("strategy_index") or {}).items():
        base.setdefault("strategy_index", {})[strat_id] = strat_data
    return base


def _load_raw_taxonomy() -> dict:
    """Load and cache the raw agentbreaker_taxonomy.yaml, merging enterprise extension if licensed."""
    global _cached_taxonomy
    if _cached_taxonomy is None:
        with open(_TAXONOMY_PATH) as f:
            _cached_taxonomy = yaml.safe_load(f) or {}
        from .license import is_enterprise_licensed
        if is_enterprise_licensed() and _ENTERPRISE_TAXONOMY_PATH.exists():
            with open(_ENTERPRISE_TAXONOMY_PATH) as f:
                ext = yaml.safe_load(f) or {}
            _cached_taxonomy = _merge_taxonomy_extension(_cached_taxonomy, ext)
    return _cached_taxonomy


def _load_raw_arc() -> dict:
    """Load and cache the raw arc_pi_taxonomy.json."""
    global _cached_arc
    if _cached_arc is None:
        if _ARC_TAXONOMY_PATH.exists():
            with open(_ARC_TAXONOMY_PATH) as f:
                _cached_arc = json.load(f)
        else:
            _cached_arc = {}
    return _cached_arc


def load_taxonomy() -> dict[str, CategoryInfo]:
    """Load the full unified taxonomy as CategoryInfo objects."""
    raw = _load_raw_taxonomy()
    categories: dict[str, CategoryInfo] = {}

    for cat_id, cat_data in raw.get("categories", {}).items():
        owasp_raw = cat_data.get("owasp", [])
        owasp = owasp_raw if isinstance(owasp_raw, list) else [owasp_raw]

        subcategories: dict[str, SubcategoryInfo] = {}
        for sub_id, sub_data in (cat_data.get("subcategories") or {}).items():
            subcategories[sub_id] = SubcategoryInfo(
                id=sub_id,
                description=sub_data.get("description", ""),
                seeds=sub_data.get("seeds", []),
                arc_techniques=sub_data.get("arc_techniques", []),
                arc_evasions=sub_data.get("arc_evasions", []),
                strategies=sub_data.get("strategies", []),
                requires=sub_data.get("requires"),
            )

        difficulty = cat_data.get("difficulty", [1, 5])
        categories[cat_id] = CategoryInfo(
            id=cat_id,
            owasp=owasp,
            difficulty=(difficulty[0], difficulty[1]) if len(difficulty) >= 2 else (1, 5),
            benchmarks=cat_data.get("benchmarks", []),
            description=cat_data.get("description", ""),
            subcategories=subcategories,
            requires=cat_data.get("requires"),
        )

    return categories


def get_category(category_id: str) -> CategoryInfo | None:
    """Get full category info including subcategories, seeds, strategies."""
    return load_taxonomy().get(category_id)


def get_strategies_for_category(category_id: str) -> list[str]:
    """Map category → applicable strategy IDs (deduped, ordered)."""
    cat = get_category(category_id)
    if not cat:
        return []
    seen: set[str] = set()
    strategies: list[str] = []
    for sub in cat.subcategories.values():
        for s in sub.strategies:
            if s not in seen:
                seen.add(s)
                strategies.append(s)
    return strategies


def get_seeds_for_strategy(strategy_id: str) -> list[str]:
    """Map strategy → relevant seed file paths."""
    taxonomy = load_taxonomy()
    seed_paths: list[str] = []
    seen: set[str] = set()
    for cat in taxonomy.values():
        for sub in cat.subcategories.values():
            if strategy_id in sub.strategies:
                for seed in sub.seeds:
                    if seed not in seen:
                        seen.add(seed)
                        seed_paths.append(seed)
    return seed_paths


def applicable_categories(capabilities: dict) -> list[str]:
    """Filter categories by target capabilities (has_tools, has_vision, etc.)."""
    taxonomy = load_taxonomy()
    result: list[str] = []
    for cat_id, cat in taxonomy.items():
        if cat.requires and not capabilities.get(cat.requires):
            continue
        result.append(cat_id)
    return result


def applicable_subcategories(
    category_id: str, capabilities: dict
) -> list[SubcategoryInfo]:
    """Filter subcategories by target capabilities."""
    cat = get_category(category_id)
    if not cat:
        return []
    return [
        sub for sub in cat.subcategories.values()
        if not sub.requires or capabilities.get(sub.requires)
    ]


def owasp_for_category(category_id: str) -> str:
    """Quick OWASP tag lookup."""
    cat = get_category(category_id)
    if not cat:
        return ""
    return ", ".join(cat.owasp)


def benchmark_for_category(category_id: str) -> str:
    """Quick benchmark lookup."""
    cat = get_category(category_id)
    if not cat:
        return ""
    return ", ".join(cat.benchmarks)


# ---------------------------------------------------------------------------
# Strategy index
# ---------------------------------------------------------------------------

def load_strategy_index() -> dict[str, StrategyMapping]:
    """Load the strategy → category reverse index."""
    raw = _load_raw_taxonomy()
    index: dict[str, StrategyMapping] = {}
    for strat_id, strat_data in raw.get("strategy_index", {}).items():
        index[strat_id] = StrategyMapping(
            strategy_id=strat_id,
            categories=strat_data.get("categories", []),
            primary_category=strat_data.get("primary_category", ""),
        )
    return index


def strategy_primary_category(strategy_id: str) -> str:
    """Get the primary category for a strategy ID."""
    idx = load_strategy_index()
    mapping = idx.get(strategy_id)
    return mapping.primary_category if mapping else ""


# ---------------------------------------------------------------------------
# Arc PI taxonomy integration
# ---------------------------------------------------------------------------

def get_arc_entries(dimension: str | None = None) -> list[ArcEntry]:
    """Get Arc PI taxonomy entries, optionally filtered by dimension."""
    arc = _load_raw_arc()
    entries: list[ArcEntry] = []
    for dim_name, dim_entries in arc.get("dimensions", {}).items():
        if dimension and dim_name != dimension:
            continue
        if not isinstance(dim_entries, list):
            continue
        for entry in dim_entries:
            entries.append(ArcEntry(
                dimension=dim_name,
                id=entry.get("id", ""),
                title=entry.get("title", ""),
                description=entry.get("description", ""),
                ideas=entry.get("ideas", []),
            ))
    return entries


def get_arc_context(subcategory_id: str) -> list[ArcEntry]:
    """Get Arc PI taxonomy entries relevant to a subcategory's technique/evasion refs."""
    taxonomy = load_taxonomy()
    # Find the subcategory across all categories
    target_sub: SubcategoryInfo | None = None
    for cat in taxonomy.values():
        if subcategory_id in cat.subcategories:
            target_sub = cat.subcategories[subcategory_id]
            break
    if not target_sub:
        return []

    # Collect relevant Arc entries
    relevant: list[ArcEntry] = []
    all_refs = set(target_sub.arc_techniques + target_sub.arc_evasions)
    if not all_refs:
        return []

    for entry in get_arc_entries():
        if entry.id in all_refs:
            relevant.append(entry)
    return relevant


def search_taxonomy(query: str, *, dimension: str | None = None) -> list[dict]:
    """Search both AgentBreaker and Arc taxonomies by keyword."""
    query_lower = query.lower()
    results: list[dict] = []

    # Search AgentBreaker categories and subcategories
    taxonomy = load_taxonomy()
    for cat_id, cat in taxonomy.items():
        if query_lower in cat_id.lower() or query_lower in cat.description.lower():
            results.append({
                "type": "category",
                "id": cat_id,
                "description": cat.description,
                "owasp": cat.owasp,
            })
        for sub_id, sub in cat.subcategories.items():
            if query_lower in sub_id.lower() or query_lower in sub.description.lower():
                results.append({
                    "type": "subcategory",
                    "id": f"{cat_id}/{sub_id}",
                    "description": sub.description,
                    "category": cat_id,
                    "strategies": sub.strategies,
                })

    # Search Arc PI taxonomy
    for entry in get_arc_entries(dimension):
        searchable = f"{entry.id} {entry.title} {entry.description} {' '.join(entry.ideas)}".lower()
        if query_lower in searchable:
            results.append({
                "type": "arc_entry",
                "dimension": entry.dimension,
                "id": entry.id,
                "title": entry.title,
                "description": entry.description,
            })

    return results


# ---------------------------------------------------------------------------
# Campaign helpers
# ---------------------------------------------------------------------------

def next_underexplored_category(
    results: list[dict],
    capabilities: dict,
) -> str:
    """Suggest the least-explored applicable category based on past results."""
    applicable = applicable_categories(capabilities)
    if not applicable:
        return "prompt_injection"

    # Count experiments per category
    counts: dict[str, int] = {cat: 0 for cat in applicable}
    for row in results:
        cat = row.get("category", "")
        if cat in counts:
            counts[cat] += 1

    # Return the category with fewest experiments
    return min(counts, key=counts.get)  # type: ignore[arg-type]


def suggest_subcategory(
    category_id: str,
    results: list[dict],
    capabilities: dict,
) -> str | None:
    """Suggest the least-explored subcategory within a category."""
    subs = applicable_subcategories(category_id, capabilities)
    if not subs:
        return None

    # Count experiments per subcategory (approximate by technique match)
    techniques_tried: set[str] = set()
    for row in results:
        if row.get("category") == category_id:
            techniques_tried.add(row.get("technique", ""))

    for sub in subs:
        # Check if any strategy from this subcategory has been tried
        if not any(s in techniques_tried for s in sub.strategies):
            return sub.id

    # All tried — return the first one for re-exploration
    return subs[0].id if subs else None
