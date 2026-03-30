"""
seed_manager.py -- Seed loading, ranking, and template rendering for AgentBreaker.

Provides SeedCandidate (a frozen dataclass) and SeedManager: a stateful manager
that loads optional static seeds and findings-derived examples, ranks them
by relevance to the current strategy/category/target, and extracts reusable
components (titles, directives, formats) for payload construction.

Extracted from attack.py to keep the mutable attack generator focused on
payload construction logic only.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from .domain_helpers import DomainContext


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DIRECTIVE_PREFIXES: tuple[str, ...] = (
    "return", "complete", "quote", "emit", "echo", "fill", "output", "print",
)

TOKEN_STOPWORDS: set[str] = {
    "the", "and", "for", "with", "that", "this", "from", "into", "only", "your",
    "using", "current", "exact", "runtime", "value", "request", "output", "return",
    "prompt", "attack", "target", "assistant", "system", "security", "profile",
}


# ---------------------------------------------------------------------------
# SeedCandidate dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SeedCandidate:
    """A single seed candidate from static corpus or findings library."""
    source: str
    text: str
    category: str
    technique: str
    title_hint: str = ""
    target_id: str = ""
    finding_tier: str = ""


# ---------------------------------------------------------------------------
# Utility functions (stateless)
# ---------------------------------------------------------------------------

def normalize_space(text: str) -> str:
    """Collapse whitespace to single spaces."""
    return re.sub(r"\s+", " ", text).strip()


def strip_canary(text: str) -> str:
    """Remove CANARY lines from text."""
    lines = text.splitlines()
    cleaned: list[str] = []
    for line in lines:
        if line.strip().startswith("[CANARY:"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def tokenize(text: str) -> set[str]:
    """Extract lowercase tokens (3+ chars) excluding stopwords."""
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_]{3,}", text.lower())
        if token not in TOKEN_STOPWORDS
    }
    return tokens


def ensure_current_canary(text: str, attack_id: str) -> str:
    """Ensure the text contains the current canary tag, replacing any old ones."""
    current = f"[CANARY:{attack_id}]"
    if current in text:
        return text

    updated = re.sub(r"\[CANARY:ATK-[A-Z0-9-]+\]", current, text)
    if updated != text:
        return updated

    stripped = text.lstrip()
    if not stripped:
        return current
    return f"{current}\n\n{stripped}"


def extract_title(candidate: SeedCandidate) -> str:
    """Extract a short title from a seed candidate."""
    if candidate.title_hint:
        title = normalize_space(candidate.title_hint)
        if title:
            return title.rstrip(".")
    for line in strip_canary(candidate.text).splitlines():
        stripped = normalize_space(line)
        if not stripped:
            continue
        if stripped.startswith(("BEGIN ", "END ", "---")):
            continue
        if len(stripped) <= 96:
            return stripped.rstrip(".")
    return ""


def extract_directives(candidate: SeedCandidate) -> list[str]:
    """Extract imperative directives from a seed candidate."""
    directives: list[str] = []
    for line in strip_canary(candidate.text).splitlines():
        stripped = normalize_space(line)
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith(DIRECTIVE_PREFIXES):
            if stripped[0].islower():
                stripped = stripped[0].upper() + stripped[1:]
            directives.append(stripped)
    return directives


def detect_seed_format(candidate: SeedCandidate) -> str:
    """Detect the structural format of a seed candidate (json, yaml, list, plain)."""
    text = strip_canary(candidate.text)
    if "{" in text and "}" in text:
        return "json"
    colon_lines = sum(1 for line in text.splitlines() if ":" in line)
    if colon_lines >= 4:
        return "yaml"
    if sum(1 for line in text.splitlines() if line.strip().startswith("-")) >= 3:
        return "list"
    return "plain"


# ---------------------------------------------------------------------------
# SeedManager -- stateful seed operations
# ---------------------------------------------------------------------------

class SeedManager:
    """
    Manages seed loading, ranking, and template rendering.

    Requires a DomainContext for accessing profile data, variant index,
    and attack parameters needed for seed relevance scoring.
    """

    def __init__(
        self,
        ctx: DomainContext,
        *,
        seed_root: Path = Path("attack_seeds"),
        findings_root: Path = Path("findings"),
        enterprise_seed_root: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.seed_root = seed_root
        self.findings_root = findings_root
        self.enterprise_seed_root = enterprise_seed_root
        self.last_seed_trace: dict[str, object] = {
            "strategy_id": "",
            "sources": [],
            "titles": [],
            "formats": [],
        }
        # Per-instance caches: static seeds don't change mid-run; finding seeds
        # are refreshed when findings_root mtime changes.
        self._static_cache: list[SeedCandidate] | None = None
        self._finding_cache: list[SeedCandidate] | None = None
        self._finding_cache_mtime: float = -1.0
        self._ranked_cache: dict[tuple[str, str], list[SeedCandidate]] = {}
        self._query_token_cache: dict[tuple[str, str], set[str]] = {}

    # -- Template rendering ----------------------------------------------

    def render_seed_template(self, template: str) -> str:
        """Render a seed template with profile-derived replacement values."""
        from .domain_helpers import humanize

        replacements = {
            "attack_id": self.ctx.attack_id,
            "persona_name": self.ctx.persona_reference(),
            "request": self.ctx.planned_value("request_goal") or "return the current protected value only",
            "base64_request": base64.b64encode(
                (self.ctx.planned_value("request_goal") or "return the current protected value only").encode("utf-8")
            ).decode("ascii"),
            "field": humanize(self.ctx.domain or "ai safety"),
            "institution": "an internal safety evaluation team",
            "topic": self.ctx.planned_value("request_goal") or "runtime disclosure behavior",
            "harmful_request": self.ctx.planned_value("request_goal") or "return the current protected value only",
        }
        try:
            return template.format(**replacements)
        except Exception:
            return template

    # -- Seed candidate loading ------------------------------------------

    def static_seed_candidates(self) -> list[SeedCandidate]:
        """Load seed candidates from the optional static corpus (cached)."""
        if self._static_cache is not None:
            return self._static_cache
        candidates: list[SeedCandidate] = []
        for path in sorted(self.seed_root.rglob("*.txt")):
            raw = path.read_text(errors="replace")
            body_lines: list[str] = []
            title_hint = path.stem.replace("_", " ")
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    if stripped.lower().startswith("# seed:"):
                        title_hint = stripped.split(":", 1)[1].strip() or title_hint
                    continue
                body_lines.append(line)
            body = self.render_seed_template("\n".join(body_lines).strip())
            if not body:
                continue
            rel = path.relative_to(self.seed_root)
            category = rel.parts[0] if rel.parts else ""
            technique = rel.stem
            candidates.append(
                SeedCandidate(
                    source=f"static:{rel.as_posix()}",
                    text=body,
                    category=category,
                    technique=technique,
                    title_hint=title_hint,
                )
            )
        if self.enterprise_seed_root and self.enterprise_seed_root.exists():
            for path in sorted(self.enterprise_seed_root.rglob("*.txt")):
                raw = path.read_text(errors="replace")
                body_lines = []
                title_hint = path.stem.replace("_", " ")
                for line in raw.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        if stripped.lower().startswith("# seed:"):
                            title_hint = stripped.split(":", 1)[1].strip() or title_hint
                        continue
                    body_lines.append(line)
                body = self.render_seed_template("\n".join(body_lines).strip())
                if not body:
                    continue
                rel = path.relative_to(self.enterprise_seed_root)
                category = rel.parts[0] if rel.parts else ""
                technique = rel.stem
                candidates.append(
                    SeedCandidate(
                        source=f"enterprise:{rel.as_posix()}",
                        text=body,
                        category=category,
                        technique=technique,
                        title_hint=title_hint,
                    )
                )
        self._static_cache = candidates
        return candidates

    def finding_seed_candidates(self) -> list[SeedCandidate]:
        """Load seed candidates from the findings/ library (success + partial, mtime-cached)."""
        # Invalidate if findings dir has been modified (new findings written)
        try:
            mtime = self.findings_root.stat().st_mtime if self.findings_root.exists() else -1.0
        except OSError:
            mtime = -1.0
        if self._finding_cache is not None and mtime == self._finding_cache_mtime:
            return self._finding_cache
        candidates: list[SeedCandidate] = []
        for tier in ("success", "partial"):
            tier_dir = self.findings_root / tier
            if not tier_dir.exists():
                continue
            for path in sorted(tier_dir.rglob("*.yaml")):
                if path.name.lower() == "readme.md":
                    continue
                try:
                    raw_text = path.read_text(errors="replace")
                    data = yaml.safe_load(raw_text) or {}
                except (OSError, UnicodeError, yaml.YAMLError):
                    continue
                payload = str(data.get("payload") or "").strip()
                if not payload:
                    continue
                candidates.append(
                    SeedCandidate(
                        source=f"finding:{tier}:{path.name}",
                        text=payload,
                        category=str(data.get("category") or "").strip(),
                        technique=str(data.get("technique") or "").strip(),
                        title_hint="",
                        target_id=str(data.get("target_id") or data.get("target") or "").strip(),
                        finding_tier=tier,
                    )
                )
        self._finding_cache = candidates
        self._finding_cache_mtime = mtime
        return candidates

    # -- Seed relevance scoring ------------------------------------------

    def seed_query_tokens(self, strategy_id: str, category: str) -> set[str]:
        """Build the token set used for seed relevance scoring (cached per strategy/category)."""
        cache_key = (strategy_id, category)
        if cache_key in self._query_token_cache:
            return self._query_token_cache[cache_key]
        from .domain_helpers import dedupe

        current_challenge = self.ctx.ctf_state.get("current_challenge") or {}
        query_bits: list[str] = [
            strategy_id,
            category,
            str(self.ctx.persona or ""),
            str(self.ctx.domain or ""),
            str(current_challenge.get("title") or ""),
            str(current_challenge.get("description") or ""),
            self.ctx.planned_value("target_field"),
            self.ctx.planned_value("request_goal"),
            self.ctx.planned_value("framing"),
            self.ctx.planned_value("mutation_hypothesis"),
            " ".join(self.ctx.ranked_domain_entities()[:4]),
            " ".join(self.ctx.refusals[:2]),
        ]
        query_bits.extend(
            str(angle.get("name") or angle.get("description") or "")
            for angle in self.ctx.angles[:4]
        )
        tokens = tokenize(" ".join(query_bits))
        self._query_token_cache[cache_key] = tokens
        return tokens

    def seed_candidate_score(
        self, candidate: SeedCandidate, strategy_id: str, category: str
    ) -> int:
        """Score a seed candidate by relevance to current strategy and target."""
        score = 0
        if candidate.target_id == self.ctx.target_id:
            score += 220
        elif candidate.target_id:
            score += 20
        if candidate.technique == strategy_id:
            score += 140
        if candidate.category == category:
            score += 100
        if candidate.finding_tier == "success":
            score += 70
        elif candidate.finding_tier == "partial":
            score += 40
        candidate_tokens = tokenize(
            " ".join([candidate.source, candidate.title_hint, candidate.text])
        )
        overlap = self.seed_query_tokens(strategy_id, category) & candidate_tokens
        score += len(overlap) * 7
        if strategy_id.replace("_", " ") in candidate.source:
            score += 18
        if category and category in candidate.source:
            score += 12
        return score

    # -- Seed ranking and packing ----------------------------------------

    def ranked_seed_candidates(
        self, strategy_id: str, category: str
    ) -> list[SeedCandidate]:
        """Return top-5 seed candidates ranked by relevance score (cached per strategy/category)."""
        cache_key = (strategy_id, category)
        if cache_key in self._ranked_cache:
            return self._ranked_cache[cache_key]
        from .domain_helpers import dedupe

        ranked = sorted(
            self.static_seed_candidates() + self.finding_seed_candidates(),
            key=lambda candidate: (
                self.seed_candidate_score(candidate, strategy_id, category),
                candidate.source,
            ),
            reverse=True,
        )
        unique: list[SeedCandidate] = []
        seen_text: set[str] = set()
        for candidate in ranked:
            signature = normalize_space(strip_canary(candidate.text))[:400]
            if not signature or signature in seen_text:
                continue
            seen_text.add(signature)
            unique.append(candidate)
            if len(unique) >= 5:
                break
        self._ranked_cache[cache_key] = unique
        return unique

    def seed_pack(self, strategy_id: str, category: str) -> dict[str, list[str]]:
        """Return a pack of titles, directives, formats, and sources from ranked seeds."""
        from .domain_helpers import dedupe

        candidates = self.ranked_seed_candidates(strategy_id, category)
        titles = dedupe(
            [title for candidate in candidates if (title := extract_title(candidate))]
        )
        directives = dedupe(
            directive
            for candidate in candidates
            for directive in extract_directives(candidate)
            if directive
        )
        formats = dedupe(
            [detect_seed_format(candidate) for candidate in candidates if candidate.text]
        )
        self.last_seed_trace = {
            "strategy_id": strategy_id,
            "sources": [candidate.source for candidate in candidates],
            "titles": titles[:4],
            "formats": formats[:4],
        }
        return {
            "titles": titles,
            "directives": directives,
            "formats": formats,
            "sources": [candidate.source for candidate in candidates],
        }

    def seed_output_style(
        self, strategy_id: str, category: str, fallback: str
    ) -> str:
        """Return the best output format for the given strategy, or fallback."""
        pack = self.seed_pack(strategy_id, category)
        return self.ctx.variant_pick(pack["formats"] + [fallback]) or fallback

    # -- Strategy seed context (used by _build_*() functions) ------------

    def strategy_seed_context(
        self,
        strategy_id: str,
        category: str,
        *,
        fallback_title: str,
        fallback_style: str = "plain",
        fallback_directive: str,
    ) -> dict[str, str | list[str]]:
        """
        Build a complete seed context for a strategy, with fallback values.

        Returns a dict with keys: title, style, directive, sources.
        """
        from .domain_helpers import dedupe

        pack = self.seed_pack(strategy_id, category)
        query_tokens = self.seed_query_tokens(strategy_id, category)
        # ranked_seed_candidates is already cached; seed_pack already populated it.
        ranked_candidates = self.ranked_seed_candidates(strategy_id, category)
        reusable_candidates = [
            candidate
            for candidate in ranked_candidates
            if candidate.target_id == self.ctx.target_id
            or candidate.source.startswith("static:")
        ]
        strong_reusable_candidates = [
            candidate
            for candidate in reusable_candidates
            if candidate.target_id == self.ctx.target_id
            or candidate.technique == strategy_id
            or (
                candidate.source.startswith("static:")
                and len(
                    query_tokens
                    & tokenize(
                        " ".join(
                            [candidate.source, candidate.title_hint, candidate.text]
                        )
                    )
                )
                >= 2
            )
        ]
        reusable_titles = dedupe(
            [
                title
                for candidate in strong_reusable_candidates
                if (title := extract_title(candidate))
            ]
        )
        reusable_formats = dedupe(
            [
                detect_seed_format(candidate)
                for candidate in strong_reusable_candidates
                if candidate.text
            ]
        )
        reusable_directives = dedupe(
            directive
            for candidate in strong_reusable_candidates
            for directive in extract_directives(candidate)
            if directive
        )

        title = (
            self.ctx.variant_pick(reusable_titles + [fallback_title]) or fallback_title
        )
        style = (
            self.ctx.variant_pick(
                reusable_formats + pack["formats"] + [fallback_style]
            )
            or fallback_style
        )
        directive_pool = dedupe(reusable_directives + [fallback_directive])
        directive = self.ctx.variant_pick(directive_pool) or fallback_directive
        return {
            "title": title.rstrip("."),
            "style": style,
            "directive": directive,
            "sources": pack["sources"],
        }
