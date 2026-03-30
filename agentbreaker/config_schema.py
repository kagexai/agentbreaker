"""
config_schema.py -- Validation and generation helpers for target_config.yaml.

Used by:
  - `agentbreaker.py validate`       → validate_config()
  - `agentbreaker.py add-target`     → detect_platform(), detect_model_family(),
                                        generate_target_entry()
  - `agentbreaker.py remove-target`  → remove_target()

All functions work with plain dicts (parsed YAML). No side effects.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .llm_error_utils import api_key_mismatch_warning


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@dataclass
class ConfigError:
    """A single validation error with severity and context."""
    level: str       # "error" | "warning"
    target_id: str   # "" for global errors
    message: str

    def __str__(self) -> str:
        prefix = f"[{self.target_id}] " if self.target_id else ""
        return f"{self.level.upper()}: {prefix}{self.message}"


REQUIRED_TARGET_FIELDS = {"id", "provider", "authorization"}
REQUIRED_AUTH_FIELDS = {"authorized_by", "scope"}
VALID_PROVIDERS = {"llm", "http", "script", "browser"}
CAPABILITY_BOOLEANS = {
    "has_tools", "has_rag", "has_multi_turn", "has_vision",
    "has_audio", "has_document",
}

_REPLACE_PATTERN = re.compile(r"REPLACE:", re.IGNORECASE)


def _is_placeholder(value: Any) -> bool:
    """Check if a value is an unfilled REPLACE: placeholder."""
    if not isinstance(value, str):
        return False
    return bool(_REPLACE_PATTERN.search(value))


def validate_target(target: dict, *, check_env: bool = False) -> list[ConfigError]:
    """Validate a single target entry and return all errors/warnings."""
    errors: list[ConfigError] = []
    tid = str(target.get("id") or "<missing-id>")

    # Required fields
    for fld in REQUIRED_TARGET_FIELDS:
        if fld not in target:
            errors.append(ConfigError("error", tid, f"Missing required field: {fld}"))

    # Provider type
    provider = target.get("provider", "")
    if provider and provider not in VALID_PROVIDERS:
        errors.append(ConfigError("error", tid, f"Invalid provider '{provider}'. Must be one of: {', '.join(sorted(VALID_PROVIDERS))}"))

    # Authorization
    auth = target.get("authorization")
    if isinstance(auth, dict):
        for fld in REQUIRED_AUTH_FIELDS:
            val = auth.get(fld, "")
            if not val:
                errors.append(ConfigError("error", tid, f"Missing authorization.{fld}"))
            elif _is_placeholder(val) and not target.get("template"):
                errors.append(ConfigError("warning", tid, f"authorization.{fld} still has REPLACE: placeholder"))
    elif auth is not None:
        errors.append(ConfigError("error", tid, "authorization must be a mapping"))

    # Config section per provider
    config = target.get("config") or {}
    if provider == "llm":
        if not config.get("model"):
            errors.append(ConfigError("error", tid, "LLM target missing config.model"))
        if not config.get("api"):
            errors.append(ConfigError("error", tid, "LLM target missing config.api"))
        api_key_env = config.get("api_key_env")
        if check_env and api_key_env and api_key_env != "null":
            api_key = os.environ.get(api_key_env)
            if not api_key:
                errors.append(ConfigError("warning", tid, f"API key env var {api_key_env} is not set"))
            else:
                mismatch = api_key_mismatch_warning(
                    api=config.get("api", "openai"),
                    endpoint=config.get("endpoint"),
                    api_key_env=api_key_env,
                    api_key=api_key,
                    role=f"LLM target '{tid}'",
                )
                if mismatch:
                    errors.append(ConfigError("warning", tid, mismatch))
    elif provider == "http":
        if not config.get("url"):
            errors.append(ConfigError("error", tid, "HTTP target missing config.url"))
        if _is_placeholder(config.get("url", "")):
            errors.append(ConfigError("warning", tid, "config.url still has REPLACE: placeholder"))
    elif provider == "script":
        script = config.get("script")
        if not script:
            errors.append(ConfigError("error", tid, "Script target missing config.script"))
        elif not Path(script).exists() and not target.get("template"):
            errors.append(ConfigError("warning", tid, f"Script file not found: {script}"))
    elif provider == "browser":
        script = config.get("script")
        if not script:
            errors.append(ConfigError("error", tid, "Browser target missing config.script"))

    # Capabilities
    caps = target.get("capabilities") or {}
    for key, val in caps.items():
        if key in CAPABILITY_BOOLEANS and not isinstance(val, bool):
            errors.append(ConfigError("warning", tid, f"capabilities.{key} should be a boolean, got {type(val).__name__}"))

    return errors


def validate_config(config: dict, *, check_env: bool = False) -> list[ConfigError]:
    """Validate the full target_config.yaml structure and return all errors."""
    errors: list[ConfigError] = []

    # Judge config
    judge = config.get("judge")
    if not judge:
        errors.append(ConfigError("error", "", "Missing 'judge' configuration"))
    else:
        if not isinstance(judge, dict):
            errors.append(ConfigError("error", "", "'judge' must be a mapping"))
        else:
            judge_config = judge.get("config") or {}
            if not judge_config.get("model"):
                errors.append(ConfigError("error", "", "Judge missing config.model"))
            if not judge_config.get("api"):
                errors.append(ConfigError("error", "", "Judge missing config.api"))
            api_key_env = judge_config.get("api_key_env")
            if check_env and api_key_env:
                api_key = os.environ.get(api_key_env)
                if not api_key:
                    errors.append(ConfigError("warning", "", f"Judge API key env var {api_key_env} is not set"))
                else:
                    mismatch = api_key_mismatch_warning(
                        api=judge_config.get("api", "openai"),
                        endpoint=judge_config.get("endpoint"),
                        api_key_env=api_key_env,
                        api_key=api_key,
                        role="Judge",
                    )
                    if mismatch:
                        errors.append(ConfigError("warning", "", mismatch))

    generator = config.get("generator")
    if isinstance(generator, dict):
        generator_config = generator.get("config") or {}
        api_key_env = generator_config.get("api_key_env")
        if check_env and api_key_env:
            api_key = os.environ.get(api_key_env)
            if not api_key:
                errors.append(ConfigError("warning", "", f"Generator API key env var {api_key_env} is not set"))
            else:
                mismatch = api_key_mismatch_warning(
                    api=generator_config.get("api", "openai"),
                    endpoint=generator_config.get("endpoint"),
                    api_key_env=api_key_env,
                    api_key=api_key,
                    role="Generator",
                )
                if mismatch:
                    errors.append(ConfigError("warning", "", mismatch))

    # Targets list
    targets = config.get("targets")
    if not isinstance(targets, list):
        errors.append(ConfigError("error", "", "'targets' must be a list"))
        return errors

    # Duplicate ID check
    ids_seen: dict[str, int] = {}
    for idx, target in enumerate(targets):
        if not isinstance(target, dict):
            errors.append(ConfigError("error", "", f"targets[{idx}] is not a mapping"))
            continue
        tid = target.get("id", "")
        if tid in ids_seen:
            errors.append(ConfigError("error", tid, f"Duplicate target ID (also at index {ids_seen[tid]})"))
        ids_seen[tid] = idx

        errors.extend(validate_target(target, check_env=check_env))

    return errors


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def load_platforms(platforms_path: Path = Path("platforms.yaml")) -> dict:
    """Load the platforms.yaml registry."""
    if not platforms_path.exists():
        return {"platforms": [], "model_families": []}
    with open(platforms_path) as f:
        return yaml.safe_load(f) or {"platforms": [], "model_families": []}


@dataclass
class PlatformMatch:
    """Result of matching a URL against the platform registry."""
    name: str
    platform: dict          # the full platform entry from platforms.yaml
    url_fields: dict        # extracted fields (e.g., {"level": "3"})


def detect_platform(url: str, *, platforms_path: Path = Path("platforms.yaml")) -> PlatformMatch | None:
    """Match a URL against the platforms.yaml registry."""
    registry = load_platforms(platforms_path)
    for platform in registry.get("platforms", []):
        for pattern in platform.get("url_patterns", []):
            if pattern in url:
                # Extract fields from URL
                url_fields: dict[str, str] = {}
                for field_name, regex in (platform.get("url_parser") or {}).items():
                    match = re.search(regex, url)
                    if match:
                        url_fields[field_name] = match.group(1)
                return PlatformMatch(
                    name=platform["name"],
                    platform=platform,
                    url_fields=url_fields,
                )
    return None


@dataclass
class ModelFamilyMatch:
    """Result of matching a model name against the model families registry."""
    api: str                 # openai | anthropic | openai-compatible
    api_key_env: str | None  # env var name for the API key
    endpoint: str | None     # custom endpoint, or None for default


def detect_model_family(
    model: str, *, platforms_path: Path = Path("platforms.yaml")
) -> ModelFamilyMatch | None:
    """Match a model name against the model families in platforms.yaml."""
    registry = load_platforms(platforms_path)
    for family in registry.get("model_families", []):
        pattern = family.get("pattern", "")
        if re.search(pattern, model, re.IGNORECASE):
            return ModelFamilyMatch(
                api=family["api"],
                api_key_env=family.get("api_key_env"),
                endpoint=family.get("endpoint"),
            )
    return None


# ---------------------------------------------------------------------------
# Target entry generation
# ---------------------------------------------------------------------------

def generate_target_entry(
    *,
    target_id: str,
    provider: str,
    authorized_by: str,
    scope: str,
    config: dict,
    capabilities: dict | None = None,
    rate_limit: dict | None = None,
    tags: list[str] | None = None,
    date: str | None = None,
) -> dict:
    """Generate a target entry dict suitable for appending to target_config.yaml."""
    import time

    entry: dict[str, Any] = {
        "id": target_id,
        "provider": provider,
        "authorization": {
            "authorized_by": authorized_by,
            "date": date or time.strftime("%Y-%m-%d"),
            "scope": scope,
        },
        "config": config,
    }
    if rate_limit:
        entry["rate_limit"] = rate_limit
    if capabilities:
        entry["capabilities"] = capabilities
    if tags:
        entry["tags"] = tags
    return entry


def generate_platform_target(
    match: PlatformMatch,
    *,
    user_inputs: dict[str, str],
    date: str | None = None,
) -> dict:
    """Generate a target entry from a platform match and user inputs."""
    import time

    platform = match.platform
    url_fields = match.url_fields

    # Merge url_fields and user_inputs for template rendering
    all_fields = {**url_fields, **user_inputs}

    # Build target ID from template
    id_template = platform.get("id_template", platform["name"].lower().replace(" ", "-"))
    try:
        target_id = id_template.format(**all_fields)
    except KeyError:
        target_id = id_template

    # Build env vars
    env_vars: dict[str, str] = dict(platform.get("env_defaults", {}))
    for prompt in platform.get("prompts", []):
        env_key = prompt.get("env", "")
        value = user_inputs.get(prompt["key"], "")
        if env_key and value:
            env_vars[env_key] = value

    # Add URL-extracted fields as env vars
    url_parser = platform.get("url_parser", {})
    for field_name, _ in url_parser.items():
        env_key = f"{platform['name'].upper().replace(' ', '_')}_{field_name.upper()}"
        if field_name in url_fields:
            env_vars[env_key] = url_fields[field_name]

    # Build capabilities with level overrides
    capabilities = dict(platform.get("capabilities", {}))
    level = url_fields.get("level")
    if level:
        overrides = (platform.get("level_overrides") or {}).get(int(level), {})
        capabilities.update(overrides)

    # Build authorization
    auth_config = platform.get("authorization", {})
    scope_template = auth_config.get("scope_template", f"{platform['name']} target")
    try:
        scope = scope_template.format(**all_fields)
    except KeyError:
        scope = scope_template

    config: dict[str, Any] = {
        "script": platform["script"],
        "timeout_seconds": 45,
        "env": env_vars,
    }

    return generate_target_entry(
        target_id=target_id,
        provider=platform["provider"],
        authorized_by=auth_config.get("authorized_by", ""),
        scope=scope,
        config=config,
        capabilities=capabilities if capabilities else None,
        rate_limit=platform.get("rate_limit"),
        tags=platform.get("tags"),
        date=date,
    )


def generate_llm_target(
    *,
    model: str,
    family: ModelFamilyMatch,
    system_prompt: str = "",
    authorized_by: str,
    scope: str,
    target_id: str | None = None,
    date: str | None = None,
) -> dict:
    """Generate a target entry for an LLM provider from a model family match."""
    tid = target_id or re.sub(r"[^a-z0-9-]", "-", model.lower()).strip("-")

    config: dict[str, Any] = {
        "api": family.api,
        "model": model,
    }
    if family.api_key_env:
        config["api_key_env"] = family.api_key_env
    if family.endpoint:
        config["endpoint"] = family.endpoint
    if system_prompt:
        config["system_prompt"] = system_prompt
    config["max_tokens"] = 1024

    capabilities: dict[str, Any] = {
        "has_multi_turn": True,
        "max_turns": 10,
    }
    # Auto-detect vision support for known model families
    model_lower = model.lower()
    if any(v in model_lower for v in ("gpt-4o", "gpt-4-turbo", "claude-3", "claude-sonnet", "claude-opus", "gemini")):
        capabilities["has_vision"] = True
    if any(v in model_lower for v in ("claude",)):
        capabilities["has_document"] = True

    return generate_target_entry(
        target_id=tid,
        provider="llm",
        authorized_by=authorized_by,
        scope=scope,
        config=config,
        capabilities=capabilities,
        rate_limit={"requests_per_minute": 60},
        tags=["llm", family.api],
        date=date,
    )


# ---------------------------------------------------------------------------
# Config file operations
# ---------------------------------------------------------------------------

def append_target_to_config(
    target_entry: dict,
    config_path: Path = Path("target_config.yaml"),
) -> None:
    """Append a target entry to the targets list in target_config.yaml."""
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    targets = config.get("targets", [])
    if not isinstance(targets, list):
        targets = []

    # Check for duplicate ID
    existing_ids = {t.get("id") for t in targets if isinstance(t, dict)}
    if target_entry.get("id") in existing_ids:
        raise ValueError(f"Target ID '{target_entry['id']}' already exists in {config_path}")

    targets.append(target_entry)
    config["targets"] = targets

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def remove_target_from_config(
    target_id: str,
    config_path: Path = Path("target_config.yaml"),
) -> bool:
    """Remove a target entry from target_config.yaml. Returns True if found and removed."""
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    targets = config.get("targets", [])
    if not isinstance(targets, list):
        return False

    original_len = len(targets)
    config["targets"] = [t for t in targets if not (isinstance(t, dict) and t.get("id") == target_id)]

    if len(config["targets"]) == original_len:
        return False

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return True


def active_targets(config: dict) -> list[dict]:
    """Return targets that are not templates and don't have REPLACE: in authorization."""
    targets = config.get("targets", [])
    if not isinstance(targets, list):
        return []
    active: list[dict] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        if target.get("template"):
            continue
        auth = target.get("authorization") or {}
        if isinstance(auth, dict):
            if _is_placeholder(auth.get("authorized_by", "")):
                continue
        active.append(target)
    return active
