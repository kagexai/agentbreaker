"""Product state for the operator: engines, targets, findings, and the next step.

The campaign harness stays in campaign/attack/target. This module only reads
config, builtin providers, environment keys, finding files, and result ledgers.
It does not import the control plane.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from .. import ROOT
from ..plugins import match_provider

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FINDING_TIERS = ("success", "partial", "novel")


def build_workspace(
    *,
    config_path: Path | None = None,
    root: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return the operator workspace for one config and artifact root."""
    repo = Path(root) if root is not None else ROOT
    path = Path(config_path) if config_path is not None else repo / "target_config.yaml"
    env = environ if environ is not None else os.environ
    config, config_error = _load_config(path)
    targets = _target_rows(config)
    finding_index = _index_findings(repo / "findings")
    configured_ids = {row["target_id"] for row in targets}

    rows: list[dict[str, Any]] = []
    for target in targets:
        target_id = target["target_id"]
        findings = finding_index.get(target_id) or _empty_finding_bucket()
        attack_count = _attack_count(repo, target_id)
        success = findings["tiers"]["success"]
        partial = findings["tiers"]["partial"]
        novel = findings["tiers"]["novel"]
        if attack_count > 0:
            status = "tested"
        elif success or partial or novel:
            status = "findings"
        else:
            status = "configured"
        rows.append(
            {
                "target_id": target_id,
                "provider": target["provider"],
                "model": target["model"],
                "tags": target["tags"],
                "capabilities": target["capabilities"],
                "status": status,
                "tested": attack_count > 0,
                "attack_count": attack_count,
                "peak_composite": findings["peak_composite"],
                "findings": {"success": success, "partial": partial, "novel": novel},
                "top_categories": [name for name, _count in findings["categories"].most_common(4)],
                "top_owasp_refs": sorted(findings["owasp"]),
            }
        )

    orphans = [
        {"target_id": target_id, "findings": _tier_counts(bucket)}
        for target_id, bucket in sorted(finding_index.items())
        if target_id not in configured_ids
    ]
    judge = _engine_state(config, "judge", env)
    generator = _engine_state(config, "generator", env)
    planner = config.get("planner") if isinstance(config.get("planner"), dict) else {}
    counts = _counts(rows, finding_index, configured_ids)
    blocking = _blocking(config_error, judge, generator, rows)
    actions = _next_actions(blocking, judge, generator, rows, counts, orphans)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config_path": str(path),
        "config_error": config_error,
        "ready": not blocking,
        "blocking": blocking,
        "headline": _headline(blocking, counts),
        "next_actions": actions,
        "engines": {
            "judge": judge,
            "generator": generator,
            "planner": {"use_judge_config": bool(planner.get("use_judge_config", True))},
        },
        "counts": counts,
        "targets": rows,
        "frameworks": _frameworks(rows, finding_index),
        "orphans": orphans[:20],
    }


def _load_config(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.is_file():
        return {}, f"Config file is missing: {path.name}"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return {}, f"Config file could not be parsed: {exc}"
    if not isinstance(data, dict):
        return {}, "Config file must be a mapping."
    return data, None


def _target_rows(config: dict[str, Any]) -> list[dict[str, Any]]:
    raw = config.get("targets")
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        target_id = str(item.get("id") or "").strip()
        if not target_id:
            continue
        item_config = item.get("config") if isinstance(item.get("config"), dict) else {}
        capabilities = item.get("capabilities") if isinstance(item.get("capabilities"), dict) else {}
        tags = [str(tag) for tag in item.get("tags") or [] if str(tag)]
        model = str(item_config.get("model") or "").strip() or None
        rows.append(
            {
                "target_id": target_id,
                "provider": str(item.get("provider") or ""),
                "model": model,
                "tags": tags,
                "capabilities": {str(key): value for key, value in capabilities.items()},
            }
        )
    return rows


def _engine_state(config: dict[str, Any], role: str, environ: Mapping[str, str]) -> dict[str, Any]:
    block = config.get(role) if isinstance(config.get(role), dict) else {}
    cfg = block.get("config") if isinstance(block.get("config"), dict) else {}
    api = str(cfg.get("api") or "").strip()
    model = str(cfg.get("model") or "").strip()
    api_key_env = str(cfg.get("api_key_env") or "").strip() or None
    endpoint = cfg.get("endpoint")
    endpoint_text = str(endpoint).strip() if endpoint else None
    provider_id = match_provider(api, api_key_env, endpoint_text) if api else None
    key_required = bool(api_key_env)
    key_present = bool(api_key_env and str(environ.get(api_key_env, "")).strip())
    reasons: list[str] = []
    if not model:
        reasons.append(f"The {role} has no model.")
    if not api:
        reasons.append(f"The {role} has no provider API.")
    if key_required and not key_present:
        reasons.append(f"The {role} key {api_key_env} is unset.")
    return {
        "role": role,
        "provider_id": provider_id,
        "api": api,
        "model": model,
        "api_key_env": api_key_env,
        "endpoint": endpoint_text,
        "api_key_required": key_required,
        "api_key_present": key_present if key_required else True,
        "ready": not reasons,
        "reasons": reasons,
    }


def _empty_finding_bucket() -> dict[str, Any]:
    return {
        "tiers": {tier: 0 for tier in _FINDING_TIERS},
        "categories": Counter(),
        "owasp": set(),
        "peak_composite": 0.0,
    }


def _index_findings(findings_root: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    if not findings_root.is_dir():
        return index
    for tier in _FINDING_TIERS:
        directory = findings_root / tier
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.yaml"):
            bucket, target_id = _read_finding(path, tier)
            if bucket is None or not target_id:
                continue
            current = index.setdefault(target_id, _empty_finding_bucket())
            current["tiers"][tier] += 1
            current["categories"].update(bucket["categories"])
            current["owasp"].update(bucket["owasp"])
            current["peak_composite"] = max(current["peak_composite"], bucket["peak_composite"])
    return index


def _read_finding(path: Path, tier: str) -> tuple[dict[str, Any] | None, str]:
    del tier
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None, ""
    if not isinstance(data, dict):
        return None, ""
    target_id = str(data.get("target_id") or data.get("target") or "").strip()
    category = str(data.get("category") or "").strip()
    owasp = str(data.get("owasp_ref") or "").strip()
    scores = data.get("scores") if isinstance(data.get("scores"), dict) else {}
    try:
        composite = float(scores.get("composite") or 0.0)
    except (TypeError, ValueError):
        composite = 0.0
    bucket = _empty_finding_bucket()
    if category:
        bucket["categories"][category] += 1
    if owasp:
        bucket["owasp"].add(owasp)
    bucket["peak_composite"] = composite
    return bucket, target_id


def _attack_count(root: Path, target_id: str) -> int:
    if not _SAFE_ID.fullmatch(target_id):
        return 0
    artifacts = (root / "artifacts").resolve()
    base = (artifacts / target_id).resolve()
    try:
        base.relative_to(artifacts)
    except ValueError:
        return 0
    if not base.is_dir():
        return 0
    total = 0
    for path in base.rglob("results.tsv"):
        resolved = path.resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            continue
        total += _count_result_rows(resolved)
    return total


def _count_result_rows(path: Path) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    rows = 0
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        if index == 0 and line.startswith("attack_id\t"):
            continue
        rows += 1
    return rows


def _tier_counts(bucket: dict[str, Any]) -> dict[str, int]:
    tiers = bucket["tiers"]
    return {tier: int(tiers[tier]) for tier in _FINDING_TIERS}


def _counts(
    rows: list[dict[str, Any]],
    finding_index: dict[str, dict[str, Any]],
    configured_ids: set[str],
) -> dict[str, int]:
    success = partial = novel = 0
    for target_id, bucket in finding_index.items():
        if target_id not in configured_ids:
            continue
        success += bucket["tiers"]["success"]
        partial += bucket["tiers"]["partial"]
        novel += bucket["tiers"]["novel"]
    tested = sum(1 for row in rows if row["tested"])
    with_findings = sum(
        1
        for row in rows
        if row["findings"]["success"] or row["findings"]["partial"] or row["findings"]["novel"]
    )
    return {
        "configured": len(rows),
        "tested": tested,
        "with_findings": with_findings,
        "untested": len(rows) - tested,
        "success_findings": success,
        "partial_findings": partial,
        "novel_findings": novel,
        "attacks": sum(row["attack_count"] for row in rows),
    }


def _frameworks(
    rows: list[dict[str, Any]],
    finding_index: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    owasp: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    for row in rows:
        bucket = finding_index.get(row["target_id"])
        if bucket is None:
            continue
        for ref in bucket["owasp"]:
            owasp[ref] += 1
        categories.update(bucket["categories"])
    return {
        "owasp": [{"ref": ref, "target_count": count} for ref, count in owasp.most_common()],
        "categories": [{"id": name, "finding_count": count} for name, count in categories.most_common(8)],
    }


def _blocking(
    config_error: str | None,
    judge: dict[str, Any],
    generator: dict[str, Any],
    rows: list[dict[str, Any]],
) -> list[str]:
    blocking: list[str] = []
    if config_error:
        blocking.append(config_error)
    blocking.extend(judge["reasons"])
    blocking.extend(generator["reasons"])
    if not rows and not config_error:
        blocking.append("No targets are configured.")
    return blocking


def _headline(blocking: list[str], counts: dict[str, int]) -> str:
    if blocking:
        return blocking[0]
    tested = counts["tested"]
    configured = counts["configured"]
    findings = counts["success_findings"]
    if findings and counts["attacks"] == 0:
        return (
            f"{configured} systems are configured and {findings} confirmed findings are saved. "
            "Campaign result files are not on disk yet."
        )
    return f"{configured} systems are configured. {tested} have campaign results."


def _next_actions(
    blocking: list[str],
    judge: dict[str, Any],
    generator: dict[str, Any],
    rows: list[dict[str, Any]],
    counts: dict[str, int],
    orphans: list[dict[str, Any]],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    if not judge["ready"]:
        actions.append(
            {
                "id": "judge",
                "title": "Configure the judge",
                "detail": " ".join(judge["reasons"]) or "The judge is not ready.",
                "href": "/ops",
            }
        )
    if not generator["ready"]:
        actions.append(
            {
                "id": "generator",
                "title": "Configure the generator",
                "detail": " ".join(generator["reasons"]) or "The generator is not ready.",
                "href": "/ops",
            }
        )
    if not rows and not any("Config file" in item or "parsed" in item or "mapping" in item for item in blocking):
        actions.append(
            {
                "id": "add-target",
                "title": "Add a target",
                "detail": "Register a system in Operations before launching a scan.",
                "href": "/ops",
            }
        )
    if counts["success_findings"] and counts["attacks"] == 0:
        actions.append(
            {
                "id": "findings",
                "title": "Review saved findings",
                "detail": (
                    f"{counts['success_findings']} confirmed findings are saved. "
                    "Attack totals stay at zero until a scan writes results.tsv."
                ),
                "href": "/regressions",
            }
        )
    if orphans:
        actions.append(
            {
                "id": "orphans",
                "title": "Findings name unknown targets",
                "detail": f"{len(orphans)} target ids appear in findings and are absent from the config.",
                "href": "/regressions",
            }
        )
    if not blocking:
        actions.append(
            {
                "id": "scan",
                "title": "Open Operations",
                "detail": "Engines and targets are ready. Launch an authorized scan from Operations.",
                "href": "/ops",
            }
        )
    elif not actions:
        actions.append(
            {
                "id": "fix-config",
                "title": "Fix the config",
                "detail": blocking[0],
                "href": "/ops",
            }
        )
    return actions
