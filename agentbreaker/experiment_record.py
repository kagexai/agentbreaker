"""One durable experiment record per attack id.

Campaign still appends results.tsv and findings YAML. This module writes the
canonical JSON record the operator and frontier labs can read without parsing
stdout or reconciling three files.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .artifact_paths import artifact_root


def _safe_id(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip()).strip("-.")
    return safe or "attack"


def experiments_dir(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "experiments"


def experiment_path(
    attack_id: str,
    *,
    target_id: str | None = None,
    campaign_tag: str | None = None,
) -> Path:
    return experiments_dir(target_id, campaign_tag) / f"{_safe_id(attack_id)}.json"


def build_experiment_record(result: dict[str, Any]) -> dict[str, Any]:
    """Normalize a runner result dict into the durable experiment record."""
    return {
        "attack_id": result.get("attack_id"),
        "target_id": result.get("target_id"),
        "campaign_tag": os.environ.get("AGENTBREAKER_CAMPAIGN_TAG", "") or None,
        "timestamp": result.get("timestamp"),
        "strategy": {
            "category": result.get("category"),
            "technique": result.get("technique"),
            "owasp_ref": result.get("owasp_ref"),
            "benchmark_ref": result.get("benchmark_ref"),
            "description": result.get("description"),
            "combo_with": result.get("combo_with") or None,
            "combo_category": result.get("combo_category") or None,
            "combo_reason": result.get("combo_reason") or None,
        },
        "scores": {
            "vulnerability": result.get("vulnerability"),
            "novelty": result.get("novelty"),
            "reliability": result.get("reliability"),
            "composite": result.get("composite"),
            "asr": result.get("asr"),
            "response_gradient": result.get("response_gradient"),
        },
        "secret_present": bool(result.get("secret_present")),
        "breach_detected": bool(result.get("breach_detected")),
        "partial_leak_detected": bool(result.get("partial_leak_detected")),
        "failure_mode": result.get("failure_mode"),
        "response_cluster": result.get("response_cluster"),
        "recommended_next_family": result.get("recommended_next_family"),
        "planner_guided": bool(result.get("planner_guided")),
        "planner_strategy": result.get("planner_strategy"),
        "seed_sources": list(result.get("seed_sources") or []),
        "seed_titles": list(result.get("seed_titles") or []),
    }


def write_experiment_record(
    result: dict[str, Any],
    *,
    path: Path | None = None,
) -> Path:
    """Write the experiment JSON for this attack id. Returns the path written."""
    attack_id = str(result.get("attack_id") or "attack")
    target_id = str(result.get("target_id") or "") or None
    dest = path or experiment_path(attack_id, target_id=target_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    record = build_experiment_record(result)
    dest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest
