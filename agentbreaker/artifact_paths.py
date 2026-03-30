from __future__ import annotations

import os
import re
from pathlib import Path

from . import ROOT


def _safe_component(value: str | None, fallback: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return fallback
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-.")
    return safe or fallback


def artifact_root(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    explicit = os.environ.get("AGENTBREAKER_ARTIFACT_ROOT", "").strip()
    if explicit:
        return Path(explicit)

    target_component = _safe_component(
        target_id or os.environ.get("AGENTBREAKER_TARGET_ID"),
        "shared",
    )
    root = ROOT / "artifacts" / target_component
    tag = _safe_component(
        campaign_tag or os.environ.get("AGENTBREAKER_CAMPAIGN_TAG"),
        "",
    )
    if tag:
        root = root / tag
    return root


def profile_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "target_profile.yaml"


def results_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "results.tsv"


def audit_log_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "attack_log.jsonl"


def planner_log_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "planner_log.jsonl"


def status_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "status.json"


def validation_report_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "validation_report.jsonl"


def ctf_state_path(target_id: str | None = None, campaign_tag: str | None = None) -> Path:
    return artifact_root(target_id, campaign_tag) / "ctf_state.json"
