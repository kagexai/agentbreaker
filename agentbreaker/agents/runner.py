"""Entry point the CLI calls for `--engine staged`."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .blackboard import new_blackboard
from .graph import run_pipeline, langgraph_available

logger = logging.getLogger(__name__)


def run_staged_campaign(
    *,
    target_id: str,
    config_path: str | Path,
    profile: dict[str, Any],
    campaign_tag: str | None = None,
    max_experiments: int = 50,
    max_replans: int = 2,
    executor: Any | None = None,
    attacker: str = "agent",
    coverage: str = "standard",
) -> int:
    """Run the recon -> analyse -> attack -> report pipeline. Returns an exit code.

    `executor` (optional) overrides the Attack stage's executor -- used by tests to avoid a
    live target. `attacker` selects the built-in executor: "engine" (tuned belief loop,
    default) or "agent" (LLM reason->craft->reflect loop).
    """
    bb = new_blackboard(
        target_id=target_id,
        config_path=config_path,
        profile=profile,
        campaign_tag=campaign_tag,
        max_experiments=max_experiments,
        max_replans=max_replans,
    )
    if executor is not None:
        bb["_executor"] = executor  # type: ignore[typeddict-unknown-key]
    bb["_attacker"] = attacker  # type: ignore[typeddict-unknown-key]
    bb["coverage"] = coverage  # type: ignore[typeddict-unknown-key]  # taxonomy breadth per scan

    runtime = "LangGraph" if langgraph_available() else "built-in fallback orchestrator"
    print(f"[staged] runtime: {runtime} | attacker: {attacker}")

    # Start the live-event log fresh so the UI doesn't replay a prior run's events.
    try:
        from .. import artifact_paths
        p = artifact_paths.live_events_path(target_id, campaign_tag)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    except Exception:
        logger.debug("could not reset live events", exc_info=True)

    final = run_pipeline(bb)

    for line in final.get("log", []):
        print(line)

    report = final.get("report")
    if report is not None:
        _persist_report(report, target_id, campaign_tag)
        print(f"\n[staged] {report.summary}")
        if report.findings:
            print(f"[staged] {len(report.findings)} finding(s):")
            for f in report.findings:
                print(f"  - {f['target_field']} / {f['category']}: "
                      f"composite={f['best_composite']} breached={f['breached']}")
        mm = (report.coverage or {}).get("method_matrix") or {}
        if mm:
            cells = ", ".join(f"{k} {v['breaks']}/{v['attempts']}" for k, v in mm.items())
            print(f"[staged] method coverage (breaks/attempts): {cells}")
        return 0 if not report.findings else 0
    print("[staged] pipeline produced no report")
    return 1


def _persist_report(report: Any, target_id: str, campaign_tag: str | None) -> None:
    """Write the staged Report (summary + findings + coverage.method_matrix) to an
    artifact the control plane can serve, so the UI can render a coverage grid."""
    import json
    from .. import artifact_paths
    try:
        path = artifact_paths.staged_report_path(target_id, campaign_tag)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = report.to_dict()
        payload["target_id"] = target_id
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(path)
    except Exception:
        logger.warning("could not persist staged report", exc_info=True)
