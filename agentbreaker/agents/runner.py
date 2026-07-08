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

    # Full-surface sweep: alongside the campaign, run the harm taxonomy + sandboxed tool-abuse
    # + safety probes so ONE scan covers what deepteam's red_team() does (not just the campaign
    # categories). Skipped for 'quick' (keep it fast); best-effort so a scanner failure never
    # sinks the run. Persisted for the report card to fold in.
    if str(coverage).lower() != "quick":
        _run_supplemental_scans(bb, target_id, config_path, campaign_tag)

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


def _run_supplemental_scans(bb: Any, target_id: str, config_path: str | Path,
                            campaign_tag: str | None) -> None:
    """Run harm-taxonomy + sandboxed tool-abuse + safety probes CONCURRENTLY alongside the
    campaign and persist the merged result, so one scan covers the full surface. Each scanner
    is best-effort: a failure (e.g. no provider key) is logged and omitted, never fatal."""
    import json
    from concurrent.futures import ThreadPoolExecutor
    from .. import artifact_paths
    from .live import stage as _stage

    cfg = str(config_path)

    def _harm():
        from ..harm_taxonomy import run_harm_scan
        return run_harm_scan(target_id, cfg)

    def _tools():
        from ..tool_harness import run_all_scenarios
        results = run_all_scenarios(target_id)
        return {"breached": sum(1 for r in results if r.breached), "total": len(results),
                "results": [r.to_dict() for r in results]}

    def _safety():
        from ..model_safety import provider_callback, probe_model
        return probe_model(target_id, provider_callback(target_id, cfg)).to_dict()

    _stage(bb, "sweep", "start", "harm taxonomy + tool-abuse sandbox + safety probes")
    jobs = {"harm": _harm, "tool_abuse": _tools, "safety": _safety}
    out: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {k: ex.submit(fn) for k, fn in jobs.items()}
        for k, fut in futures.items():
            try:
                out[k] = fut.result()
            except Exception as exc:
                logger.warning("supplemental %s scan skipped: %s", k, exc)

    try:
        path = artifact_paths.supplemental_scans_path(target_id, campaign_tag)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(out, indent=2))
        tmp.replace(path)
    except Exception:
        logger.warning("could not persist supplemental scans", exc_info=True)

    harm = out.get("harm") or {}
    tool = out.get("tool_abuse") or {}
    _stage(bb, "sweep", "done",
           f"harm {harm.get('complied', 0)}/{harm.get('probes', 0)} · "
           f"tool-abuse {tool.get('breached', 0)}/{tool.get('total', 0)} · "
           f"safety {(out.get('safety') or {}).get('resistance', '—')}")


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
