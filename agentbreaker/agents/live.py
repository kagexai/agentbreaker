"""Live pipeline events for the staged engine.

The SSE stream in the control plane tails artifact files written by the belief engine
(planner_log / attack_log / results.tsv). The staged pipeline's narrative — which stage is
running, which objective, which attack method, and when it breaks through — lived only in
the end-of-run `log`, so the UI had no live visibility into it.

This module appends structured events to ``live_events.jsonl`` under the target's artifact
root as the pipeline runs. The stream tails that file and forwards each event to the UI.
Every event carries ``type: "pipeline"`` plus a ``kind`` so the frontend can render a
timeline. Best-effort: a failed write never breaks the campaign.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Serializes appends so concurrent objectives (staged engine) don't interleave event lines.
_EMIT_LOCK = threading.Lock()


def emit(state: dict, kind: str, **fields: Any) -> None:
    """Append one pipeline event. `state` supplies target_id/campaign_tag."""
    try:
        from .. import artifact_paths
        path = artifact_paths.live_events_path(state.get("target_id"), state.get("campaign_tag"))
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {"type": "pipeline", "kind": kind, **fields}
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with _EMIT_LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception:
        logger.debug("live emit failed", exc_info=True)


def stage(state: dict, stage_name: str, phase: str, detail: str = "") -> None:
    """Convenience: a stage lifecycle event (phase = 'start' | 'done')."""
    emit(state, "stage", stage=stage_name, phase=phase, detail=detail)
