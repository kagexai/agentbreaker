"""Attack stage.

Phase 0 ("wrap, then migrate"): execute each objective by running the existing
CampaignEngine for a bounded number of experiments, focused on the objective's target
field. The engine still decides tactics internally; later phases replace it with a
per-objective Attack Agent (Payload Crafter / Executor / Refiner / Critic) while reusing
the same belief/PAIR/judge machinery.

The executor is injectable so the stage is testable without a live target.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from ..contracts import AttackObjective, AttackResults, ObjectiveOutcome
from ..blackboard import remaining_experiments

logger = logging.getLogger(__name__)

# An executor turns one objective + a step budget into an outcome.
Executor = Callable[[AttackObjective, int, dict], ObjectiveOutcome]


class EngineExecutor:
    """Default executor: runs the in-process CampaignEngine, focused on the objective."""

    def __init__(self, *, target_id: str, config_path: str, profile: dict,
                 campaign_tag: str | None = None, staged_trials: int = 2,
                 llm_first: bool = True):
        self.target_id = target_id
        self.config_path = config_path
        self.profile = profile
        self.campaign_tag = campaign_tag
        self.staged_trials = staged_trials   # fewer trials/attack than the default 5 -> faster
        self.llm_first = llm_first           # activate the LLM generator from attack #1
        self._engine = None   # test-injection override; production builds fresh per objective

    def _get_engine(self):
        # A FRESH engine per objective: objectives run concurrently, and the engine focuses
        # field selection by mutating belief.ranked_fields_override (below) -- sharing one
        # engine across threads would let objectives stomp each other's focus, belief, and
        # _experiments_run counter. Building per-objective keeps them isolated. The shared
        # artifact files (audit log, campaign.db, attack-id counter) are guarded by locks.
        # A test may inject self._engine to bypass real provider/harness construction.
        if self._engine is not None:
            return self._engine
        from ...campaign_engine import CampaignEngine
        engine = CampaignEngine(
            target_id=self.target_id,
            config_path=self.config_path,
            profile=self.profile,
            campaign_tag=self.campaign_tag,
        )
        self._tune_for_staged(engine)
        return engine

    def _tune_for_staged(self, engine) -> None:
        """Make the staged engine reason like an agent instead of brute-forcing.

        - Activate the LLM generator immediately (the default belief loop runs ~20
          template attacks first, which is the slow, "tool-calling" feel).
        - Reduce trials per attack so each reasoned payload is cheaper.
        """
        try:
            if self.staged_trials and getattr(engine, "harness", None) is not None:
                engine.harness._trials = max(1, int(self.staged_trials))
        except Exception:
            logger.debug("could not set staged trials", exc_info=True)
        try:
            if self.llm_first and getattr(engine, "generator", None) is not None:
                engine.generator.config.min_template_experiments = 0
                engine.generator.config.stuck_threshold = 1
        except Exception:
            logger.debug("could not enable llm-first", exc_info=True)

    def __call__(self, objective: AttackObjective, budget: int, state: dict) -> ObjectiveOutcome:
        engine = self._get_engine()
        # Focus the engine's field selection on this objective.
        engine.belief.ranked_fields_override = [objective.target_field]
        before_exp = engine._experiments_run
        before_breach = engine.belief.total_breaches
        before_best = engine.belief.best_composite
        # engine._experiments_run is cumulative across run() calls, and run() stops when
        # it reaches max_steps -- so the ceiling must be relative to the current count,
        # otherwise every objective after the first gets starved to a single experiment.
        try:
            rc = engine.run(max_steps=before_exp + budget, loop=True)
        except Exception:
            logger.warning("Engine run failed for objective %s", objective.target_field, exc_info=True)
            rc = 0
        # CampaignEngine.run() catches KeyboardInterrupt internally and returns 130. If we
        # don't propagate that, a Stop/Ctrl-C only ends THIS objective and the staged
        # pipeline marches on -- making the job feel unstoppable. Re-raise to abort.
        if rc == 130:
            raise KeyboardInterrupt
        return ObjectiveOutcome(
            objective=objective,
            experiments_run=max(0, engine._experiments_run - before_exp),
            best_composite=max(before_best, engine.belief.best_composite),
            breached=engine.belief.total_breaches > before_breach,
        )


def attack_stage(state: dict[str, Any]) -> dict[str, Any]:
    plan = state.get("plan")
    objectives: list[AttackObjective] = list(getattr(plan, "objectives", []) or [])
    budget = state.get("budget", {}) or {}
    remaining = remaining_experiments(state)
    max_replans = int(budget.get("max_replans", 0))
    replan_count = int(state.get("replan_count", 0))

    executor: Executor | None = state.get("_executor")
    if executor is None:
        if str(state.get("_attacker", "engine")).lower() == "agent":
            from .attack_agent import AgentExecutor
            executor = AgentExecutor(
                target_id=str(state.get("target_id", "")),
                config_path=str(state.get("config_path", "")),
                profile=state.get("profile", {}) or {},
                campaign_tag=state.get("campaign_tag"),
            )
        else:
            executor = EngineExecutor(
                target_id=str(state.get("target_id", "")),
                config_path=str(state.get("config_path", "")),
                profile=state.get("profile", {}) or {},
                campaign_tag=state.get("campaign_tag"),
            )

    from ..live import emit as _emit, stage as _stage
    _stage(state, "attack", "start", f"{len(objectives)} objective(s), {remaining} experiments available")

    # Pre-slice the shared experiment budget across objectives, then run them CONCURRENTLY.
    # Previously this loop was strictly sequential -- each objective drained its whole budget
    # before the next began, so an N-objective plan took ~Nx longer than necessary (the
    # dominant cost is the per-objective LLM reason->craft->reflect rounds). Objectives are
    # independent (each focuses its own target_field), so we fan them out; the shared artifact
    # writes (audit log, campaign.db, attack-id counter, live events) are lock-guarded.
    planned: list[tuple[int, AttackObjective, int]] = []
    rem = remaining
    for idx, obj in enumerate(objectives, 1):
        if rem <= 0:
            break
        spend = max(1, min(int(obj.budget), rem))
        planned.append((idx, obj, spend))
        rem -= spend

    for idx, obj, spend in planned:
        _emit(state, "objective", index=idx, total=len(objectives),
              field=obj.target_field, category=obj.category,
              strategy_family=obj.strategy_family, budget=spend)

    def _run_one(item: tuple[int, AttackObjective, int]) -> tuple[int, ObjectiveOutcome]:
        idx, obj, spend = item
        outcome = executor(obj, spend, state)
        _emit(state, "objective_done", field=obj.target_field, category=obj.category,
              breached=outcome.breached, experiments=outcome.experiments_run,
              best_composite=round(outcome.best_composite, 2),
              methods=[m.get("method") for m in (outcome.methods_tried or [])])
        return idx, outcome

    concurrency = max(1, min(len(planned), int(budget.get("objective_concurrency", 4) or 4)))
    outcomes_by_idx: dict[int, ObjectiveOutcome] = {}
    if concurrency <= 1 or len(planned) <= 1:
        for item in planned:
            i, oc = _run_one(item)
            outcomes_by_idx[i] = oc
    else:
        from concurrent.futures import ThreadPoolExecutor
        # ex.map re-raises a worker's exception (e.g. EngineExecutor's KeyboardInterrupt on
        # Stop) when we iterate to it, propagating the abort out of the stage as before.
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            for i, oc in ex.map(_run_one, planned):
                outcomes_by_idx[i] = oc

    outcomes: list[ObjectiveOutcome] = [outcomes_by_idx[i] for i in sorted(outcomes_by_idx)]

    results = AttackResults(per_objective=outcomes)
    _stage(state, "attack", "done",
           f"{results.total_experiments} experiments over {len(outcomes)} objective(s), "
           f"{sum(1 for o in outcomes if o.breached)} breach(es)")

    # Loop-back desire: stuck (no breach) but budget + replan allowance remain.
    want_replan = (
        not results.any_breach
        and remaining_experiments(state) > 0
        and replan_count < max_replans
        and bool(objectives)
    )
    results.replan_requested = want_replan

    new_budget = dict(budget)
    new_budget["experiments_spent"] = int(budget.get("experiments_spent", 0)) + results.total_experiments

    log = list(state.get("log", []))
    log.append(
        f"[attack] ran {results.total_experiments} experiments over {len(outcomes)} objectives; "
        f"breach={results.any_breach} replan_requested={want_replan}"
    )
    return {
        "results": results,
        "budget": new_budget,
        "replan_count": replan_count + (1 if want_replan else 0),
        "log": log,
    }
