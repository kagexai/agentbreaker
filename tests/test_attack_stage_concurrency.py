"""Staged attack stage: objectives run CONCURRENTLY, not sequentially.

The stage used to run objectives one-at-a-time (each draining its whole budget before the
next began), which is why a 4-objective UI job felt slow. These tests pin the new behaviour:
objectives fan out in parallel, outcomes stay in objective order, the shared budget is
sliced across them, and concurrent attack-id allocation never hands out a duplicate.
"""

from __future__ import annotations

import threading
import time

from agentbreaker.agents.contracts import AttackObjective, AttackPlan, ObjectiveOutcome
from agentbreaker.agents.stages.attack import attack_stage


def _plan(n: int, budget: int = 3) -> AttackPlan:
    return AttackPlan(objectives=[
        AttackObjective(target_field=f"field_{i}", category="data_exfiltration",
                        strategy_family="json_export", budget=budget)
        for i in range(n)
    ])


def _state(plan: AttackPlan, executor, max_experiments: int = 100) -> dict:
    return {
        "plan": plan,
        "target_id": "t", "config_path": "c", "profile": {},
        "budget": {"max_experiments": max_experiments, "experiments_spent": 0, "max_replans": 0},
        "replan_count": 0,
        "_executor": executor,
        "log": [],
    }


class _ConcurrencyProbe:
    """Fake executor that records how many objectives run at once."""

    def __init__(self, hold: float = 0.05):
        self.hold = hold
        self._active = 0
        self.max_active = 0
        self._lock = threading.Lock()
        self.seen_fields: list[str] = []

    def __call__(self, objective: AttackObjective, budget: int, state: dict) -> ObjectiveOutcome:
        with self._lock:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
            self.seen_fields.append(objective.target_field)
        try:
            time.sleep(self.hold)   # simulate the LLM reason->craft->reflect rounds
        finally:
            with self._lock:
                self._active -= 1
        return ObjectiveOutcome(objective=objective, experiments_run=budget, breached=False)


def test_objectives_run_concurrently():
    probe = _ConcurrencyProbe()
    plan = _plan(4)
    out = attack_stage(_state(plan, probe))
    results = out["results"]
    # All four objectives ran ...
    assert len(results.per_objective) == 4
    # ... and at least two were in flight at the same time (proves parallel, not sequential).
    assert probe.max_active >= 2


def test_outcomes_preserve_objective_order():
    probe = _ConcurrencyProbe(hold=0.0)
    plan = _plan(5)
    out = attack_stage(_state(plan, probe))
    fields = [o.objective.target_field for o in out["results"].per_objective]
    assert fields == [f"field_{i}" for i in range(5)]


def test_budget_is_sliced_not_multiplied():
    # Total spend across objectives must not exceed the remaining experiment budget.
    probe = _ConcurrencyProbe(hold=0.0)
    plan = _plan(6, budget=5)          # 6 objectives x5 = 30 requested ...
    out = attack_stage(_state(plan, probe, max_experiments=10))  # ... but only 10 available
    total = out["results"].total_experiments
    assert total <= 10


def test_concurrent_next_attack_id_never_duplicates(tmp_path, monkeypatch):
    # The real allocator under heavy concurrent load must return all-unique ids.
    from agentbreaker import campaign as camp
    monkeypatch.setenv("AGENTBREAKER_AUDIT_LOG", str(tmp_path / "attack_log.jsonl"))
    monkeypatch.setattr(camp, "_ID_HIGH_WATER", 0, raising=False)
    monkeypatch.setattr(camp, "_existing_attack_ids_global", lambda: [])
    monkeypatch.setattr(camp, "_audit_log_max_id", lambda: 0)

    ids: list[str] = []
    ids_lock = threading.Lock()

    def _grab():
        got = [camp._next_attack_id() for _ in range(50)]
        with ids_lock:
            ids.extend(got)

    threads = [threading.Thread(target=_grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ids) == 400
    assert len(set(ids)) == 400   # zero collisions
