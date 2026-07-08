"""Typed contracts handed between pipeline stages.

Each stage validates its input and produces one of these. They are plain dataclasses so
they serialize cleanly into the Blackboard and (later) into LangGraph state / artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ReconReport:
    """What the Recon stage learned about the target."""
    target_id: str
    capabilities: dict[str, bool] = field(default_factory=dict)
    attack_surface: list[dict[str, Any]] = field(default_factory=list)  # {field, category, reason, priority}
    guardrails: dict[str, Any] = field(default_factory=dict)            # refusal_phrases, blockers, clusters
    persona: str = ""
    domain: str = ""
    deployment_type: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReconReport":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class AttackObjective:
    """A single thing the Attack stage should try to achieve (not a single payload)."""
    target_field: str
    category: str
    strategy_family: str = ""
    hypothesis: str = ""
    success_criteria: str = ""
    budget: int = 5                 # max experiments the Attack stage may spend here
    priority: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackObjective":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class AttackPlan:
    """Ordered objectives produced by the Analyse stage."""
    objectives: list[AttackObjective] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"objectives": [o.to_dict() for o in self.objectives], "rationale": self.rationale}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackPlan":
        return cls(
            objectives=[AttackObjective.from_dict(o) for o in d.get("objectives", [])],
            rationale=str(d.get("rationale", "")),
        )


@dataclass
class ObjectiveOutcome:
    objective: AttackObjective
    experiments_run: int = 0
    best_composite: float = 0.0
    breached: bool = False
    evidence_refs: list[str] = field(default_factory=list)   # attack_ids / finding paths
    methods_tried: list[dict[str, Any]] = field(default_factory=list)  # {method, broke} coverage cells
    # Per-attempt evidence: the actual prompt that ran, what the model returned, and the
    # judge's reason. `broke` cells become confirmed vulnerabilities in the report; the
    # strongest non-breaking attempt is kept too so "resisted, but closest was X" is shown.
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"objective": self.objective.to_dict(), "experiments_run": self.experiments_run,
                "best_composite": self.best_composite, "breached": self.breached,
                "evidence_refs": list(self.evidence_refs),
                "methods_tried": list(self.methods_tried),
                "evidence": list(self.evidence)}


@dataclass
class AttackResults:
    """Outcomes from the Attack stage, plus loop-back signal."""
    per_objective: list[ObjectiveOutcome] = field(default_factory=list)
    replan_requested: bool = False
    new_surface: list[str] = field(default_factory=list)

    @property
    def total_experiments(self) -> int:
        return sum(o.experiments_run for o in self.per_objective)

    @property
    def any_breach(self) -> bool:
        return any(o.breached for o in self.per_objective)

    def to_dict(self) -> dict[str, Any]:
        return {"per_objective": [o.to_dict() for o in self.per_objective],
                "replan_requested": self.replan_requested, "new_surface": list(self.new_surface)}


@dataclass
class Report:
    """Final synthesis from the Report stage."""
    target_id: str
    summary: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
