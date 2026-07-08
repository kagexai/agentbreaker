"""Target discovery for AgentBreaker.

Finds new attackable targets -- public AI-security CTFs and newly released models --
from several sources, deduplicates them against the existing target_config.yaml, and
records them as *candidates*. Discovery NEVER attacks: a candidate must be explicitly
approved (which registers it as a target) before any campaign can run against it.

Public entry points:
  - DiscoveryEngine.discover(): run all enabled sources and persist new candidates
  - CandidateStore: load/save/list candidates
  - approve_candidate(): turn an approved candidate into a target_config.yaml entry
"""

from __future__ import annotations

from .base import Candidate, CandidateStore, DiscoverySource
from .engine import DiscoveryEngine
from .approve import approve_candidate, ApprovalError

__all__ = [
    "Candidate",
    "CandidateStore",
    "DiscoverySource",
    "DiscoveryEngine",
    "approve_candidate",
    "ApprovalError",
]
