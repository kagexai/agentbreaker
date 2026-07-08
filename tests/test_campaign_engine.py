"""Unit tests for the in-process campaign engine (agentbreaker/campaign_engine.py).

These cover the belief-state learning logic and the engine decision/dedup/persistence
paths in isolation -- no real provider, harness, or LLM calls. Engine methods are
exercised on a bare instance built with __new__ so we never touch EvaluationHarness.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentbreaker import campaign_engine as ce


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_belief(**kw) -> ce.BeliefState:
    return ce.BeliefState(target_id=kw.pop("target_id", "t"), profile=kw.pop("profile", {}), **kw)


def make_engine(belief: ce.BeliefState | None = None) -> ce.CampaignEngine:
    """Build a CampaignEngine without running __init__ (no harness/provider needed)."""
    eng = ce.CampaignEngine.__new__(ce.CampaignEngine)
    eng.target_id = "t"
    eng.profile = {}
    eng.config_path = Path("target_config.yaml")
    eng.campaign_tag = None
    eng.belief = belief or make_belief()
    eng._experiments_run = 0
    eng._strategy_sequence = list(ce.DEFAULT_STRATEGY_SEQUENCE)
    return eng


def make_result(attack_id="ATK-00001", composite=0.0, gradient=0.0, breach=False,
                partial_leak=False, cluster="", failure_mode="", recommended=""):
    return {
        "attack_id": attack_id,
        "composite": composite,
        "response_gradient": gradient,
        "breach_detected": breach,
        "partial_leak_detected": partial_leak,
        "response_cluster": cluster,
        "failure_mode": failure_mode,
        "recommended_next_family": recommended,
        "payload_preview": "",
    }


def make_action(strategy_id="completion_attack", target_field="system_prompt",
                warm_vector=None, use_template=True, variant_index=0):
    return ce.AttackAction(
        attack_id="ATK-00001",
        strategy_id=strategy_id,
        category="prompt_injection",
        target_field=target_field,
        warm_vector=warm_vector,
        use_template=use_template,
        variant_index=variant_index,
    )


@pytest.fixture(autouse=True)
def stub_audit(monkeypatch):
    """Neutralize audit-log reads so update_belief is hermetic by default."""
    monkeypatch.setattr(ce._campaign, "_latest_audit_entry", lambda aid: {})
    monkeypatch.setattr(ce._campaign, "_audit_text", lambda audit: "")
    monkeypatch.setattr(ce._campaign, "_audit_semantic_breach", lambda audit: {})


# ---------------------------------------------------------------------------
# BeliefState.record_result
# ---------------------------------------------------------------------------

def test_record_result_tracks_scores_and_stall():
    b = make_belief()
    b.record_result("s", 1.0, 0.0, "", "", False)
    b.record_result("s", 1.0, 0.0, "", "", False)
    assert b.strategy_scores["s"] == [1.0, 1.0]
    assert b.stall_counter == 2          # both below 3.0
    b.record_result("s", 5.0, 0.0, "", "", False)
    assert b.stall_counter == 0          # high score resets


def test_record_result_cools_after_consecutive_lows():
    b = make_belief()
    for _ in range(ce._COOL_THRESHOLD):
        b.record_result("weak", 1.0, 0.0, "", "", False)
    assert b.is_cooled("weak")


def test_infra_failures_excluded_from_belief():
    b = make_belief()
    b.record_result("s", 0.0, 0.0, "", "infra_timeout", False, is_infra=True)
    # counted for observability...
    assert b.total_attacks == 1
    # ...but excluded from every learning aggregate
    assert "s" not in b.strategy_scores
    assert b.recent_composites == []
    assert b.stall_counter == 0
    assert not b.is_cooled("s")


def test_strategy_reopens_on_rebound():
    b = make_belief()
    for _ in range(ce._COOL_THRESHOLD):
        b.record_result("s", 1.0, 0.0, "", "", False)
    assert b.is_cooled("s")
    b.record_result("s", 5.0, 0.0, "", "", False)   # rebound >= floor
    assert not b.is_cooled("s")
    assert "s" in b.reopened_strategies


# ---------------------------------------------------------------------------
# Warm vectors
# ---------------------------------------------------------------------------

def make_wv(strategy_id="completion_attack", target_field="system_prompt",
            composite=4.0, gradient=0.4, refinement_count=0):
    wv = ce.WarmVector(
        strategy_id=strategy_id, category="prompt_injection", target_field=target_field,
        last_composite=composite, last_gradient=gradient, response_excerpt="x",
        recommended_next="", failure_mode="", refinement_count=refinement_count,
    )
    wv.compute_priority()
    return wv


def test_warm_vector_priority_decreases_with_refinement():
    fresh = make_wv(refinement_count=0).priority
    worn = make_wv(refinement_count=2).priority
    assert worn < fresh


def test_best_warm_vector_respects_min_priority():
    b = make_belief()
    b.add_warm_vector(make_wv(composite=0.1, gradient=0.0))  # very low priority
    assert b.best_warm_vector(min_priority=0.5) is None


def test_warm_vector_starvation_is_bounded():
    """A vector that keeps scoring mediocre (no improvement) must eventually decay
    out, instead of pinning Priority 1 forever."""
    b = make_belief()
    wv = make_wv(composite=4.0)
    b.add_warm_vector(wv)
    eng = make_engine(b)

    # Exploit it _MAX_REFINEMENT_ATTEMPTS times with non-improving results.
    for i in range(ce._MAX_REFINEMENT_ATTEMPTS):
        assert b.best_warm_vector() is not None  # still alive before this attempt
        action = make_action(warm_vector=wv)
        eng.update_belief(action, make_result(composite=3.0))  # < last_composite, no breach
    # After enough fruitless attempts the vector is pruned.
    assert b.best_warm_vector() is None


def test_warm_vector_survives_on_improvement():
    b = make_belief()
    wv = make_wv(composite=3.0)
    b.add_warm_vector(wv)
    eng = make_engine(b)
    action = make_action(warm_vector=wv)
    eng.update_belief(action, make_result(composite=6.0))  # improvement -> no decay
    assert wv.refinement_count == 0


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_belief_intelligence_roundtrip():
    b = make_belief()
    b.add_warm_vector(make_wv())
    b.partial_extractions = {"system_prompt": "frag"}
    b.confirmed_extractions = {"flag": "SECRET"}
    b.cooled_strategies = {"weak"}
    b.reopened_strategies = {"strong"}

    snapshot = b.intelligence_to_dict()
    restored = make_belief()
    restored.load_intelligence(snapshot)

    assert len(restored.warm_vectors) == 1
    assert restored.partial_extractions == {"system_prompt": "frag"}
    assert restored.confirmed_extractions == {"flag": "SECRET"}
    assert restored.cooled_strategies == {"weak"}
    assert restored.reopened_strategies == {"strong"}


def test_save_and_load_belief_via_disk(tmp_path, monkeypatch):
    import agentbreaker.artifact_paths as ap
    monkeypatch.setattr(ap, "artifact_root", lambda tid=None, tag=None: tmp_path)

    eng = make_engine()
    eng.belief.add_warm_vector(make_wv())
    eng.belief.partial_extractions = {"system_prompt": "leaked-bit"}
    eng._save_belief()

    assert (tmp_path / "belief_state.json").exists()

    eng2 = make_engine()
    eng2._load_belief()
    assert len(eng2.belief.warm_vectors) == 1
    assert eng2.belief.partial_extractions == {"system_prompt": "leaked-bit"}


def test_load_belief_tolerates_missing_and_malformed(tmp_path, monkeypatch):
    import agentbreaker.artifact_paths as ap
    monkeypatch.setattr(ap, "artifact_root", lambda tid=None, tag=None: tmp_path)
    eng = make_engine()
    eng._load_belief()  # missing file -> no error
    (tmp_path / "belief_state.json").write_text("{ this is not json")
    eng._load_belief()  # malformed -> swallowed, fresh state
    assert eng.belief.warm_vectors == []


# ---------------------------------------------------------------------------
# Payload deduplication
# ---------------------------------------------------------------------------

def test_ensure_unique_payload_advances_variant(monkeypatch):
    eng = make_engine()

    # Previews: variants 0 and 1 collide with a seen payload; variant 2 is unique.
    def fake_preview(*, variant_index, **kw):
        return "dup" if variant_index < 2 else "unique"

    monkeypatch.setattr(ce, "preview_template_payload", fake_preview)
    monkeypatch.setattr(ce._campaign, "_seen_payload_signatures", lambda tid: ["dup"])
    monkeypatch.setattr(ce._campaign, "_normalize_payload_text", lambda t: t)
    monkeypatch.setattr(ce._campaign, "_too_similar_to_recent",
                        lambda sig, seen: (sig in seen, 1.0 if sig in seen else 0.0))

    action = make_action(variant_index=0)
    eng._ensure_unique_payload(action)
    assert action.variant_index == 2


def test_ensure_unique_payload_noop_without_history(monkeypatch):
    eng = make_engine()
    monkeypatch.setattr(ce._campaign, "_seen_payload_signatures", lambda tid: [])
    action = make_action(variant_index=0)
    eng._ensure_unique_payload(action)
    assert action.variant_index == 0  # nothing to dedup against


# ---------------------------------------------------------------------------
# Decision routing
# ---------------------------------------------------------------------------

def test_decide_prefers_warm_vector(monkeypatch):
    monkeypatch.setattr(ce._campaign, "_next_attack_id", lambda: "ATK-00009")
    b = make_belief()
    b.add_warm_vector(make_wv(strategy_id="completion_attack"))
    eng = make_engine(b)
    # Avoid the dedup preview path touching disk.
    monkeypatch.setattr(eng, "_ensure_unique_payload", lambda action: None)
    action = eng.decide_next_action()
    assert action.source == "warm_vector"


def test_decide_falls_back_when_no_signal(monkeypatch):
    monkeypatch.setattr(ce._campaign, "_next_attack_id", lambda: "ATK-00010")
    eng = make_engine()
    eng.generator = None
    eng.planner = type("P", (), {"enabled": False})()
    monkeypatch.setattr(eng, "_ensure_unique_payload", lambda action: None)
    # Force taxonomy path to yield nothing by keeping total_attacks low.
    action = eng.decide_next_action()
    assert action.source == "fallback"
