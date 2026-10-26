"""Builtin strategy plugins and experiment records."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from agentbreaker.domain_helpers import DomainContext
from agentbreaker.experiment_record import build_experiment_record, write_experiment_record
from agentbreaker.seed_manager import SeedManager
from agentbreaker.strategies import (
    StrategyRuntime,
    bind,
    clear,
    list_strategies,
    require_strategy,
    strategy_catalog,
)


class StrategyRegistryTests(unittest.TestCase):
    def test_bundled_strategies_register(self) -> None:
        ids = [plugin.id for plugin in list_strategies()]
        self.assertIn("completion_attack", ids)
        self.assertIn("verbatim_request", ids)
        self.assertIn("maintenance_override", ids)
        self.assertIn("image_text_injection", ids)

    def test_alias_resolves_membership_card(self) -> None:
        plugin = require_strategy("membership_card_injection")
        self.assertEqual(plugin.id, "image_text_injection")

    def test_catalog_exposes_metadata(self) -> None:
        row = next(item for item in strategy_catalog() if item["id"] == "verbatim_request")
        self.assertEqual(row["category"], "system_prompt_extraction")
        self.assertEqual(row["owasp_ref"], "LLM07")


class StrategyBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        ctx = DomainContext(
            profile={},
            persona="Deskbot",
            domain="office",
            refusals=[],
            angles=[],
            ctf_state={},
            variant_idx=0,
            attack_id="ATK-90001",
            target_id="lab",
            attack_spec={},
        )
        seeds = SeedManager(ctx)
        bind(
            StrategyRuntime(
                attack_id="ATK-90001",
                target_id="lab",
                variant_index=0,
                ctx=ctx,
                seeds=seeds,
            )
        )

    def tearDown(self) -> None:
        clear()

    def test_verbatim_builder_embeds_canary(self) -> None:
        plugin = require_strategy("verbatim_request")
        text = plugin.builder()
        self.assertIn("[CANARY:ATK-90001]", text)
        self.assertIn("Deskbot", text)


class ExperimentRecordTests(unittest.TestCase):
    def test_write_experiment_record_json(self) -> None:
        result = {
            "attack_id": "ATK-90002",
            "target_id": "frontier",
            "category": "system_prompt_extraction",
            "technique": "verbatim_request",
            "owasp_ref": "LLM07",
            "benchmark_ref": "TensorTrust",
            "description": "test",
            "vulnerability": 10.0,
            "novelty": 1.0,
            "reliability": 10.0,
            "composite": 7.2,
            "asr": 1.0,
            "breach_detected": True,
            "secret_present": True,
            "partial_leak_detected": False,
            "failure_mode": "substantive_leak",
            "response_cluster": "substantive",
            "response_gradient": 1.0,
            "timestamp": "2026-10-27T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ATK-90002.json"
            written = write_experiment_record(result, path=path)
            payload = json.loads(written.read_text(encoding="utf-8"))
            self.assertTrue(payload["secret_present"])
            self.assertTrue(payload["breach_detected"])
            self.assertEqual(payload["strategy"]["technique"], "verbatim_request")
            self.assertEqual(build_experiment_record(result)["attack_id"], "ATK-90002")


if __name__ == "__main__":
    unittest.main()
