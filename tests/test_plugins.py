"""Builtin provider plugins and model switching."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentbreaker.plugins import get_provider, list_providers, provider_catalog
from agentbreaker.plugins.model_switch import switch_model


class BuiltinRegistryTests(unittest.TestCase):
    def test_bundled_providers_register_in_order(self) -> None:
        ids = [plugin.id for plugin in list_providers()]
        self.assertEqual(
            ids,
            ["openai", "anthropic", "google", "groq", "openrouter", "local", "custom"],
        )

    def test_aliases_resolve_to_the_builtin(self) -> None:
        self.assertEqual(get_provider("gemini").id, "google")
        self.assertEqual(get_provider("ollama").id, "local")

    def test_catalog_exposes_models(self) -> None:
        openai = next(item for item in provider_catalog() if item["id"] == "openai")
        self.assertIn("gpt-5.4", openai["models"])
        self.assertTrue(openai["builtin"])


class ModelSwitchTests(unittest.TestCase):
    def test_switch_keeps_unrelated_settings(self) -> None:
        config = {
            "judge": {
                "provider": "llm",
                "config": {"api": "openai", "model": "gpt-5.4", "temperature": 0.0},
                "use_provider_breach_hint": True,
            },
            "generator": {"provider": "llm", "config": {"model": "gpt-5.4", "temperature": 1.0}},
        }
        result = switch_model(config, role="judge", provider="anthropic", model="claude-sonnet-4-5")
        self.assertEqual(result["provider"], "anthropic")
        judge = config["judge"]["config"]
        self.assertEqual(judge["model"], "claude-sonnet-4-5")
        self.assertEqual(judge["api"], "anthropic")
        self.assertEqual(judge["api_key_env"], "ANTHROPIC_API_KEY")
        self.assertEqual(judge["temperature"], 0.0)
        self.assertTrue(config["judge"]["use_provider_breach_hint"])
        self.assertEqual(config["generator"]["config"]["model"], "gpt-5.4")

    def test_provider_default_model_and_alias(self) -> None:
        config: dict = {}
        result = switch_model(config, role="both", provider="gemini")
        self.assertEqual(result["provider"], "google")
        self.assertEqual(result["model"], "gemini-2.5-pro")
        self.assertEqual(config["judge"]["config"]["model"], "gemini-2.5-pro")
        self.assertEqual(config["generator"]["config"]["endpoint"], "https://generativelanguage.googleapis.com/v1beta/openai")

    def test_unknown_provider_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            switch_model({}, role="judge", provider="missing")


class ModelCliTests(unittest.TestCase):
    def test_plugins_json_and_model_switch_file(self) -> None:
        listed = subprocess.run(
            [sys.executable, "-m", "agentbreaker", "plugins", "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(listed.stdout)
        self.assertIn("groq", {item["id"] for item in payload})

        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "target_config.yaml"
            config_path.write_text(
                "judge:\n  provider: llm\n  config:\n    api: openai\n    model: gpt-5.4\n    temperature: 0.0\n",
                encoding="utf-8",
            )
            switched = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentbreaker",
                    "model",
                    "--config",
                    str(config_path),
                    "--role",
                    "judge",
                    "--provider",
                    "groq",
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(switched.stdout)
            self.assertEqual(result["model"], "llama-3.3-70b-versatile")
            saved = config_path.read_text(encoding="utf-8")
            self.assertIn("llama-3.3-70b-versatile", saved)
            self.assertIn("temperature: 0.0", saved)
