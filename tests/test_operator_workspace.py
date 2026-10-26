"""Operator workspace: readiness and configured targets without the attack harness."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentbreaker.operator import build_workspace


LOCAL_CONFIG = """
judge:
  provider: llm
  config:
    api: openai-compatible
    model: llama3.1
    endpoint: http://localhost:11434/v1
generator:
  provider: llm
  config:
    api: openai-compatible
    model: llama3.1
    endpoint: http://localhost:11434/v1
targets:
- id: demo
  provider: script
  tags: [ctf]
  config: {}
- id: "../secret"
  provider: http
  config: {}
"""


class WorkspaceTests(unittest.TestCase):
    def test_missing_judge_key_blocks_and_keeps_every_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "target_config.yaml"
            config.write_text(
                "judge:\n  provider: llm\n  config:\n    api: openai\n    model: gpt-5.4\n    api_key_env: OPENAI_API_KEY\n"
                "generator:\n  provider: llm\n  config:\n    api: openai\n    model: gpt-5.4\n    api_key_env: OPENAI_API_KEY\n"
                "targets:\n- id: alpha\n  provider: http\n- id: beta\n  provider: llm\n",
                encoding="utf-8",
            )
            payload = build_workspace(config_path=config, root=root, environ={})
            self.assertFalse(payload["ready"])
            self.assertEqual([row["target_id"] for row in payload["targets"]], ["alpha", "beta"])
            self.assertTrue(any("OPENAI_API_KEY" in item for item in payload["blocking"]))
            self.assertEqual(payload["counts"]["configured"], 2)
            self.assertEqual(payload["counts"]["tested"], 0)

    def test_findings_count_without_campaign_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "target_config.yaml"
            config.write_text(LOCAL_CONFIG, encoding="utf-8")
            finding = root / "findings" / "success"
            finding.mkdir(parents=True)
            (finding / "ATK-1.yaml").write_text(
                "target: demo\ncategory: prompt_injection\nowasp_ref: LLM01\nscores:\n  composite: 6.5\n",
                encoding="utf-8",
            )
            partial = root / "findings" / "partial"
            partial.mkdir()
            (partial / "ATK-2.yaml").write_text("target_id: demo\ncategory: prompt_injection\n", encoding="utf-8")
            outside = root / "artifacts" / "elsewhere"
            outside.mkdir(parents=True)
            (outside / "results.tsv").write_text("attack_id\tstatus\nATK-9\tkeep\n", encoding="utf-8")
            payload = build_workspace(config_path=config, root=root, environ={})
            self.assertTrue(payload["ready"])
            demo = payload["targets"][0]
            self.assertEqual(demo["status"], "findings")
            self.assertEqual(demo["findings"]["success"], 1)
            self.assertEqual(demo["findings"]["partial"], 1)
            self.assertEqual(demo["attack_count"], 0)
            self.assertEqual(demo["peak_composite"], 6.5)
            self.assertEqual(payload["frameworks"]["owasp"][0]["ref"], "LLM01")
            unsafe = payload["targets"][1]
            self.assertEqual(unsafe["attack_count"], 0)
            self.assertEqual(payload["counts"]["success_findings"], 1)

    def test_campaign_rows_mark_a_target_tested(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "target_config.yaml"
            config.write_text(LOCAL_CONFIG, encoding="utf-8")
            ledger = root / "artifacts" / "demo" / "run-1"
            ledger.mkdir(parents=True)
            (ledger / "results.tsv").write_text("attack_id\tstatus\nATK-1\tkeep\nATK-2\tdrop\n", encoding="utf-8")
            payload = build_workspace(config_path=config, root=root, environ={})
            demo = next(row for row in payload["targets"] if row["target_id"] == "demo")
            self.assertEqual(demo["status"], "tested")
            self.assertEqual(demo["attack_count"], 2)
            self.assertEqual(payload["counts"]["tested"], 1)

    def test_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "target_config.yaml"
            config.write_text(LOCAL_CONFIG, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "agentbreaker", "workspace", "--config", str(config), "--json"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ready"])
            self.assertEqual(payload["engines"]["judge"]["provider_id"], "local")
            self.assertEqual(payload["counts"]["configured"], 2)


if __name__ == "__main__":
    unittest.main()
