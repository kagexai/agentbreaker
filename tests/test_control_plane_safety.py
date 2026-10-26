"""Safety and wiring checks for the operator control plane."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from agentbreaker.config_schema import detect_model_family, resolve_llm_family
from agentbreaker.control_plane import (
    _QuietThreadingHTTPServer,
    ControlPlaneHandler,
    _build_scan_command,
    _build_target_from_payload,
    assert_loopback_bind,
    resolve_frontend_asset,
)
from agentbreaker.llm_error_utils import normalize_openai_base_url


class LoopbackBindTests(unittest.TestCase):
    def test_loopback_hosts_are_allowed(self) -> None:
        for host in ("127.0.0.1", "localhost", "::1"):
            assert_loopback_bind(host)

    def test_routable_and_empty_hosts_are_refused(self) -> None:
        for host in ("0.0.0.0", "192.168.1.8", ""):
            with self.assertRaises(SystemExit) as raised:
                assert_loopback_bind(host)
            self.assertIn("Refusing to bind", str(raised.exception))

    def test_remote_override(self) -> None:
        with mock.patch.dict(os.environ, {"AGENTBREAKER_ALLOW_REMOTE": "1"}):
            assert_loopback_bind("0.0.0.0")


class ScanCommandTests(unittest.TestCase):
    def test_rejects_flag_and_path_targets(self) -> None:
        for target_id in ("--config", "../secret", "gpt 5", ""):
            with self.assertRaises(ValueError):
                _build_scan_command({"action": "run", "target_id": target_id})

    def test_builds_a_safe_command(self) -> None:
        command, _label, target_id = _build_scan_command(
            {
                "action": "run",
                "target_id": "gpt-5.4",
                "campaign_tag": "mar-24",
                "max_steps": "3",
                "dry_run": True,
            }
        )
        self.assertEqual(target_id, "gpt-5.4")
        self.assertEqual(command[-6:], ["gpt-5.4", "--campaign-tag", "mar-24", "--max-steps", "3", "--dry-run"])
        self.assertNotIn("--config", command)

    def test_rejects_non_numeric_max_steps(self) -> None:
        with self.assertRaises(ValueError):
            _build_scan_command({"action": "run", "target_id": "gpt-5.4", "max_steps": "--config"})


class ModelFamilyTests(unittest.TestCase):
    def test_detection_ignores_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            previous = os.getcwd()
            os.chdir(temp)
            try:
                family = detect_model_family("gpt-5.4")
            finally:
                os.chdir(previous)
        self.assertIsNotNone(family)
        assert family is not None
        self.assertEqual(family.api, "openai")

    def test_local_endpoint_is_an_sdk_base_url(self) -> None:
        family = detect_model_family("llama3.1")
        self.assertIsNotNone(family)
        assert family is not None
        self.assertEqual(family.endpoint, "http://localhost:11434/v1")

    def test_explicit_groq_beats_llama_name_detection(self) -> None:
        family = resolve_llm_family("llama-3.3-70b-versatile", "groq")
        self.assertIsNotNone(family)
        assert family is not None
        self.assertEqual(family.api_key_env, "GROQ_API_KEY")
        self.assertEqual(family.endpoint, "https://api.groq.com/openai/v1")

    def test_chat_completions_suffix_is_stripped(self) -> None:
        self.assertEqual(
            normalize_openai_base_url("http://localhost:11434/v1/chat/completions"),
            "http://localhost:11434/v1",
        )


class TargetWriteTests(unittest.TestCase):
    def test_groq_target_keeps_groq_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "target_config.yaml"
            config_path.write_text("targets: []\n", encoding="utf-8")
            result = _build_target_from_payload(
                {
                    "input_kind": "model",
                    "model": "llama-3.3-70b-versatile",
                    "provider_kind": "groq",
                    "target_id": "groq-llama",
                },
                config_path=config_path,
            )
            self.assertEqual(result["target_id"], "groq-llama")
            saved = config_path.read_text(encoding="utf-8")
            self.assertIn("https://api.groq.com/openai/v1", saved)
            self.assertNotIn("11434", saved)


class FrontendAssetTests(unittest.TestCase):
    def test_path_escape_is_not_served(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            dist = Path(temp)
            (dist / "index.html").write_text("ok", encoding="utf-8")
            self.assertIsNone(resolve_frontend_asset(dist, "/../../etc/passwd"))
            self.assertEqual(resolve_frontend_asset(dist, "/missing") , dist / "index.html")


class ControlPlaneHttpTests(unittest.TestCase):
    def test_dashboard_and_target_guard(self) -> None:
        server = _QuietThreadingHTTPServer(("127.0.0.1", 0), ControlPlaneHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with mock.patch(
                "agentbreaker.control_plane.frontend_dist_dir",
                return_value=Path("/no/such/agentbreaker-dist"),
            ):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as response:
                    body = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("text/html", response.headers.get("Content-Type", ""))
                    self.assertIn("AgentBreaker", body)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=10) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    self.assertTrue(payload["ok"])

                request = urllib.request.Request(f"http://127.0.0.1:{port}/api/targets/..%2F..%2F.env")
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=10)
                self.assertEqual(raised.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()


class ImportTests(unittest.TestCase):
    def test_root_modules_import(self) -> None:
        import control_plane
        import metadata_index

        self.assertTrue(callable(control_plane.serve_control_plane))
        self.assertTrue(callable(metadata_index._now_iso))


if __name__ == "__main__":
    unittest.main()
