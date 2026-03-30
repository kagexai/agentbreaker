#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .arc_taxonomy import (
    ARC_DIMENSION_ORDER,
    arc_taxonomy_counts,
    arc_taxonomy_entries,
    arc_taxonomy_source,
    search_arc_taxonomy,
)
from .artifact_paths import (
    artifact_root,
    audit_log_path,
    ctf_state_path,
    planner_log_path,
    profile_path,
    results_path,
    status_path,
    validation_report_path,
)
from .control_plane import serve_control_plane
from . import ROOT
ENV_FILE_PATH = ROOT / ".env"
load_dotenv(ENV_FILE_PATH)
DEFAULT_CONFIG_PATH = ROOT / "target_config.yaml"
FINDINGS_DIR = ROOT / "findings"
SPINNER_FRAMES = "|/-\\"
NO_COLOR = bool(os.environ.get("NO_COLOR"))
USE_COLOR = sys.stdout.isatty() and not NO_COLOR
AGENTBREAKER_LOGO = [
    r"    _    ____ _____ _   _ _____",
    r"   / \  / ___| ____| \ | |_   _|",
    r"  / _ \| |  _|  _| |  \| | | |",
    r" / ___ \ |_| | |___| |\  | | |",
    r"/_/   \_\____|_____|_| \_| |_|",
    r" ____  ____  _____    _    _  _______ ____",
    r"| __ )|  _ \| ____|  / \  | |/ / ____|  _ \\",
    r"|  _ \| |_) |  _|   / _ \ | ' /|  _| | |_) |",
    r"| |_) |  _ <| |___ / ___ \| . \| |___|  _ <",
    r"|____/|_| \_\_____/_/   \_\_|\_\_____|_| \_\\",
]
API_PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "openai": {
        "label": "OpenAI",
        "api": "openai",
        "api_key_env": "OPENAI_API_KEY",
        "endpoint": None,
        "default_model": "gpt-5.4",
    },
    "anthropic": {
        "label": "Anthropic",
        "api": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
        "endpoint": None,
        "default_model": "claude-sonnet-4-5",
    },
    "google": {
        "label": "Google Gemini",
        "api": "openai-compatible",
        "api_key_env": "GOOGLE_API_KEY",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.5-pro",
    },
    "local": {
        "label": "Local OpenAI-compatible",
        "api": "openai-compatible",
        "api_key_env": None,
        "endpoint": "http://localhost:11434/v1/chat/completions",
        "default_model": "llama3.1",
    },
    "custom": {
        "label": "Custom API",
        "api": "openai-compatible",
        "api_key_env": "CUSTOM_API_KEY",
        "endpoint": "",
        "default_model": "custom-model",
    },
}
COMMAND_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Setup",
        [
            ("add-api", "Configure API credentials in .env and optionally bind judge/generator."),
            ("add-target", "Register a target from a URL or model name."),
            ("validate", "Check config shape and referenced environment variables."),
            ("remove-target", "Remove a target entry from target_config.yaml."),
        ],
    ),
    (
        "Campaign Ops",
        [
            ("healthcheck", "Verify target reachability before longer runs."),
            ("probe", "Profile a target and write its target_profile artifact."),
            ("run", "Launch the autonomous attack loop."),
            ("status", "Review campaign health, scores, and findings."),
            ("serve", "Run the localhost:1337 control plane for evals and risk mapping."),
        ],
    ),
    (
        "Inspection",
        [
            ("targets", "List configured targets and authorization state."),
            ("artifacts", "Show resolved artifact paths for a target."),
            ("preview", "Render the current payload without executing it."),
            ("taxonomy", "Inspect the AgentBreaker and Arc PI taxonomies."),
        ],
    ),
]


def _ansi(code: str) -> str:
    return f"\033[{code}m" if USE_COLOR else ""


def _style(text: str, *codes: str) -> str:
    if not USE_COLOR or not codes:
        return text
    return f"{''.join(_ansi(code) for code in codes)}{text}{_ansi('0')}"


def _terminal_width(default: int = 100) -> int:
    return max(72, shutil.get_terminal_size((default, 24)).columns)


def _divider(char: str = "-") -> str:
    return char * _terminal_width()


class Spinner:
    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Spinner":
        if sys.stdout.isatty():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.2)
        if sys.stdout.isatty():
            print("\r" + " " * min(_terminal_width(), len(self.message) + 8) + "\r", end="", flush=True)

    def _spin(self) -> None:
        idx = 0
        while not self._stop.is_set():
            frame = SPINNER_FRAMES[idx % len(SPINNER_FRAMES)]
            print(f"\r{_style(frame, '36', '1')} {self.message}", end="", flush=True)
            idx += 1
            time.sleep(0.08)


def _load_config(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _save_config(path: Path, config: dict[str, Any]) -> None:
    path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True))


def _dotenv_quote(value: str) -> str:
    if value == "":
        return ""
    if re.fullmatch(r"[A-Za-z0-9_./:@%+,\-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def _upsert_env_var(path: Path, key: str, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text().splitlines() if path.exists() else []
    updated = False
    assign_re = re.compile(rf"^\s*(?:export\s+)?{re.escape(key)}\s*=")
    rendered = f"{key}={_dotenv_quote(value)}"
    for idx, line in enumerate(lines):
        if assign_re.match(line):
            lines[idx] = rendered
            updated = True
            break
    if not updated:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(rendered)
    path.write_text("\n".join(lines) + "\n")


def _mask_secret(value: str | None) -> str:
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


def _prompt_value(label: str, default: str | None = None) -> str:
    default_hint = f" [{default}]" if default not in (None, "") else ""
    raw = input(f"{label}{default_hint}: ").strip()
    return raw if raw else str(default or "")


def _bind_roles(bind: str | None) -> list[str]:
    choice = (bind or "none").lower()
    if choice == "judge":
        return ["judge"]
    if choice == "generator":
        return ["generator"]
    if choice == "both":
        return ["judge", "generator"]
    return []


def _provider_key_from_family(api: str, api_key_env: str | None, endpoint: str | None) -> str:
    if api == "openai" and api_key_env == "OPENAI_API_KEY":
        return "openai"
    if api == "anthropic" and api_key_env == "ANTHROPIC_API_KEY":
        return "anthropic"
    if api == "openai-compatible" and api_key_env == "GOOGLE_API_KEY":
        return "google"
    if api == "openai-compatible" and not api_key_env and endpoint:
        return "local"
    return "custom"


def _engine_block_defaults(config: dict[str, Any], role: str) -> dict[str, Any]:
    block = config.get(role) or {}
    block_cfg = block.get("config") or {}
    return {
        "api": str(block_cfg.get("api", "") or ""),
        "model": str(block_cfg.get("model", "") or ""),
        "api_key_env": block_cfg.get("api_key_env"),
        "endpoint": block_cfg.get("endpoint"),
    }


def _apply_engine_binding(
    config: dict[str, Any],
    *,
    role: str,
    api: str,
    model: str,
    api_key_env: str | None,
    endpoint: str | None,
) -> None:
    block = config.setdefault(role, {})
    block["provider"] = "llm"
    block_cfg = block.setdefault("config", {})
    block_cfg["api"] = api
    block_cfg["model"] = model
    if api_key_env:
        block_cfg["api_key_env"] = api_key_env
    else:
        block_cfg.pop("api_key_env", None)
    if endpoint:
        block_cfg["endpoint"] = endpoint
    else:
        block_cfg.pop("endpoint", None)


def _configured_targets(config: dict[str, Any]) -> list[dict[str, Any]]:
    raw = config.get("targets") or []
    return [item for item in raw if isinstance(item, dict) and item.get("id")]


def _get_target(config: dict[str, Any], target_id: str) -> dict[str, Any] | None:
    for target in _configured_targets(config):
        if target.get("id") == target_id:
            return target
    return None


def _authorization_state(target: dict[str, Any] | None) -> str:
    if not target:
        return "unknown"
    auth = target.get("authorization") or {}
    values = [
        str(auth.get("authorized_by", "") or ""),
        str(auth.get("date", "") or ""),
        str(auth.get("scope", "") or ""),
    ]
    return "placeholder" if any("REPLACE:" in value for value in values) else "configured"


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _artifact_paths(target_id: str, campaign_tag: str | None) -> dict[str, Path]:
    return {
        "root": artifact_root(target_id, campaign_tag),
        "profile": profile_path(target_id, campaign_tag),
        "results": results_path(target_id, campaign_tag),
        "audit_log": audit_log_path(target_id, campaign_tag),
        "planner_log": planner_log_path(target_id, campaign_tag),
        "status": status_path(target_id, campaign_tag),
        "validation_report": validation_report_path(target_id, campaign_tag),
        "ctf_state": ctf_state_path(target_id, campaign_tag),
    }


def _child_env(target_id: str, campaign_tag: str | None, config_path: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    paths = _artifact_paths(target_id, campaign_tag)
    env["AGENTBREAKER_TARGET_ID"] = target_id
    env["AGENTBREAKER_PROFILE_PATH"] = str(paths["profile"])
    env["AGENTBREAKER_AUDIT_LOG"] = str(paths["audit_log"])
    env["AGENTBREAKER_STATUS_FILE"] = str(paths["status"])
    env["AGENTBREAKER_CTF_STATE_PATH"] = str(paths["ctf_state"])
    if campaign_tag:
        env["AGENTBREAKER_CAMPAIGN_TAG"] = campaign_tag
    else:
        env.pop("AGENTBREAKER_CAMPAIGN_TAG", None)
    if config_path is not None:
        env["AGENTBREAKER_CONFIG_PATH"] = str(config_path)
    return env


def _run_passthrough(cmd: list[str], env: dict[str, str]) -> int:
    def _normalized_returncode(code: int | None) -> int:
        if code is None:
            return 130
        if code < 0:
            return 128 + abs(code)
        return code

    proc = subprocess.Popen(cmd, cwd=ROOT, env=env)
    try:
        return _normalized_returncode(proc.wait())
    except KeyboardInterrupt:
        try:
            proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            return _normalized_returncode(proc.wait(timeout=2))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return 130


def _run_capture(cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=False))


def _read_results(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open() as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _finding_counts(target_id: str) -> dict[str, int]:
    counts = {"success": 0, "partial": 0, "novel": 0}
    for bucket in counts:
        directory = FINDINGS_DIR / bucket
        if not directory.exists():
            continue
        for path in directory.rglob("*.yaml"):
            if path.name.lower() == "readme.md":
                continue
            try:
                data = yaml.safe_load(path.read_text()) or {}
            except Exception:
                continue
            finding_target = str(data.get("target_id", "") or data.get("target", "") or "")
            if finding_target == target_id:
                counts[bucket] += 1
    return counts


def _latest_result(rows: list[dict[str, str]]) -> dict[str, str]:
    return rows[-1] if rows else {}


def _status_summary(target_id: str, campaign_tag: str | None, config_path: Path) -> dict[str, Any]:
    config = _load_config(config_path)
    target = _get_target(config, target_id)
    paths = _artifact_paths(target_id, campaign_tag)
    results = _read_results(paths["results"])
    validation = _read_jsonl(paths["validation_report"])
    review_signal = _read_yaml(paths["status"])
    ctf_state = _read_json_file(paths["ctf_state"])
    latest = _latest_result(results)
    keep_count = sum(1 for row in results if row.get("status") == "keep")
    breach_like = sum(
        1 for row in results
        if float(row.get("asr", "0") or 0.0) > 0.0 or float(row.get("vulnerability_score", "0") or 0.0) >= 7.0
    )
    findings = _finding_counts(target_id)
    return {
        "target_id": target_id,
        "campaign_tag": campaign_tag,
        "configured": bool(target),
        "provider": (target or {}).get("provider", "unknown"),
        "authorization": _authorization_state(target),
        "artifacts": {
            name: {
                "path": _relative(path),
                "exists": path.exists(),
            }
            for name, path in paths.items()
        },
        "profile_present": paths["profile"].exists(),
        "results": {
            "count": len(results),
            "keep": keep_count,
            "breach_like": breach_like,
            "latest": latest,
        },
        "validation": {
            "issue_count": len(validation),
            "attack_ids": [entry.get("attack_id", "") for entry in validation[:10]],
        },
        "findings": findings,
        "review_signal": review_signal,
        "ctf": {
            "present": bool(ctf_state),
            "current_challenge": (ctf_state.get("current_challenge") or {}),
            "flag_count": len(ctf_state.get("flags") or []),
            "submitted_flag_count": sum(1 for item in (ctf_state.get("flags") or []) if item.get("submitted")),
            "pending_high_confidence_flags": sum(
                1
                for item in (ctf_state.get("flags") or [])
                if not item.get("submitted") and item.get("confidence") == "high"
            ),
        },
    }


def _logo_block(accent: str = "36") -> str:
    return "\n".join(_style(line, accent, "1") for line in AGENTBREAKER_LOGO)


def _plain_logo_block() -> str:
    return "\n".join(AGENTBREAKER_LOGO)


def _root_help_text() -> str:
    command_width = max(len(name) for _, entries in COMMAND_GROUPS for name, _ in entries) + 2
    lines = [
        _plain_logo_block(),
        "",
        "Autonomous AI red-teaming for authorized targets.",
        "",
        "usage: agentbreaker <command> [options]",
        "",
        "Project Brief",
        "  AgentBreaker profiles AI targets, generates adversarial payloads, executes",
        "  them through an immutable harness, scores outcomes with an independent",
        "  judge model, and stores artifacts for iterative campaigns and review.",
        "",
        "Quick Start",
        "  1. add-api     configure model credentials",
        "  2. add-target  register the target",
        "  3. validate    confirm config and env",
        "  4. probe       map the target surface",
        "  5. run         launch the campaign loop",
        "  6. serve       open the local evaluation control plane",
        "",
        "Command Groups",
    ]
    for group_name, entries in COMMAND_GROUPS:
        lines.append(f"  {group_name}")
        for name, description in entries:
            lines.append(f"    {name.ljust(command_width)}{description}")
        lines.append("")
    lines.extend(
        [
            "Global Options",
            "  -h, --help    show this help message and exit",
            "",
            "Examples",
            "  agentbreaker add-api --provider openai --bind judge --model gpt-5.4",
            "  agentbreaker add-target --url https://promptairlines.com",
            "  agentbreaker validate --check-env",
            "  agentbreaker probe promptairlines --campaign-tag mar16",
            "  agentbreaker run promptairlines --loop --campaign-tag mar16",
            "  agentbreaker serve --host 127.0.0.1 --port 1337",
            "  agentbreaker status promptairlines --campaign-tag mar16",
            "",
            "Use `agentbreaker <command> -h` for command-specific options.",
        ]
    )
    return "\n".join(lines) + "\n"


def _print_cli_launch_banner(
    title: str,
    *,
    target_id: str,
    campaign_tag: str | None,
    config_path: Path,
    mode: str,
    accent: str = "36",
) -> None:
    print(_style(_divider("="), "34"))
    print(_logo_block(accent))
    print(_style(title, accent, "1"))
    print(_style(_divider("-"), "34"))
    print(f"target       : {target_id}")
    print(f"campaign tag : {campaign_tag or 'default'}")
    print(f"config       : {_relative(config_path)}")
    print(f"mode         : {mode}")
    print(_style(_divider("="), "34"))
    print("")
    sys.stdout.flush()


def _project_brief_text() -> str:
    return (
        "Project Brief\n"
        "  AgentBreaker is an autonomous AI red-teaming CLI for authorized testing.\n"
        "  It profiles targets, generates adversarial payloads, executes them through\n"
        "  an immutable harness, scores outcomes with an independent judge model, and\n"
        "  writes reusable artifacts for iterative campaigns.\n"
    )


def _workflow_text() -> str:
    return (
        "Core Workflow\n"
        "  1. add-api     configure judge/generator credentials in .env\n"
        "  2. add-target  register a target from a URL or model name\n"
        "  3. validate    verify config shape and required env vars\n"
        "  4. probe       profile the target and capture its attack surface\n"
        "  5. run         launch the autonomous campaign loop\n"
        "  6. serve       run the local eval and risk-mapping control plane\n"
        "  7. status      inspect scores, findings, and campaign health\n"
    )


def _examples_text() -> str:
    return (
        "Examples\n"
        "  agentbreaker add-api --provider openai --bind judge --model gpt-5.4\n"
        "  agentbreaker add-target --url https://promptairlines.com\n"
        "  agentbreaker validate --check-env\n"
        "  agentbreaker probe promptairlines --campaign-tag mar16\n"
        "  agentbreaker run promptairlines --loop --campaign-tag mar16\n"
        "  agentbreaker serve --host 127.0.0.1 --port 1337\n"
        "  agentbreaker status promptairlines --campaign-tag mar16\n"
    )


class AgentBreakerHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=30, width=min(112, _terminal_width(112)))


class AgentBreakerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        if " " not in self.prog:
            return _root_help_text()
        return super().format_help()


def _cmd_targets(args: argparse.Namespace) -> int:
    config = _load_config(Path(args.config))
    targets = _configured_targets(config)
    if getattr(args, "active_only", False):
        from .config_schema import active_targets
        targets = active_targets(config)
    if args.json:
        payload = []
        for target in targets:
            payload.append(
                {
                    "id": target.get("id"),
                    "provider": target.get("provider", "unknown"),
                    "authorization": _authorization_state(target),
                    "tags": target.get("tags") or [],
                }
            )
        _print_json(payload)
        return 0

    if not targets:
        print("No targets configured." if not getattr(args, "active_only", False) else "No active targets (all have REPLACE: placeholders).")
        return 0

    label = "Active targets" if getattr(args, "active_only", False) else "Configured targets"
    print(f"{label}:\n")
    for target in targets:
        tags = ", ".join(target.get("tags") or [])
        print(
            f"- {target.get('id')} | provider={target.get('provider', 'unknown')} "
            f"| auth={_authorization_state(target)}"
        )
        if tags:
            print(f"  tags: {tags}")
    return 0


def _cmd_healthcheck(args: argparse.Namespace) -> int:
    cmd = [sys.executable, "-m", "agentbreaker.target", "--healthcheck", "--config", str(Path(args.config))]
    if args.target:
        cmd.extend(["--target", args.target])
    env = os.environ.copy()
    return _run_passthrough(cmd, env)


def _cmd_probe(args: argparse.Namespace) -> int:
    target_id = args.target
    config_path = Path(args.config)
    env = _child_env(target_id, args.campaign_tag, config_path)
    output = Path(args.output) if args.output else _artifact_paths(target_id, args.campaign_tag)["profile"]
    cmd = [
        sys.executable,
        "-m", "agentbreaker.target",
        "--probe",
        "--target",
        target_id,
        "--config",
        str(config_path),
        "--output",
        str(output),
    ]
    if args.autonomous:
        cmd.append("--autonomous")
    return _run_passthrough(cmd, env)


def _cmd_run(args: argparse.Namespace) -> int:
    target_id = args.target
    config_path = Path(args.config)
    env = _child_env(target_id, args.campaign_tag, config_path)
    env["AGENTBREAKER_SUPPRESS_DEPRECATION"] = "1"
    mode_bits = []
    if args.loop:
        mode_bits.append("campaign-loop")
    else:
        mode_bits.append("campaign-run")
    if args.dry_run:
        mode_bits.append("dry-run")
    if args.skip_profile:
        mode_bits.append("skip-profile")
    if args.no_planner:
        mode_bits.append("no-planner")
    _print_cli_launch_banner(
        "AGENTBREAKER // RUN",
        target_id=target_id,
        campaign_tag=args.campaign_tag,
        config_path=config_path,
        mode=", ".join(mode_bits),
        accent="36",
    )
    cmd = [
        sys.executable,
        "-m", "agentbreaker.campaign",
        "--target",
        target_id,
        "--config",
        str(config_path),
    ]
    if args.campaign_tag:
        cmd.extend(["--campaign-tag", args.campaign_tag])
    if args.loop:
        cmd.append("--loop")
    if args.max_steps is not None:
        cmd.extend(["--max-steps", str(args.max_steps)])
    if args.skip_profile:
        cmd.append("--skip-profile")
    if args.skip_attack:
        cmd.append("--skip-attack")
    if args.dry_run:
        cmd.append("--dry-run")
    if args.no_planner:
        cmd.append("--no-planner")
    if args.short_prompt:
        cmd.append("--short-prompt")
    rc = _run_passthrough(cmd, env)
    if rc == 130:
        print("[agentbreaker] Run interrupted. Child processes were asked to stop cleanly.")
    return rc


def _cmd_preview(args: argparse.Namespace) -> int:
    target_id = args.target
    config_path = Path(args.config)
    env = _child_env(target_id, args.campaign_tag, config_path)
    env["AGENTBREAKER_ATTACK_ID"] = args.attack_id
    env["AGENTBREAKER_STRATEGY"] = args.strategy
    env["AGENTBREAKER_VARIANT_INDEX"] = str(args.variant_index)
    if args.anchor_payload:
        env["AGENTBREAKER_ANCHOR_PAYLOAD"] = args.anchor_payload

    proc = _run_capture([sys.executable, "-m", "agentbreaker.attack", "--preview"], env)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
        return proc.returncode

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(proc.stdout, end="")
        return 1

    if args.json:
        _print_json(payload)
        return 0

    print(f"attack_id: {payload.get('attack_id', '')}")
    print(f"target_id: {payload.get('target_id', '')}")
    print(f"technique: {payload.get('technique', '')}")
    print(f"modality: {payload.get('modality', 'text')}")
    print(f"media_count: {payload.get('media_count', 0)}")
    if payload.get("seed_sources"):
        print("seed_sources:")
        for source in payload.get("seed_sources", []):
            print(f"- {source}")
    print("payload:")
    print(payload.get("payload_text", ""))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    summary = _status_summary(args.target, args.campaign_tag, Path(args.config))
    if args.json:
        _print_json(summary)
        return 0

    print(f"Target: {summary['target_id']}")
    print(f"Campaign tag: {summary['campaign_tag'] or '(default)'}")
    print(
        f"Provider: {summary['provider']} | configured={summary['configured']} "
        f"| auth={summary['authorization']}"
    )
    print("")
    print("Artifacts:")
    for name, meta in summary["artifacts"].items():
        state = "present" if meta["exists"] else "missing"
        print(f"- {name}: {meta['path']} ({state})")
    print("")
    results = summary["results"]
    latest = results["latest"] or {}
    print(
        "Results: "
        f"count={results['count']} keep={results['keep']} breach_like={results['breach_like']}"
    )
    if latest:
        print(
            "Latest: "
            f"{latest.get('attack_id', '')} "
            f"technique={latest.get('technique', '')} "
            f"status={latest.get('status', '')} "
            f"composite={latest.get('composite_score', '')} "
            f"asr={latest.get('asr', '')}"
        )
    print(
        "Validation: "
        f"{summary['validation']['issue_count']} issue(s)"
    )
    if summary["validation"]["attack_ids"]:
        print("Validation attacks: " + ", ".join(summary["validation"]["attack_ids"]))
    findings = summary["findings"]
    print(
        "Findings: "
        f"success={findings['success']} partial={findings['partial']} novel={findings['novel']}"
    )
    ctf = summary["ctf"]
    if ctf["present"]:
        current = ctf["current_challenge"] or {}
        title = current.get("title", "") or "(unknown)"
        print(
            "CTF state: "
            f"challenge={current.get('id', '?')} {title} "
            f"flags={ctf['flag_count']} submitted={ctf['submitted_flag_count']} "
            f"pending={ctf['pending_high_confidence_flags']}"
        )
    if summary["review_signal"]:
        review = summary["review_signal"]
        print(
            "Review signal: "
            f"{review.get('attack_id', '')} "
            f"composite={review.get('composite_score', '')}"
        )
    return 0


def _cmd_artifacts(args: argparse.Namespace) -> int:
    paths = _artifact_paths(args.target, args.campaign_tag)
    payload = {
        name: {
            "path": _relative(path),
            "exists": path.exists(),
        }
        for name, path in paths.items()
    }
    if args.json:
        _print_json(payload)
        return 0

    print(f"Artifacts for {args.target} ({args.campaign_tag or 'default'}):\n")
    for name, meta in payload.items():
        state = "present" if meta["exists"] else "missing"
        print(f"- {name}: {meta['path']} ({state})")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve_control_plane(host=args.host, port=args.port)
    return 0


# ---------------------------------------------------------------------------
# New commands: add-target, validate, remove-target
# ---------------------------------------------------------------------------

def _cmd_validate(args: argparse.Namespace) -> int:
    """Validate target_config.yaml structure and report issues."""
    from .config_schema import validate_config

    config = _load_config(Path(args.config))
    check_env = getattr(args, "check_env", False)
    errors = validate_config(config, check_env=check_env)

    if args.json:
        _print_json([{"level": e.level, "target_id": e.target_id, "message": e.message} for e in errors])
        return 1 if any(e.level == "error" for e in errors) else 0

    error_count = sum(1 for e in errors if e.level == "error")
    warning_count = sum(1 for e in errors if e.level == "warning")

    if not errors:
        print(_style("✓ Configuration is valid. No warnings detected.", "32", "1"))
        return 0

    if error_count:
        print(_style("✗ Configuration validation failed.", "31", "1"))
    else:
        print(_style("⚠ Configuration is valid, but warnings need review.", "33", "1"))

    grouped = [
        ("error", "Errors", "31"),
        ("warning", "Warnings", "33"),
    ]
    for level, label, color in grouped:
        issues = [e for e in errors if e.level == level]
        if not issues:
            continue
        print(f"\n{_style(label, color, '1')} ({len(issues)})")
        for e in issues:
            prefix = _style(f"[{e.target_id}]", color) + " " if e.target_id else ""
            bullet = _style("●", color)
            print(f"  {bullet} {prefix}{e.message}")

    if warning_count and not error_count:
        print("\nWarnings do not block execution, but they usually indicate broken paths or missing config.")

    summary_color = "31" if error_count else "33"
    print(f"\n{_style('Summary', summary_color, '1')}: {error_count} error(s), {warning_count} warning(s)")
    return 1 if error_count > 0 else 0


def _cmd_add_api(args: argparse.Namespace) -> int:
    """Add or update API credentials in .env and optionally bind engine configs."""
    from .config_schema import detect_model_family

    env_path = Path(getattr(args, "env_file", ENV_FILE_PATH))
    config_path = Path(getattr(args, "config", DEFAULT_CONFIG_PATH))
    config = _load_config(config_path) if config_path.exists() else {}
    interactive = sys.stdin.isatty()

    provider = (getattr(args, "provider", None) or "").strip().lower()
    model = (getattr(args, "model", None) or "").strip()
    bind = getattr(args, "bind", None)
    api = (getattr(args, "api", None) or "").strip()
    endpoint = getattr(args, "endpoint", None)
    env_var = (getattr(args, "env_var", None) or "").strip()
    api_key = getattr(args, "api_key", None)

    detected_family = detect_model_family(model) if model else None
    if not provider and detected_family:
        provider = _provider_key_from_family(
            detected_family.api,
            detected_family.api_key_env,
            detected_family.endpoint,
        )

    if not provider:
        if not interactive:
            print("Provider is required in non-interactive mode. Use --provider openai|anthropic|google|local|custom.")
            return 1
        print("AgentBreaker — Add API\n")
        print("Providers:")
        print("  [1] OpenAI")
        print("  [2] Anthropic")
        print("  [3] Google Gemini")
        print("  [4] Local OpenAI-compatible")
        print("  [5] Custom")
        provider_choice = _prompt_value("Choose provider", "1")
        provider = {
            "1": "openai",
            "2": "anthropic",
            "3": "google",
            "4": "local",
            "5": "custom",
        }.get(provider_choice, provider_choice.lower())

    if provider not in API_PROVIDER_PRESETS:
        print(f"Unsupported provider '{provider}'. Choose one of: {', '.join(API_PROVIDER_PRESETS)}")
        return 1

    preset = dict(API_PROVIDER_PRESETS[provider])
    label = preset["label"]
    if not api:
        api = str(preset.get("api", "") or "")
    if endpoint is None:
        endpoint = preset.get("endpoint")
    if not env_var and preset.get("api_key_env"):
        env_var = str(preset.get("api_key_env") or "")

    if bind is None:
        if interactive:
            bind = _prompt_value("Bind to engine (none/judge/generator/both)", "none").lower()
        else:
            bind = "none"
    roles = _bind_roles(bind)
    if bind not in {"none", "judge", "generator", "both"}:
        print("Bind must be one of: none, judge, generator, both.")
        return 1

    if provider == "custom":
        if not api:
            if not interactive:
                print("Custom provider requires --api openai|anthropic|openai-compatible.")
                return 1
            api = _prompt_value("API backend", "openai-compatible")
        if not env_var:
            if not interactive:
                print("Custom provider requires --env-var NAME.")
                return 1
            env_var = _prompt_value("API key env var", "CUSTOM_API_KEY").upper()
        if api == "openai-compatible" and endpoint in (None, ""):
            if not interactive:
                print("Custom openai-compatible provider requires --endpoint URL.")
                return 1
            endpoint = _prompt_value("Endpoint URL")

    if provider == "local":
        env_var = ""
        api_key = None

    if roles:
        engine_defaults = _engine_block_defaults(config, roles[0])
        default_model = (
            model
            or engine_defaults.get("model")
            or str(preset.get("default_model", "") or "")
        )
        if not model:
            if interactive:
                model = _prompt_value("Model for bound engine(s)", default_model)
            else:
                model = default_model
        if not model:
            print("A model is required when binding judge/generator config. Pass --model or choose interactively.")
            return 1

    if env_var:
        if api_key is None:
            if not interactive:
                print("API key value is required in non-interactive mode. Pass --api-key.")
                return 1
            import getpass

            api_key = getpass.getpass(f"{label} API key ({env_var}): ")
        if not api_key:
            print("API key cannot be empty.")
            return 1
        _upsert_env_var(env_path, env_var, api_key)
        os.environ[env_var] = api_key
        load_dotenv(env_path, override=True)

    if roles:
        for role in roles:
            _apply_engine_binding(
                config,
                role=role,
                api=api,
                model=model,
                api_key_env=env_var or None,
                endpoint=str(endpoint or "") or None,
            )
        _save_config(config_path, config)

    print(f"{_style('✓', '32', '1')} API configuration updated")
    print(f"  provider     : {label}")
    print(f"  backend      : {api}")
    if env_var:
        print(f"  env var      : {env_var}")
        print(f"  stored value : {_mask_secret(api_key)}")
        print(f"  env file     : {_relative(env_path) if env_path.is_absolute() else str(env_path)}")
    else:
        print("  auth         : none required")
    if endpoint:
        print(f"  endpoint     : {endpoint}")
    if roles:
        print(f"  bound roles  : {', '.join(roles)}")
        if (config.get("planner") or {}).get("use_judge_config", False) and "judge" in roles:
            print("  planner      : reuses judge config")
        print(f"  config file  : {_relative(config_path) if config_path.is_absolute() else str(config_path)}")
    else:
        print("  bound roles  : none")
    print("")
    print("Next:")
    print("  agentbreaker validate --check-env")
    print("  agentbreaker --help")
    return 0


def _cmd_add_target(args: argparse.Namespace) -> int:
    """Smart auto-detect wizard for adding targets."""
    from .config_schema import (
        detect_platform,
        detect_model_family,
        generate_platform_target,
        generate_llm_target,
        append_target_to_config,
        generate_target_entry,
    )

    config_path = Path(args.config)
    url = getattr(args, "url", None)
    model = getattr(args, "model", None)

    # Auto-detect flow
    if url:
        match = detect_platform(url)
        if match:
            return _add_target_platform(match, config_path, args)
        else:
            return _add_target_url(url, config_path, args)
    elif model:
        return _add_target_model(model, config_path, args)
    else:
        # Interactive mode
        print("AgentBreaker — Add Target\n")
        choice = input("Enter a URL or model name: ").strip()
        if not choice:
            print("No input provided.")
            return 1
        if choice.startswith("http"):
            match = detect_platform(choice)
            if match:
                return _add_target_platform(match, config_path, args)
            return _add_target_url(choice, config_path, args)
        else:
            return _add_target_model(choice, config_path, args)


def _add_target_platform(match, config_path: Path, args) -> int:
    """Add a known platform target."""
    from .config_schema import generate_platform_target, append_target_to_config

    platform = match.platform
    print(f"\n{_style('✓', '32', '1')} Detected: {match.name}")
    if match.url_fields:
        for k, v in match.url_fields.items():
            print(f"  {k}: {v}")
    print(f"  Provider: {platform['provider']} → {platform.get('script', 'N/A')}")

    # Collect user inputs from prompts
    user_inputs: dict[str, str] = {}
    for prompt_def in platform.get("prompts", []):
        key = prompt_def["key"]
        label = prompt_def.get("label", key)
        default = prompt_def.get("default", "")
        choices = prompt_def.get("choices")
        is_secret = prompt_def.get("secret", False)

        if choices:
            hint = f" ({'/'.join(choices)})"
            default_hint = f" [{default}]" if default else ""
            raw = input(f"  {label}{hint}{default_hint}: ").strip()
            value = raw if raw else str(default)
            if choices and value not in choices:
                print(f"  Warning: '{value}' not in {choices}, using anyway.")
        elif is_secret:
            import getpass
            raw = getpass.getpass(f"  {label}: ")
            value = raw
        else:
            default_hint = f" [{default}]" if default else ""
            raw = input(f"  {label}{default_hint}: ").strip()
            value = raw if raw else str(default)
        if value:
            user_inputs[key] = value

    # Generate and preview the target entry
    entry = generate_platform_target(match, user_inputs=user_inputs)
    tid = entry["id"]

    # Allow ID override
    override = input(f"  Target ID [{tid}]: ").strip()
    if override:
        entry["id"] = override
        tid = override

    # Append to config
    try:
        append_target_to_config(entry, config_path)
    except ValueError as e:
        print(f"\n{_style('✗', '31', '1')} {e}")
        return 1

    print(f"\n{_style('✓', '32', '1')} Added to {config_path}")
    print(f"\nNext: agentbreaker run {tid} --loop")
    return 0


def _add_target_model(model: str, config_path: Path, args) -> int:
    """Add an LLM target from a model name."""
    from .config_schema import detect_model_family, generate_llm_target, append_target_to_config

    family = detect_model_family(model)
    if not family:
        print(f"Could not auto-detect model family for '{model}'.")
        print("Supported patterns: gpt-*, claude-*, gemini-*, llama*, mistral*, etc.")
        return 1

    print(f"\n{_style('✓', '32', '1')} Detected: {family.api} ({model})")
    print(f"  API key env var: {family.api_key_env or 'none (local)'}")
    if family.endpoint:
        print(f"  Endpoint: {family.endpoint}")

    # Collect auth info
    system_prompt = input("  System prompt (Enter to skip): ").strip()
    authorized_by = input("  Authorization — who authorized this test?: ").strip()
    if not authorized_by:
        authorized_by = "Self (internal guardrail assessment)"
    scope = input("  Scope: ").strip()
    if not scope:
        scope = f"Guardrail assessment of {model}"

    tid_default = re.sub(r"[^a-z0-9-]", "-", model.lower()).strip("-")
    tid = input(f"  Target ID [{tid_default}]: ").strip() or tid_default

    entry = generate_llm_target(
        model=model,
        family=family,
        system_prompt=system_prompt,
        authorized_by=authorized_by,
        scope=scope,
        target_id=tid,
    )

    try:
        append_target_to_config(entry, config_path)
    except ValueError as e:
        print(f"\n{_style('✗', '31', '1')} {e}")
        return 1

    print(f"\n{_style('✓', '32', '1')} Added to {config_path}")
    print(f"\nNext: agentbreaker probe {tid} --campaign-tag <tag>")
    return 0


def _add_target_url(url: str, config_path: Path, args) -> int:
    """Add a generic URL target (HTTP or browser)."""
    from .config_schema import generate_target_entry, append_target_to_config

    print(f"\n? Not a recognized platform. What type of target is this?")
    print("  [1] HTTP/REST endpoint (POST JSON, get JSON back)")
    print("  [2] Web chat UI (needs a browser)")
    print("  [3] Custom script")
    choice = input("  Choice [1]: ").strip() or "1"

    provider_map = {"1": "http", "2": "browser", "3": "script"}
    provider = provider_map.get(choice, "http")

    authorized_by = input("  Authorization — who authorized?: ").strip()
    if not authorized_by:
        authorized_by = "Self"
    scope = input("  Scope: ").strip() or f"Security assessment of {url}"

    tid_default = re.sub(r"https?://", "", url).split("/")[0].replace(".", "-")
    tid = input(f"  Target ID [{tid_default}]: ").strip() or tid_default

    config: dict = {}
    if provider == "http":
        config = {
            "url": url,
            "method": "POST",
            "request_transform": '{"message": "{{ payload.text }}"}',
            "response_extract": '{"text": response.get("content", "")}',
            "success_condition": "len(extracted['text']) > 50",
            "timeout_seconds": 30,
        }
    elif provider == "browser":
        config = {
            "script": f"providers/{tid}_browser.py",
            "headless": True,
            "timeout_seconds": 60,
            "env": {"TARGET_URL": url},
        }
    elif provider == "script":
        script_path = input("  Script path (providers/...): ").strip()
        config = {
            "script": script_path or f"providers/{tid}.py",
            "timeout_seconds": 45,
        }

    entry = generate_target_entry(
        target_id=tid,
        provider=provider,
        authorized_by=authorized_by,
        scope=scope,
        config=config,
    )

    try:
        append_target_to_config(entry, config_path)
    except ValueError as e:
        print(f"\n{_style('✗', '31', '1')} {e}")
        return 1

    print(f"\n{_style('✓', '32', '1')} Added to {config_path}")
    print(f"\nNext: agentbreaker healthcheck {tid}")
    return 0


def _cmd_remove_target(args: argparse.Namespace) -> int:
    """Remove a target entry from target_config.yaml."""
    from .config_schema import remove_target_from_config

    config_path = Path(args.config)
    target_id = args.target

    # Check for existing artifacts
    paths = _artifact_paths(target_id, None)
    has_artifacts = paths["root"].exists()
    has_findings = False
    for tier in ("success", "partial", "novel"):
        directory = FINDINGS_DIR / tier
        if not directory.exists():
            continue
        for path in directory.rglob("*.yaml"):
            if path.name.lower() == "readme.md":
                continue
            try:
                data = yaml.safe_load(path.read_text()) or {}
            except Exception:
                continue
            finding_target = str(data.get("target_id", "") or data.get("target", "") or "")
            if finding_target == target_id:
                has_findings = True
                break
        if has_findings:
            break

    if has_artifacts:
        print(f"⚠  Target '{target_id}' has artifacts at {_relative(paths['root'])}")
    if has_findings:
        print(f"⚠  Target '{target_id}' has findings in findings/")

    if not getattr(args, "confirm", False):
        confirm = input(f"Remove target '{target_id}' from config? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Cancelled.")
            return 0

    removed = remove_target_from_config(target_id, config_path)
    if removed:
        print(f"{_style('✓', '32', '1')} Removed '{target_id}' from {config_path}")
        if has_artifacts:
            print(f"  Note: artifacts at {_relative(paths['root'])} were NOT deleted.")
    else:
        print(f"Target '{target_id}' not found in {config_path}.")
        return 1
    return 0


def _cmd_db_import(args: argparse.Namespace) -> int:
    """Import an existing flat-file campaign into campaign.db."""
    from . import db as _db
    from .artifact_paths import artifact_root, audit_log_path, planner_log_path, results_path

    aroot = artifact_root(args.target, args.tag or None)
    db_path = aroot / "campaign.db"
    tsv = results_path(args.target, args.tag or None)
    jsonl = audit_log_path(args.target, args.tag or None)
    planner = planner_log_path(args.target, args.tag or None)

    if not tsv.exists() and not jsonl.exists():
        print(f"No flat-file artifacts found at {aroot}")
        return 1

    print(f"Importing into {db_path} ...")
    conn = _db.open_db(db_path)
    counts = _db.import_flat_files(
        conn,
        results_tsv=tsv,
        audit_jsonl=jsonl,
        planner_jsonl=planner if planner.exists() else None,
        campaign_tag=args.tag or "",
    )
    conn.close()
    print(
        f"Done.  attacks={counts['attacks']}  trials={counts['trials']}  "
        f"planner_decisions={counts['planner_decisions']}"
    )
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """Tail results.tsv and pretty-print new rows as they appear."""
    results_path = ROOT / "results.tsv"
    if not results_path.exists():
        print(_style("No results.tsv found yet. Start a campaign first.", "33"))
        return 1

    import csv as _csv

    def _read_rows() -> list[dict[str, str]]:
        with results_path.open() as fh:
            return list(_csv.DictReader(fh, delimiter="\t"))

    seen = len(_read_rows())
    print(f"[watch] Watching {results_path.relative_to(ROOT)} ({seen} existing rows)")
    print(f"[watch] Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1.5)
            rows = _read_rows()
            if len(rows) > seen:
                for row in rows[seen:]:
                    comp = float(row.get("composite", 0))
                    comp_color = "32" if comp >= 8 else ("33" if comp >= 5 else "2")
                    breach = row.get("breach_detected", "").lower() == "true"
                    breach_str = _style("BREACH", "1;32") if breach else "no"
                    status = row.get("status", "unknown")
                    print(
                        f"  {_style(row.get('attack_id', '?'), '1')} "
                        f"{row.get('technique', '?')} | "
                        f"composite={_style(f'{comp:.2f}', comp_color)} "
                        f"breach={breach_str} status={status}"
                    )
                seen = len(rows)
    except KeyboardInterrupt:
        print(f"\n[watch] Stopped. {seen} total rows in results.tsv.")
    return 0


def _cmd_taxonomy(args: argparse.Namespace) -> int:
    # Unified view: if --strategies or a category name given, use taxonomy_loader
    show_strategies = getattr(args, "strategies", False)
    category_arg = getattr(args, "category", None)
    use_arc = getattr(args, "arc", False)

    if show_strategies or (category_arg and not use_arc):
        return _cmd_taxonomy_unified(args, category_arg=category_arg, show_strategies=show_strategies)

    source = arc_taxonomy_source()
    counts = arc_taxonomy_counts()
    dimension = args.dimension or None
    limit = args.limit if args.limit and args.limit > 0 else (10 if args.query else None)
    if args.query and not use_arc:
        # Search both taxonomies
        from .taxonomy_loader import search_taxonomy as unified_search
        results = unified_search(args.query, dimension=dimension)
        if results:
            print(f"Unified search for {args.query!r}:\n")
            for r in results[: (limit or 20)]:
                if r["type"] == "category":
                    print(f"  [{_style('category', '36')}] {r['id']}: {r['description']}")
                elif r["type"] == "subcategory":
                    print(f"  [{_style('subcategory', '33')}] {r['id']}: {r['description']}")
                    print(f"    strategies: {', '.join(r.get('strategies', []))}")
                elif r["type"] == "arc_entry":
                    print(f"  [{_style('arc:' + r['dimension'], '35')}] {r['id']}: {r.get('title', '')}")
            return 0

    if args.query:
        entries = search_arc_taxonomy(args.query, dimension=dimension, limit=limit or 10)
    else:
        entries = arc_taxonomy_entries(dimension)
        if limit:
            entries = entries[:limit]

    payload = {
        "source": source,
        "counts": counts,
        "dimension": dimension,
        "query": args.query or "",
        "entries": entries,
    }
    if args.json:
        _print_json(payload)
        return 0

    print(source.get("name", "Arc PI Taxonomy"))
    print(
        f"Source: {source.get('url', '')} | version={source.get('version', 'unknown')}"
    )
    print(
        "Counts: "
        + ", ".join(f"{name}={counts.get(name, 0)}" for name in ARC_DIMENSION_ORDER)
    )
    print("")
    if args.query:
        header = f"Matches for {args.query!r}"
        if dimension:
            header += f" in {dimension}"
        print(header + ":")
    elif dimension:
        print(f"{dimension}:")
    else:
        print("All taxonomy entries:")
    for entry in entries:
        print(
            f"- [{entry.get('dimension', dimension or '?')}] "
            f"{entry.get('id', '')} | {entry.get('path_text') or entry.get('title', '')}"
        )
        if args.verbose and entry.get("description"):
            print(f"  {entry.get('description', '')}")
    if not entries:
        print("(no entries)")
    return 0


def _cmd_taxonomy_unified(args: argparse.Namespace, *, category_arg: str | None, show_strategies: bool) -> int:
    """Show unified AgentBreaker taxonomy (categories, subcategories, strategies)."""
    from .taxonomy_loader import load_taxonomy, get_strategies_for_category, load_strategy_index

    taxonomy = load_taxonomy()

    if show_strategies:
        idx = load_strategy_index()
        if args.json:
            _print_json({s: {"categories": m.categories, "primary": m.primary_category} for s, m in idx.items()})
            return 0
        print("Strategy → Category Mapping:\n")
        for strat_id, mapping in idx.items():
            cats = ", ".join(mapping.categories)
            print(f"  {_style(strat_id, '1')}: {cats} (primary: {mapping.primary_category})")
        return 0

    if category_arg:
        cat = taxonomy.get(category_arg)
        if not cat:
            print(f"Unknown category: {category_arg}")
            print(f"Available: {', '.join(taxonomy.keys())}")
            return 1
        if args.json:
            payload = {
                "id": cat.id,
                "owasp": cat.owasp,
                "difficulty": list(cat.difficulty),
                "benchmarks": cat.benchmarks,
                "description": cat.description,
                "subcategories": {
                    sid: {
                        "description": s.description,
                        "seeds": s.seeds,
                        "arc_techniques": s.arc_techniques,
                        "arc_evasions": s.arc_evasions,
                        "strategies": s.strategies,
                        "requires": s.requires,
                    }
                    for sid, s in cat.subcategories.items()
                },
            }
            _print_json(payload)
            return 0
        print(f"\n{_style(cat.id, '1', '36')} — {cat.description}")
        print(f"  OWASP: {', '.join(cat.owasp)} | Difficulty: {cat.difficulty[0]}-{cat.difficulty[1]}")
        print(f"  Benchmarks: {', '.join(cat.benchmarks)}")
        if cat.requires:
            print(f"  Requires: {cat.requires}")
        print(f"\n  Subcategories:")
        for sid, sub in cat.subcategories.items():
            print(f"\n    {_style(sid, '33')}: {sub.description}")
            if sub.requires:
                print(f"      requires: {sub.requires}")
            if sub.seeds:
                print(f"      seeds: {', '.join(sub.seeds)}")
            if sub.strategies:
                print(f"      strategies: {', '.join(sub.strategies)}")
            if sub.arc_techniques:
                print(f"      arc_techniques: {', '.join(sub.arc_techniques)}")
            if sub.arc_evasions:
                print(f"      arc_evasions: {', '.join(sub.arc_evasions)}")
        return 0

    # Default: show all categories with subcategory counts
    if args.json:
        payload = {
            cid: {
                "description": c.description,
                "owasp": c.owasp,
                "subcategory_count": len(c.subcategories),
                "strategy_count": len(get_strategies_for_category(cid)),
            }
            for cid, c in taxonomy.items()
        }
        _print_json(payload)
        return 0
    print("AgentBreaker Attack Taxonomy\n")
    print(f"{'Category':<28} {'OWASP':<14} {'Subs':>4} {'Strats':>6}  Description")
    print("-" * 100)
    for cid, cat in taxonomy.items():
        owasp = ", ".join(cat.owasp)
        strats = len(get_strategies_for_category(cid))
        print(f"{cid:<28} {owasp:<14} {len(cat.subcategories):>4} {strats:>6}  {cat.description[:50]}")
    print(f"\n{len(taxonomy)} categories. Use `taxonomy <category>` for details.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = AgentBreakerArgumentParser(
        prog="agentbreaker",
        description="Unified CLI for AgentBreaker profiling, campaign runs, previews, and artifact inspection.",
        epilog="\n".join([
            _project_brief_text(),
            _workflow_text(),
            _examples_text(),
            "Use `agentbreaker <command> -h` for command-specific options.",
        ]),
        formatter_class=AgentBreakerHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    p_targets = subparsers.add_parser("targets", help="List configured targets.")
    p_targets.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_targets.add_argument("--json", action="store_true")
    p_targets.add_argument("--active-only", action="store_true", help="Hide targets with REPLACE: placeholders.")
    p_targets.set_defaults(func=_cmd_targets)

    p_health = subparsers.add_parser("healthcheck", help="Run harness health checks.")
    p_health.add_argument("target", nargs="?", help="Optional target id. Omit to check all configured targets.")
    p_health.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_health.set_defaults(func=_cmd_healthcheck)

    p_probe = subparsers.add_parser("probe", help="Profile a target and write its target profile.")
    p_probe.add_argument("target", help="Target id from target_config.yaml")
    p_probe.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_probe.add_argument("--campaign-tag", help="Optional artifact namespace under artifacts/<target>/<tag>/")
    p_probe.add_argument("--output", help="Override the profile output path.")
    p_probe.add_argument("--autonomous", action="store_true", help="Continue directly into the campaign runner after profiling.")
    p_probe.set_defaults(func=_cmd_probe)

    p_run = subparsers.add_parser("run", help="Run the autonomous campaign loop.")
    p_run.add_argument("target", help="Target id from target_config.yaml")
    p_run.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_run.add_argument("--campaign-tag", help="Optional artifact namespace under artifacts/<target>/<tag>/")
    p_run.add_argument("--loop", action="store_true", help="Keep running attack iterations until interrupted.")
    p_run.add_argument("--max-steps", type=int, help="Maximum number of attack iterations for this invocation.")
    p_run.add_argument("--skip-profile", action="store_true", help="Reuse the existing target profile.")
    p_run.add_argument("--skip-attack", action="store_true", help="Stop after profiling.")
    p_run.add_argument("--dry-run", action="store_true", help="Show what would run without executing it.")
    p_run.add_argument("--no-planner", action="store_true", help="Disable the LLM planner for this run.")
    p_run.add_argument("--short-prompt", action="store_true", help="Use short single-sentence prompts (better for CTFs with input length limits).")
    p_run.set_defaults(func=_cmd_run)

    p_preview = subparsers.add_parser("preview", help="Render the current attack payload without executing it.")
    p_preview.add_argument("target", help="Target id from target_config.yaml")
    p_preview.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_preview.add_argument("--campaign-tag", help="Optional artifact namespace under artifacts/<target>/<tag>/")
    p_preview.add_argument("--strategy", default="completion_attack")
    p_preview.add_argument("--variant-index", type=int, default=0)
    p_preview.add_argument("--attack-id", default="ATK-PREVIEW")
    p_preview.add_argument("--anchor-payload", default="")
    p_preview.add_argument("--json", action="store_true")
    p_preview.set_defaults(func=_cmd_preview)

    p_status = subparsers.add_parser("status", help="Summarize campaign state, artifacts, and validation issues.")
    p_status.add_argument("target", help="Target id from target_config.yaml")
    p_status.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_status.add_argument("--campaign-tag", help="Optional artifact namespace under artifacts/<target>/<tag>/")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=_cmd_status)

    p_serve = subparsers.add_parser("serve", help="Run the localhost control plane for evals, coverage, and risk mapping.")
    p_serve.add_argument("--host", default="127.0.0.1", help="Interface to bind. Default: 127.0.0.1")
    p_serve.add_argument("--port", type=int, default=1337, help="Port to bind. Default: 1337")
    p_serve.set_defaults(func=_cmd_serve)

    p_artifacts = subparsers.add_parser("artifacts", help="Show the resolved artifact paths for a target.")
    p_artifacts.add_argument("target", help="Target id from target_config.yaml")
    p_artifacts.add_argument("--campaign-tag", help="Optional artifact namespace under artifacts/<target>/<tag>/")
    p_artifacts.add_argument("--json", action="store_true")
    p_artifacts.set_defaults(func=_cmd_artifacts)

    p_taxonomy = subparsers.add_parser("taxonomy", help="Inspect the attack taxonomy (unified + Arc PI).")
    p_taxonomy.add_argument("category", nargs="?", help="Show details for a specific category (e.g., prompt_injection).")
    p_taxonomy.add_argument("--arc", action="store_true", help="Show Arc PI taxonomy only.")
    p_taxonomy.add_argument("--strategies", action="store_true", help="List all strategies with their category mappings.")
    p_taxonomy.add_argument("--dimension", choices=list(ARC_DIMENSION_ORDER))
    p_taxonomy.add_argument("--query", help="Search the taxonomy by keyword.")
    p_taxonomy.add_argument("--limit", type=int, default=0, help="Limit the number of returned entries.")
    p_taxonomy.add_argument("--verbose", action="store_true", help="Show entry descriptions.")
    p_taxonomy.add_argument("--json", action="store_true")
    p_taxonomy.set_defaults(func=_cmd_taxonomy)

    # --- New commands ---

    p_validate = subparsers.add_parser("validate", help="Validate target_config.yaml structure.")
    p_validate.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_validate.add_argument("--check-env", action="store_true", help="Also check that referenced env vars are set.")
    p_validate.add_argument("--json", action="store_true")
    p_validate.set_defaults(func=_cmd_validate)

    p_api = subparsers.add_parser("add-api", aliases=["api"], help="Add/update API credentials in .env and optionally bind judge/generator.")
    p_api.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_api.add_argument("--env-file", default=str(ENV_FILE_PATH), help="Path to the .env file to write.")
    p_api.add_argument("--provider", choices=list(API_PROVIDER_PRESETS), help="Preset provider profile.")
    p_api.add_argument("--model", help="Model name to bind for judge/generator.")
    p_api.add_argument("--api", choices=["openai", "anthropic", "openai-compatible"], help="Override the backend API.")
    p_api.add_argument("--endpoint", help="Custom endpoint for openai-compatible or custom providers.")
    p_api.add_argument("--env-var", help="Env var name used to store the API key.")
    p_api.add_argument("--api-key", help="API key value. If omitted, prompts securely.")
    p_api.add_argument("--bind", choices=["none", "judge", "generator", "both"], help="Optionally bind the provider to judge/generator config.")
    p_api.set_defaults(func=_cmd_add_api)

    p_add = subparsers.add_parser("add-target", help="Add a new target via smart auto-detect wizard.")
    p_add.add_argument("--url", help="URL of the target (CTF platform, HTTP endpoint, etc.).")
    p_add.add_argument("--model", help="Model name for LLM targets (e.g., gpt-4o, claude-opus-4).")
    p_add.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_add.set_defaults(func=_cmd_add_target)

    p_remove = subparsers.add_parser("remove-target", help="Remove a target from config.")
    p_remove.add_argument("target", help="Target id to remove.")
    p_remove.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    p_remove.add_argument("--confirm", action="store_true", help="Skip confirmation prompt.")
    p_remove.set_defaults(func=_cmd_remove_target)

    p_watch = subparsers.add_parser("watch", help="Live-tail results.tsv and pretty-print new attack results.")
    p_watch.set_defaults(func=_cmd_watch)

    p_db = subparsers.add_parser("db", help="Campaign database utilities.")
    db_sub = p_db.add_subparsers(dest="db_command")
    p_db_import = db_sub.add_parser(
        "import",
        help="Import an existing flat-file campaign (results.tsv + attack_log.jsonl) into campaign.db.",
    )
    p_db_import.add_argument("--target", required=True, help="Target ID (e.g. gpt-5.4)")
    p_db_import.add_argument("--tag", default="", help="Campaign tag (e.g. mar-17-v5)")
    p_db_import.set_defaults(func=_cmd_db_import)

    return parser


def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit(0)
    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        raise SystemExit(1)
    try:
        raise SystemExit(args.func(args))
    except KeyboardInterrupt:
        print("\n[agentbreaker] Interrupted by user. Exiting cleanly.")
        raise SystemExit(130)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agentbreaker] Interrupted by user. Exiting cleanly.")
        raise SystemExit(130)
