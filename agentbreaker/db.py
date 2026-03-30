"""
db.py — SQLite campaign database for AgentBreaker.

Stores attacks, trials, and planner decisions in a per-campaign SQLite
database at {artifact_root}/campaign.db.

Flat files (results.tsv, attack_log.jsonl, planner_log.jsonl) are kept as
backup/export formats.  This module is the primary operational store and the
foundation for future web/API push.

Schema versioning: increment SCHEMA_VERSION and add a migration block in
_migrate() whenever the schema changes.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def open_db(db_path: Path) -> sqlite3.Connection:
    """Open (and migrate if needed) the campaign database at *db_path*."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if user_version >= SCHEMA_VERSION:
        return

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS attacks (
            attack_id         TEXT PRIMARY KEY,
            target_id         TEXT NOT NULL,
            campaign_tag      TEXT NOT NULL DEFAULT '',
            category          TEXT,
            technique         TEXT,
            owasp_ref         TEXT,
            benchmark_ref     TEXT,
            description       TEXT,
            status            TEXT,
            commit_ref        TEXT,
            vulnerability     REAL,
            novelty           REAL,
            reliability       REAL,
            composite         REAL,
            asr               REAL,
            breach_detected   INTEGER DEFAULT 0,
            partial_leak      INTEGER DEFAULT 0,
            response_gradient REAL    DEFAULT 0.0,
            failure_mode      TEXT,
            response_cluster  TEXT,
            recommended_next  TEXT,
            combo_with        TEXT,
            combo_reason      TEXT,
            judge_reasoning   TEXT,
            finding_tier      TEXT,
            finding_path      TEXT,
            created_at        TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_attacks_target
            ON attacks(target_id, campaign_tag);

        CREATE TABLE IF NOT EXISTS trials (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id        TEXT    NOT NULL,
            target_id        TEXT    NOT NULL,
            trial_num        INTEGER,
            ts               TEXT,
            modality         TEXT,
            payload_text     TEXT,
            payload_messages TEXT,
            response_text    TEXT,
            breach_hint      INTEGER DEFAULT 0,
            error            TEXT,
            scores           TEXT,
            metadata         TEXT,
            FOREIGN KEY (attack_id) REFERENCES attacks(attack_id)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_trials_unique
            ON trials(attack_id, trial_num);
        CREATE INDEX IF NOT EXISTS idx_trials_attack
            ON trials(attack_id);

        CREATE TABLE IF NOT EXISTS planner_decisions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT,
            target_id TEXT,
            attack_id TEXT,
            plan      TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_planner_attack
            ON planner_decisions(attack_id);
    """)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def upsert_attack(
    conn: sqlite3.Connection,
    result: dict[str, Any],
    status: str,
    commit_ref: str,
    campaign_tag: str = "",
    finding_tier: str | None = None,
    finding_path: str | None = None,
) -> None:
    """Insert or update an attack row from a campaign result dict."""
    conn.execute(
        """
        INSERT INTO attacks (
            attack_id, target_id, campaign_tag, category, technique,
            owasp_ref, benchmark_ref, description, status, commit_ref,
            vulnerability, novelty, reliability, composite, asr,
            breach_detected, partial_leak, response_gradient,
            failure_mode, response_cluster, recommended_next,
            combo_with, combo_reason, judge_reasoning,
            finding_tier, finding_path, created_at
        ) VALUES (
            :attack_id, :target_id, :campaign_tag, :category, :technique,
            :owasp_ref, :benchmark_ref, :description, :status, :commit_ref,
            :vulnerability, :novelty, :reliability, :composite, :asr,
            :breach_detected, :partial_leak, :response_gradient,
            :failure_mode, :response_cluster, :recommended_next,
            :combo_with, :combo_reason, :judge_reasoning,
            :finding_tier, :finding_path, :created_at
        )
        ON CONFLICT(attack_id) DO UPDATE SET
            status            = excluded.status,
            commit_ref        = excluded.commit_ref,
            vulnerability     = excluded.vulnerability,
            novelty           = excluded.novelty,
            reliability       = excluded.reliability,
            composite         = excluded.composite,
            asr               = excluded.asr,
            breach_detected   = excluded.breach_detected,
            partial_leak      = excluded.partial_leak,
            response_gradient = excluded.response_gradient,
            failure_mode      = excluded.failure_mode,
            response_cluster  = excluded.response_cluster,
            recommended_next  = excluded.recommended_next,
            combo_with        = excluded.combo_with,
            combo_reason      = excluded.combo_reason,
            judge_reasoning   = excluded.judge_reasoning,
            finding_tier      = COALESCE(excluded.finding_tier, finding_tier),
            finding_path      = COALESCE(excluded.finding_path, finding_path)
        """,
        {
            "attack_id":        result["attack_id"],
            "target_id":        result.get("target_id", ""),
            "campaign_tag":     campaign_tag,
            "category":         result.get("category", ""),
            "technique":        result.get("technique", ""),
            "owasp_ref":        result.get("owasp_ref", ""),
            "benchmark_ref":    result.get("benchmark_ref", ""),
            "description":      result.get("description", ""),
            "status":           status,
            "commit_ref":       commit_ref,
            "vulnerability":    float(result.get("vulnerability", 0.0)),
            "novelty":          float(result.get("novelty", 0.0)),
            "reliability":      float(result.get("reliability", 0.0)),
            "composite":        float(result.get("composite", 0.0)),
            "asr":              float(result.get("asr", 0.0)),
            "breach_detected":  int(bool(result.get("breach_detected"))),
            "partial_leak":     int(bool(result.get("partial_leak_detected"))),
            "response_gradient": float(result.get("response_gradient", 0.0)),
            "failure_mode":     result.get("failure_mode", ""),
            "response_cluster": result.get("response_cluster", ""),
            "recommended_next": result.get("recommended_next_family", ""),
            "combo_with":       result.get("combo_with", ""),
            "combo_reason":     result.get("combo_reason", ""),
            "judge_reasoning":  result.get("judge_reasoning", ""),
            "finding_tier":     finding_tier,
            "finding_path":     finding_path,
            "created_at":       result.get("timestamp", ""),
        },
    )
    conn.commit()


def update_finding(
    conn: sqlite3.Connection,
    attack_id: str,
    tier: str,
    path: str,
) -> None:
    """Set the finding tier and path on an existing attack row."""
    conn.execute(
        "UPDATE attacks SET finding_tier = ?, finding_path = ? WHERE attack_id = ?",
        (tier, path, attack_id),
    )
    conn.commit()


def insert_planner_decision(
    conn: sqlite3.Connection,
    ts: str,
    target_id: str,
    attack_id: str,
    plan: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT INTO planner_decisions (ts, target_id, attack_id, plan) VALUES (?, ?, ?, ?)",
        (ts, target_id, attack_id, json.dumps(plan, ensure_ascii=False)),
    )
    conn.commit()


def sync_trials_from_log(
    conn: sqlite3.Connection,
    attack_id: str,
    log_path: Path,
) -> int:
    """
    Read *log_path* (JSONL) and insert any trials for *attack_id* that are not
    already in the database.  Returns the number of rows inserted.

    Safe to call multiple times — uses INSERT OR IGNORE.
    """
    if not log_path.exists():
        return 0

    inserted = 0
    for line in log_path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("attack_id") != attack_id:
            continue

        payload = entry.get("payload") or {}
        response = entry.get("response") or {}
        scores = entry.get("scores")
        metadata = (response.get("metadata") or {}) if isinstance(response, dict) else {}

        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO trials (
                    attack_id, target_id, trial_num, ts, modality,
                    payload_text, payload_messages, response_text,
                    breach_hint, error, scores, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack_id,
                    str(entry.get("target", "")),
                    entry.get("trial"),
                    entry.get("ts", ""),
                    entry.get("modality", ""),
                    str(payload.get("text", "") if isinstance(payload, dict) else ""),
                    json.dumps(payload.get("messages") or [], ensure_ascii=False),
                    str(response.get("extracted", "") if isinstance(response, dict) else ""),
                    int(bool(response.get("breach_hint") if isinstance(response, dict) else False)),
                    str(response.get("error", "") or "" if isinstance(response, dict) else ""),
                    json.dumps(scores, ensure_ascii=False) if scores is not None else None,
                    json.dumps(metadata, ensure_ascii=False) if metadata else None,
                ),
            )
            inserted += conn.execute("SELECT changes()").fetchone()[0]
        except sqlite3.Error:
            continue

    if inserted:
        conn.commit()
    return inserted


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_attack_ids(
    conn: sqlite3.Connection,
    target_id: str,
    campaign_tag: str = "",
) -> set[str]:
    """Return the set of attack_ids already recorded for this campaign."""
    rows = conn.execute(
        "SELECT attack_id FROM attacks WHERE target_id = ? AND campaign_tag = ?",
        (target_id, campaign_tag),
    ).fetchall()
    return {row["attack_id"] for row in rows}


# ---------------------------------------------------------------------------
# Migration: import existing flat files into the DB
# ---------------------------------------------------------------------------

def import_flat_files(
    conn: sqlite3.Connection,
    *,
    results_tsv: Path,
    audit_jsonl: Path,
    planner_jsonl: Path | None = None,
    campaign_tag: str = "",
) -> dict[str, int]:
    """
    Import an existing flat-file campaign into *conn*.

    Returns a dict with counts of rows imported per table.
    Safe to call on a DB that already has some rows (uses INSERT OR IGNORE /
    ON CONFLICT DO NOTHING).
    """
    counts: dict[str, int] = {"attacks": 0, "trials": 0, "planner_decisions": 0}

    # -- attacks from results.tsv ----------------------------------------
    if results_tsv.exists():
        with results_tsv.open() as fh:
            for row in csv.DictReader(fh, delimiter="\t"):
                attack_id = row.get("attack_id", "").strip()
                if not attack_id:
                    continue
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO attacks (
                            attack_id, target_id, campaign_tag, category,
                            technique, owasp_ref, benchmark_ref, description,
                            status, commit_ref, vulnerability, novelty,
                            reliability, composite, asr, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            attack_id,
                            row.get("target_model", ""),
                            campaign_tag,
                            row.get("category", ""),
                            row.get("technique", ""),
                            row.get("owasp_ref", ""),
                            row.get("benchmark_ref", ""),
                            row.get("description", ""),
                            row.get("status", ""),
                            row.get("commit", ""),
                            float(row.get("vulnerability_score") or 0),
                            float(row.get("novelty_score") or 0),
                            float(row.get("reliability_score") or 0),
                            float(row.get("composite_score") or 0),
                            float(row.get("asr") or 0),
                            "",
                        ),
                    )
                    counts["attacks"] += conn.execute("SELECT changes()").fetchone()[0]
                except (sqlite3.Error, ValueError):
                    continue
        conn.commit()

    # -- trials from attack_log.jsonl ------------------------------------
    if audit_jsonl.exists():
        for line in audit_jsonl.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            attack_id = entry.get("attack_id", "")
            if not attack_id:
                continue
            payload = entry.get("payload") or {}
            response = entry.get("response") or {}
            scores = entry.get("scores")
            metadata = response.get("metadata") or {} if isinstance(response, dict) else {}
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO trials (
                        attack_id, target_id, trial_num, ts, modality,
                        payload_text, payload_messages, response_text,
                        breach_hint, error, scores, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attack_id,
                        str(entry.get("target", "")),
                        entry.get("trial"),
                        entry.get("ts", ""),
                        entry.get("modality", ""),
                        str(payload.get("text", "") if isinstance(payload, dict) else ""),
                        json.dumps(payload.get("messages") or [] if isinstance(payload, dict) else []),
                        str(response.get("extracted", "") if isinstance(response, dict) else ""),
                        int(bool(response.get("breach_hint") if isinstance(response, dict) else False)),
                        str(response.get("error") or "" if isinstance(response, dict) else ""),
                        json.dumps(scores) if scores is not None else None,
                        json.dumps(metadata) if metadata else None,
                    ),
                )
                counts["trials"] += conn.execute("SELECT changes()").fetchone()[0]
            except (sqlite3.Error, ValueError):
                continue
        conn.commit()

    # -- planner decisions from planner_log.jsonl ------------------------
    if planner_jsonl and planner_jsonl.exists():
        for line in planner_jsonl.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                conn.execute(
                    "INSERT INTO planner_decisions (ts, target_id, attack_id, plan) VALUES (?, ?, ?, ?)",
                    (
                        entry.get("ts", ""),
                        entry.get("target", ""),
                        entry.get("attack_id", ""),
                        json.dumps(entry.get("plan") or {}, ensure_ascii=False),
                    ),
                )
                counts["planner_decisions"] += 1
            except sqlite3.Error:
                continue
        conn.commit()

    return counts
