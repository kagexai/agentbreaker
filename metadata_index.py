from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from artifact_paths import ROOT
from response_analysis import is_low_signal_response, response_cluster

METADATA_DB_PATH = ROOT / "artifacts" / "metadata.sqlite3"
_DB_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _open_db() -> sqlite3.Connection:
    METADATA_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(METADATA_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_counts (
          target_id TEXT PRIMARY KEY,
          success_count INTEGER NOT NULL DEFAULT 0,
          partial_count INTEGER NOT NULL DEFAULT 0,
          novel_count INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS finding_records (
          finding_path TEXT PRIMARY KEY,
          target_id TEXT NOT NULL,
          bucket TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS target_experiment_stats (
          target_id TEXT PRIMARY KEY,
          experiment_count INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS target_low_signal_clusters (
          target_id TEXT NOT NULL,
          cluster TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (target_id, cluster)
        );
        """
    )
    return conn


def _upsert_target_row(conn: sqlite3.Connection, target_id: str) -> None:
    conn.execute(
        """
        INSERT INTO finding_counts (target_id, success_count, partial_count, novel_count, updated_at)
        VALUES (?, 0, 0, 0, ?)
        ON CONFLICT(target_id) DO NOTHING
        """,
        (target_id, _now_iso()),
    )


def increment_finding_count(target_id: str, bucket: str, finding_path: Path) -> None:
    if bucket not in {"success", "partial", "novel"}:
        return
    canonical = str(finding_path.resolve())
    with _DB_LOCK:
        with _open_db() as conn:
            _upsert_target_row(conn, target_id)
            inserted = conn.execute(
                """
                INSERT INTO finding_records (finding_path, target_id, bucket, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(finding_path) DO NOTHING
                """,
                (canonical, target_id, bucket, _now_iso()),
            ).rowcount
            if inserted:
                column = f"{bucket}_count"
                conn.execute(
                    f"""
                    UPDATE finding_counts
                    SET {column} = {column} + 1, updated_at = ?
                    WHERE target_id = ?
                    """,
                    (_now_iso(), target_id),
                )
            conn.commit()


def get_finding_counts(target_id: str) -> dict[str, int] | None:
    with _DB_LOCK:
        with _open_db() as conn:
            row = conn.execute(
                """
                SELECT success_count, partial_count, novel_count
                FROM finding_counts
                WHERE target_id = ?
                """,
                (target_id,),
            ).fetchone()
    if not row:
        return None
    return {
        "success": int(row["success_count"] or 0),
        "partial": int(row["partial_count"] or 0),
        "novel": int(row["novel_count"] or 0),
    }


def recompute_finding_counts(target_id: str, findings_root: Path) -> dict[str, int]:
    counts = {"success": 0, "partial": 0, "novel": 0}
    entries: list[tuple[str, str, str]] = []
    for bucket in ("success", "partial", "novel"):
        directory = findings_root / bucket
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
            if finding_target != target_id:
                continue
            counts[bucket] += 1
            entries.append((str(path.resolve()), finding_target, bucket))
    with _DB_LOCK:
        with _open_db() as conn:
            conn.execute("DELETE FROM finding_records WHERE target_id = ?", (target_id,))
            conn.execute(
                """
                INSERT INTO finding_counts (target_id, success_count, partial_count, novel_count, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                  success_count = excluded.success_count,
                  partial_count = excluded.partial_count,
                  novel_count = excluded.novel_count,
                  updated_at = excluded.updated_at
                """,
                (target_id, counts["success"], counts["partial"], counts["novel"], _now_iso()),
            )
            if entries:
                conn.executemany(
                    """
                    INSERT INTO finding_records (finding_path, target_id, bucket, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    [(path, tid, bucket, _now_iso()) for path, tid, bucket in entries],
                )
            conn.commit()
    return counts


def get_experiment_count(target_id: str) -> int:
    with _DB_LOCK:
        with _open_db() as conn:
            row = conn.execute(
                "SELECT experiment_count FROM target_experiment_stats WHERE target_id = ?",
                (target_id,),
            ).fetchone()
    if not row:
        return 0
    return int(row["experiment_count"] or 0)


def get_low_signal_clusters(target_id: str) -> set[str]:
    with _DB_LOCK:
        with _open_db() as conn:
            rows = conn.execute(
                "SELECT cluster FROM target_low_signal_clusters WHERE target_id = ?",
                (target_id,),
            ).fetchall()
    return {str(row["cluster"]) for row in rows}


def bootstrap_target_experiment_stats(
    target_id: str,
    audit_log_path: Path,
    extra_markers: Iterable[str],
) -> None:
    with _DB_LOCK:
        with _open_db() as conn:
            row = conn.execute(
                "SELECT target_id FROM target_experiment_stats WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            if row:
                return
    if not audit_log_path.exists():
        with _DB_LOCK:
            with _open_db() as conn:
                conn.execute(
                    """
                    INSERT INTO target_experiment_stats (target_id, experiment_count, updated_at)
                    VALUES (?, 0, ?)
                    ON CONFLICT(target_id) DO NOTHING
                    """,
                    (target_id, _now_iso()),
                )
                conn.commit()
        return
    markers = [str(item).strip() for item in extra_markers if str(item).strip()]
    experiment_count = 0
    low_signal_clusters: set[str] = set()
    with audit_log_path.open() as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("target") != target_id:
                continue
            if entry.get("trial") != 0:
                continue
            response = entry.get("response") or {}
            text = str(response.get("extracted", "") or "")
            error = response.get("error")
            cluster = response_cluster(text, extra_markers=markers, error=error)
            if is_low_signal_response(text, extra_markers=markers, error=error):
                low_signal_clusters.add(cluster)
            if "scores" in entry:
                experiment_count += 1
    with _DB_LOCK:
        with _open_db() as conn:
            conn.execute(
                """
                INSERT INTO target_experiment_stats (target_id, experiment_count, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                  experiment_count = excluded.experiment_count,
                  updated_at = excluded.updated_at
                """,
                (target_id, experiment_count, _now_iso()),
            )
            conn.execute(
                "DELETE FROM target_low_signal_clusters WHERE target_id = ?",
                (target_id,),
            )
            if low_signal_clusters:
                conn.executemany(
                    """
                    INSERT INTO target_low_signal_clusters (target_id, cluster, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(target_id, cluster) DO UPDATE SET
                      updated_at = excluded.updated_at
                    """,
                    [(target_id, cluster, _now_iso()) for cluster in sorted(low_signal_clusters)],
                )
            conn.commit()


def record_experiment(target_id: str, low_signal_cluster: str | None = None) -> None:
    with _DB_LOCK:
        with _open_db() as conn:
            conn.execute(
                """
                INSERT INTO target_experiment_stats (target_id, experiment_count, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                  experiment_count = experiment_count + 1,
                  updated_at = excluded.updated_at
                """,
                (target_id, _now_iso()),
            )
            if low_signal_cluster:
                conn.execute(
                    """
                    INSERT INTO target_low_signal_clusters (target_id, cluster, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(target_id, cluster) DO UPDATE SET
                      updated_at = excluded.updated_at
                    """,
                    (target_id, low_signal_cluster, _now_iso()),
                )
            conn.commit()
