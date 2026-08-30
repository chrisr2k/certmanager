"""Local SQLite database for offline buffering.

When the agent cannot reach the central API, scan results and heartbeats
are buffered locally in SQLite. On reconnection, buffered data is flushed
to the central API.

Schema:
    pending_results: job results awaiting submission
    pending_heartbeats: heartbeat timestamps during offline periods
    agent_state: key-value store for agent metadata
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import structlog

logger = structlog.get_logger()


class LocalDB:
    """SQLite-based local buffer for offline resilience."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a SQLite connection with WAL mode and foreign keys."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS pending_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                );

                CREATE TABLE IF NOT EXISTS pending_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    agent_status TEXT NOT NULL DEFAULT 'online'
                );

                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_results_created
                    ON pending_results(created_at);
                CREATE INDEX IF NOT EXISTS idx_results_retry
                    ON pending_results(retry_count);
            """)
            conn.commit()

    # --- Pending results ---

    def buffer_result(self, job_id: str, result: dict) -> int:
        """Buffer a scan result for later submission.

        Args:
            job_id: The scan job ID.
            result: The result dict to buffer.

        Returns:
            Row ID of the buffered result.
        """
        with self._get_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO pending_results (job_id, result_json) VALUES (?, ?)",
                (job_id, json.dumps(result, default=str)),
            )
            conn.commit()
            logger.info("result_buffered", job_id=job_id, row_id=cursor.lastrowid)
            return cursor.lastrowid

    def get_pending_results(self, limit: int = 100) -> list[dict]:
        """Get pending results ordered by creation time.

        Args:
            limit: Maximum number of results to return.

        Returns:
            List of result dicts with row id.
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, job_id, result_json, created_at, retry_count "
                "FROM pending_results "
                "ORDER BY created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()

            return [
                {
                    "row_id": row["id"],
                    "job_id": row["job_id"],
                    "result": json.loads(row["result_json"]),
                    "created_at": row["created_at"],
                    "retry_count": row["retry_count"],
                }
                for row in rows
            ]

    def mark_result_submitted(self, row_id: int) -> None:
        """Remove a successfully submitted result from the buffer."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM pending_results WHERE id = ?", (row_id,))
            conn.commit()
            logger.debug("result_flushed", row_id=row_id)

    def mark_result_failed(self, row_id: int, error: str) -> None:
        """Increment retry count and record error for a failed submission."""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE pending_results SET retry_count = retry_count + 1, last_error = ? WHERE id = ?",
                (error[:500], row_id),
            )
            conn.commit()

    def get_pending_count(self) -> int:
        """Get the number of buffered results."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM pending_results").fetchone()
            return row["cnt"]

    def purge_failed(self, max_retries: int = 10) -> int:
        """Remove results that have exceeded the retry limit."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM pending_results WHERE retry_count >= ?", (max_retries,)
            )
            conn.commit()
            return cursor.rowcount

    # --- Heartbeats ---

    def buffer_heartbeat(self, status: str = "online") -> None:
        """Record a heartbeat during offline mode."""
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO pending_heartbeats (timestamp, agent_status) VALUES (datetime('now'), ?)",
                (status,),
            )
            conn.commit()

    def get_heartbeat_history(self, since_hours: int = 24) -> list[dict]:
        """Get heartbeat history for the last N hours."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT timestamp, agent_status FROM pending_heartbeats "
                "WHERE timestamp >= datetime('now', ?) "
                "ORDER BY timestamp DESC",
                (f"-{since_hours} hours",),
            ).fetchall()

            return [{"timestamp": row["timestamp"], "status": row["agent_status"]} for row in rows]

    def clear_heartbeats(self) -> None:
        """Clear buffered heartbeats after successful flush."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM pending_heartbeats")
            conn.commit()

    # --- Agent state ---

    def set_state(self, key: str, value: str) -> None:
        """Persist a key-value state entry."""
        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_state (key, value, updated_at) VALUES (?, ?, datetime('now'))",
                (key, value),
            )
            conn.commit()

    def get_state(self, key: str) -> str | None:
        """Read a persisted state value."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM agent_state WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def get_all_state(self) -> dict[str, str]:
        """Get all agent state entries."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT key, value FROM agent_state").fetchall()
            return {row["key"]: row["value"] for row in rows}
