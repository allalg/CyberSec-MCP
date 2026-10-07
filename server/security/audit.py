"""Audit Logger — records every tool execution attempt to SQLite.

Provides a permanent, queryable trail of:
- What tool was used
- Against which target
- By whom (agent_id / session_id)
- What the policy decided
- The outcome and duration
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from server.models import AuditEntry, ToolRequest, ToolResult

logger = logging.getLogger(__name__)

# SQL schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    session_id      TEXT,
    agent_id        TEXT,
    request_id      TEXT    NOT NULL UNIQUE,
    tool_name       TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    arguments       TEXT    DEFAULT '{}',
    sandbox_id      TEXT,
    policy_decision TEXT    NOT NULL,
    duration_ms     INTEGER DEFAULT 0,
    status          TEXT    NOT NULL,
    error           TEXT,
    findings_count  INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_tool      ON audit_log(tool_name);
CREATE INDEX IF NOT EXISTS idx_audit_session   ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_request   ON audit_log(request_id);
"""


class AuditLogger:
    """Async SQLite-backed audit logger."""

    def __init__(self, db_path: str = "audit.db"):
        self._db_path = db_path
        self._initialized = False

    async def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        if self._initialized:
            return

        # Ensure parent directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

        self._initialized = True
        logger.info("Audit database initialized at %s", self._db_path)

    async def log(
        self,
        request: ToolRequest,
        result: ToolResult | None = None,
        policy_decision: str = "approved",
        sandbox_id: str | None = None,
        error: str | None = None,
    ) -> None:
        """Log a tool execution attempt."""
        await self._ensure_db()

        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            session_id=request.session_id,
            request_id=str(request.request_id),
            tool_name=request.tool_name,
            target=request.target,
            arguments=json.dumps(request.arguments),
            sandbox_id=sandbox_id,
            policy_decision=policy_decision,
            duration_ms=result.duration_ms if result else 0,
            status=result.status.value if result else "denied",
            error=error or (result.error if result else None),
            findings_count=len(result.findings) if result else 0,
        )

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO audit_log (
                    timestamp, session_id, agent_id, request_id,
                    tool_name, target, arguments, sandbox_id,
                    policy_decision, duration_ms, status, error, findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp.isoformat(),
                    entry.session_id,
                    entry.agent_id,
                    entry.request_id,
                    entry.tool_name,
                    entry.target,
                    entry.arguments,
                    entry.sandbox_id,
                    entry.policy_decision,
                    entry.duration_ms,
                    entry.status,
                    entry.error,
                    entry.findings_count,
                ),
            )
            await db.commit()

        logger.debug(
            "Audit logged: tool=%s target=%s status=%s duration=%dms",
            entry.tool_name, entry.target, entry.status, entry.duration_ms,
        )

    async def log_attempt(
        self,
        request: ToolRequest,
        policy_decision: str = "approved",
        status: str = "success",
        duration_ms: int = 0,
        sandbox_id: str | None = None,
        error: str | None = None,
        findings_count: int = 0,
    ) -> None:
        """Log a tool execution attempt without needing a full ToolResult object."""
        await self._ensure_db()

        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            session_id=request.session_id,
            request_id=str(request.request_id),
            tool_name=request.tool_name,
            target=request.target,
            arguments=json.dumps(request.arguments),
            sandbox_id=sandbox_id,
            policy_decision=policy_decision,
            duration_ms=duration_ms,
            status=status,
            error=error,
            findings_count=findings_count,
        )

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO audit_log (
                    timestamp, session_id, agent_id, request_id,
                    tool_name, target, arguments, sandbox_id,
                    policy_decision, duration_ms, status, error, findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp.isoformat(),
                    entry.session_id,
                    entry.agent_id,
                    entry.request_id,
                    entry.tool_name,
                    entry.target,
                    entry.arguments,
                    entry.sandbox_id,
                    entry.policy_decision,
                    entry.duration_ms,
                    entry.status,
                    entry.error,
                    entry.findings_count,
                ),
            )
            await db.commit()

    async def query(
        self,
        tool_name: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query audit entries with optional filters."""
        await self._ensure_db()

        conditions = []
        params: list = []

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT ?",
                params + [limit],
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_recent(self, limit: int = 20) -> list[dict]:
        """Get the most recent audit entries."""
        return await self.query(limit=limit)

    async def get_session(self, session_id: str) -> list[dict]:
        """Get all audit entries for a specific session."""
        return await self.query(session_id=session_id)

    async def get_stats(self) -> dict:
        """Get aggregate audit statistics."""
        await self._ensure_db()

        async with aiosqlite.connect(self._db_path) as db:
            # Total executions
            cursor = await db.execute("SELECT COUNT(*) FROM audit_log")
            total = (await cursor.fetchone())[0]

            # By status
            cursor = await db.execute(
                "SELECT status, COUNT(*) FROM audit_log GROUP BY status"
            )
            by_status = {row[0]: row[1] for row in await cursor.fetchall()}

            # By tool
            cursor = await db.execute(
                "SELECT tool_name, COUNT(*) FROM audit_log GROUP BY tool_name"
            )
            by_tool = {row[0]: row[1] for row in await cursor.fetchall()}

            # Average duration
            cursor = await db.execute(
                "SELECT AVG(duration_ms) FROM audit_log WHERE status = 'success'"
            )
            avg_duration = (await cursor.fetchone())[0] or 0

            return {
                "total_executions": total,
                "by_status": by_status,
                "by_tool": by_tool,
                "avg_duration_ms": round(avg_duration, 1),
            }
