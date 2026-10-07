"""Risk Engine — tracks session risk scoring, operation limits, and approval management."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from server.models import RiskLevel, ToolRequest

logger = logging.getLogger(__name__)

TOOL_BASE_RISK_SCORES: dict[str, int] = {
    "dns_lookup": 1,
    "whois_lookup": 1,
    "hash_file": 1,
    "http_probe": 2,
    "nmap_scan": 4,
    "directory_scan": 5,
}

SESSION_RISK_THRESHOLD_APPROVAL = 15


@dataclass
class SessionRiskState:
    """Tracks state and cumulative risk for an active investigation session."""

    session_id: str
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    executed_tools: list[dict[str, Any]] = field(default_factory=list)
    cumulative_score: int = 0
    approved_actions: set[str] = field(default_factory=set)


class RiskEngine:
    """Evaluates risk escalation, tracks investigation session intensity, and handles approval gates."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRiskState] = {}

    def get_or_create_session(self, session_id: str, target: str) -> SessionRiskState:
        """Retrieve existing session state or initialize a new one."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionRiskState(session_id=session_id, target=target)
        return self._sessions[session_id]

    def record_execution(self, request: ToolRequest, risk_level: RiskLevel) -> int:
        """Record an execution under a session and update cumulative risk score."""
        session_id = request.session_id or f"default_{request.target}"
        session = self.get_or_create_session(session_id, request.target)

        score = TOOL_BASE_RISK_SCORES.get(request.tool_name, 2)
        session.cumulative_score += score
        session.executed_tools.append({
            "tool": request.tool_name,
            "target": request.target,
            "score": score,
            "risk_level": risk_level.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            "Session %s score updated: +%d -> %d",
            session_id, score, session.cumulative_score,
        )
        return session.cumulative_score

    def requires_approval(self, request: ToolRequest, base_requires_approval: bool) -> tuple[bool, str]:
        """Determine if an action requires operator approval (due to base policy or session risk score)."""
        if base_requires_approval:
            return True, f"Tool {request.tool_name} requires explicit operator approval."

        if not request.session_id:
            return False, ""

        session = self._sessions.get(request.session_id)
        if session and session.cumulative_score >= SESSION_RISK_THRESHOLD_APPROVAL:
            action_key = f"{request.tool_name}:{request.target}"
            if action_key not in session.approved_actions:
                return (
                    True,
                    f"Session risk threshold ({SESSION_RISK_THRESHOLD_APPROVAL}) exceeded (current: {session.cumulative_score}). Explicit operator approval required for escalation.",
                )

        return False, ""

    def approve_action(self, session_id: str, action_key: str) -> None:
        """Mark an action as explicitly approved by operator."""
        if session_id in self._sessions:
            self._sessions[session_id].approved_actions.add(action_key)
            logger.info("Session %s: approved action %s", session_id, action_key)
