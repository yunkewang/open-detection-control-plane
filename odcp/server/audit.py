"""Append-only audit logger for the ODCP server.

Every mutating API call — token creation/revocation, agent registration,
report pushes, deregistrations — is logged as an :class:`AuditEvent`.
Events are held in a bounded in-memory ring buffer (last 10,000 events)
and optionally written to a JSONL file for long-term retention.

Usage::

    logger = AuditLogger()
    logger.log(actor="bootstrap-admin", action="token.create",
               resource="token:a1b2c3d4", actor_role="admin")
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from odcp.models.auth import AuditEvent

_log = logging.getLogger(__name__)

_MAX_MEMORY_EVENTS = 10_000


class AuditLogger:
    """Thread-safe audit event recorder.

    Parameters
    ----------
    log_path:
        Optional path to a JSONL file.  Each event is appended as a
        single JSON line.  Pass ``None`` to keep events in memory only.
    max_memory:
        Maximum number of events to hold in memory (oldest are dropped).
    """

    def __init__(
        self,
        log_path: Optional[str | Path] = None,
        max_memory: int = _MAX_MEMORY_EVENTS,
    ) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_memory)
        self._lock = threading.Lock()
        self._log_path = Path(log_path) if log_path else None

    # ── Write ───────────────────────────────────────────────────────────────

    def log(
        self,
        actor: str,
        action: str,
        resource: str,
        *,
        actor_role: Optional[str] = None,
        status: str = "success",
        ip_address: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        """Record an audit event and return it."""
        event = AuditEvent(
            actor=actor,
            action=action,
            resource=resource,
            actor_role=actor_role,
            status=status,
            ip_address=ip_address,
            detail=detail or {},
        )
        with self._lock:
            self._events.append(event)
        if self._log_path:
            self._write_line(event)
        _log.debug(
            "AUDIT %s %s %s → %s",
            actor, action, resource, status,
        )
        return event

    def log_from_request(
        self,
        request: Any,          # FastAPI Request
        action: str,
        resource: str,
        *,
        token: Any = None,     # Optional[TokenRecord]
        status: str = "success",
        detail: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        """Convenience wrapper that extracts actor info from a FastAPI request."""
        actor = token.name if token else "anonymous"
        actor_role = token.role.value if token else None
        ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.client.host
            if request.client else None
        )
        return self.log(
            actor=actor,
            action=action,
            resource=resource,
            actor_role=actor_role,
            status=status,
            ip_address=ip,
            detail=detail or {},
        )

    # ── Read ────────────────────────────────────────────────────────────────

    def recent(
        self,
        limit: int = 100,
        action_filter: Optional[str] = None,
        actor_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> list[AuditEvent]:
        """Return the most recent events (newest first), with optional filters."""
        with self._lock:
            events = list(self._events)

        if action_filter:
            events = [e for e in events if action_filter in e.action]
        if actor_filter:
            events = [e for e in events if actor_filter.lower() in e.actor.lower()]
        if status_filter:
            events = [e for e in events if e.status == status_filter]

        return list(reversed(events))[:limit]

    def total(self) -> int:
        with self._lock:
            return len(self._events)

    # ── Persistence ─────────────────────────────────────────────────────────

    def _write_line(self, event: AuditEvent) -> None:
        try:
            line = json.dumps(event.model_dump(mode="json"), default=str) + "\n"
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as exc:
            _log.error("Failed to write audit log: %s", exc)

    def load_from_file(self) -> int:
        """Replay events from JSONL file into the in-memory buffer."""
        if not self._log_path or not self._log_path.exists():
            return 0
        count = 0
        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = AuditEvent.model_validate_json(line)
                    with self._lock:
                        self._events.append(event)
                    count += 1
                except Exception:
                    pass
        return count
