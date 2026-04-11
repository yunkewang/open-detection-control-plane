"""Authentication and audit data models.

Used by the ODCP server for API token management, role-based access
control, and the append-only audit log.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    """Role hierarchy for API token authorization.

    ``admin > analyst > readonly``.  ``agent`` is a peer of ``readonly``
    but can write reports and heartbeats for its own agent_id.
    """

    admin = "admin"        # full access — token management, deletions
    analyst = "analyst"    # read + load reports + AI agent queries
    readonly = "readonly"  # read-only GET access
    agent = "agent"        # register, push reports, heartbeat


# Roles that can perform read operations
READER_ROLES = {UserRole.admin, UserRole.analyst, UserRole.readonly}

# Roles that can push scan data (analyst acts as analyst-agent hybrid)
WRITER_ROLES = {UserRole.admin, UserRole.analyst, UserRole.agent}


class TokenRecord(BaseModel):
    """A stored API token (never stores the plain-text secret)."""

    token_id: str
    name: str
    role: UserRole
    token_hash: str      # sha256(plain_token) — never expose this
    created_at: datetime
    last_used_at: Optional[datetime] = None
    agent_id: Optional[str] = None  # if set, agent token is bound to this agent


class TokenPublic(BaseModel):
    """Token info safe to expose via the API (no hash)."""

    token_id: str
    name: str
    role: UserRole
    created_at: datetime
    last_used_at: Optional[datetime] = None
    agent_id: Optional[str] = None


class TokenCreateRequest(BaseModel):
    """Request body for ``POST /api/auth/tokens``."""

    name: str
    role: UserRole = UserRole.readonly
    agent_id: Optional[str] = None  # bind to a specific agent (for agent tokens)


class AuditEvent(BaseModel):
    """A single immutable audit log entry."""

    event_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str                         # token name or "system"
    actor_role: Optional[str] = None   # token role value
    action: str                        # e.g. "token.create", "report.push"
    resource: str                      # e.g. "token:a1b2c3d4", "agent:my-agent"
    status: str = "success"            # "success" | "denied"
    ip_address: Optional[str] = None
    detail: dict[str, Any] = Field(default_factory=dict)
