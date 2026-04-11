"""API token authentication and role-based access control.

Token format:  ``odcp_<8-hex-id>_<32-char-secret>``

Usage in FastAPI routes::

    @router.post("/resource", dependencies=[Depends(require_role(UserRole.admin))])
    async def create_resource(...):
        ...

    # Or capture the token record:
    @router.get("/me")
    async def me(token: TokenRecord = Depends(get_current_token)):
        ...

Auth is opt-in — the ``TokenStore`` is created with ``auth_enabled=True``
only when the server is started with ``--auth``.  When disabled (default),
all routes pass through without authentication, so existing tests and
zero-config deployments continue to work unchanged.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request

from odcp.models.auth import TokenRecord, UserRole

logger = logging.getLogger(__name__)


class TokenStore:
    """Thread-safe in-memory store of API tokens.

    Parameters
    ----------
    auth_enabled:
        When ``False`` (default), ``get_current_token`` always returns
        ``None`` and all routes are open.  Set ``True`` to require valid
        bearer tokens.
    """

    def __init__(self, auth_enabled: bool = False) -> None:
        self.auth_enabled = auth_enabled
        self._tokens: dict[str, TokenRecord] = {}   # token_id → record
        self._hash_index: dict[str, str] = {}       # sha256(plain) → token_id
        self._lock = threading.Lock()

    # ── CRUD ───────────────────────────────────────────────────────────────

    def create(
        self,
        name: str,
        role: UserRole,
        agent_id: Optional[str] = None,
    ) -> tuple[str, TokenRecord]:
        """Generate a new token. Returns ``(plain_token, TokenRecord)``.

        The plain token is returned exactly once — it is never stored.
        """
        token_id = secrets.token_hex(4)           # 8 hex chars
        secret = secrets.token_urlsafe(24)        # ~32 URL-safe chars
        plain = f"odcp_{token_id}_{secret}"
        token_hash = hashlib.sha256(plain.encode()).hexdigest()
        record = TokenRecord(
            token_id=token_id,
            name=name,
            role=role,
            token_hash=token_hash,
            created_at=datetime.now(timezone.utc),
            agent_id=agent_id,
        )
        with self._lock:
            self._tokens[token_id] = record
            self._hash_index[token_hash] = token_id
        logger.info("Created token '%s' (role=%s, id=%s)", name, role.value, token_id)
        return plain, record

    def verify(self, plain_token: str) -> Optional[TokenRecord]:
        """Verify a plain token; update ``last_used_at`` on success."""
        token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
        with self._lock:
            token_id = self._hash_index.get(token_hash)
            if not token_id:
                return None
            record = self._tokens.get(token_id)
            if record is None:
                return None
            record.last_used_at = datetime.now(timezone.utc)
            return record

    def revoke(self, token_id: str) -> bool:
        """Remove a token by ID. Returns False if not found."""
        with self._lock:
            record = self._tokens.pop(token_id, None)
            if record is None:
                return False
            self._hash_index.pop(record.token_hash, None)
        logger.info("Revoked token '%s' (id=%s)", record.name, token_id)
        return True

    def get(self, token_id: str) -> Optional[TokenRecord]:
        with self._lock:
            return self._tokens.get(token_id)

    def list_all(self) -> list[TokenRecord]:
        with self._lock:
            return sorted(self._tokens.values(), key=lambda r: r.created_at)

    def count(self) -> int:
        with self._lock:
            return len(self._tokens)


# ── FastAPI dependencies ────────────────────────────────────────────────────


async def get_current_token(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Optional[TokenRecord]:
    """Resolve the bearer token from ``Authorization: Bearer <token>``.

    Returns ``None`` when auth is disabled.
    Raises HTTP 401 when auth is enabled but the token is missing/invalid.

    Works both as a FastAPI dependency (where ``authorization`` is injected
    from the request header) and when called directly (falls back to reading
    from ``request.headers``).
    """
    store: TokenStore = request.app.state.token_store
    if not store.auth_enabled:
        return None  # open access — auth disabled

    # When called directly (not via Depends), the Header descriptor isn't
    # resolved by FastAPI's DI — fall back to reading from the request.
    if not isinstance(authorization, str):
        authorization = request.headers.get("authorization")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Include: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    plain = authorization[7:].strip()
    record = store.verify(plain)
    if record is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return record


def require_role(*allowed: UserRole):
    """Dependency factory — raises HTTP 403 if the token's role is not in *allowed*.

    Usage::

        @router.delete("/agents/{id}", dependencies=[Depends(require_role(UserRole.admin))])

        # Or capture the token:
        @router.post("/tokens")
        async def create_token(_auth = Depends(require_role(UserRole.admin))):
            ...
    """
    async def _check(
        token: Optional[TokenRecord] = Depends(get_current_token),
    ) -> Optional[TokenRecord]:
        if token is None:
            return None  # auth disabled
        if token.role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Role '{token.role.value}' is not permitted for this operation. "
                    f"Required: {[r.value for r in allowed]}"
                ),
            )
        return token
    return _check


# ── Role shorthand helpers ──────────────────────────────────────────────────


def admin_only():
    """Require admin role."""
    return require_role(UserRole.admin)


def analyst_or_above():
    """Require admin or analyst role."""
    return require_role(UserRole.admin, UserRole.analyst)


def reader_or_above():
    """Require admin, analyst, or readonly role."""
    return require_role(UserRole.admin, UserRole.analyst, UserRole.readonly)


def agent_or_above():
    """Require admin, analyst, or agent role (write access for data pushes)."""
    return require_role(UserRole.admin, UserRole.analyst, UserRole.agent)
