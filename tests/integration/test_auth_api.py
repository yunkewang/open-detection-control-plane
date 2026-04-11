"""Integration tests for the ODCP auth API — token management, RBAC, and audit log."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed; skipping server tests")
pytest.importorskip("httpx", reason="httpx not installed; skipping server tests")

from fastapi.testclient import TestClient

from odcp.models.auth import UserRole
from odcp.server.app import create_app
from odcp.server.audit import AuditLogger
from odcp.server.auth import TokenStore


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_app_with_auth():
    """Create an app instance with auth enabled and a bootstrap admin token."""
    token_store = TokenStore(auth_enabled=True)
    audit_logger = AuditLogger()
    plain, admin_record = token_store.create("admin", UserRole.admin)
    app = create_app(token_store=token_store, audit_logger=audit_logger)
    return app, plain, admin_record, token_store, audit_logger


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── GET /api/auth/me ────────────────────────────────────────────────────────


class TestWhoami:
    def test_whoami_auth_disabled(self):
        app = create_app()  # auth disabled by default
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_enabled"] is False

    def test_whoami_returns_token_info(self):
        app, plain, record, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/me", headers=auth_header(plain))
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_enabled"] is True
        assert data["name"] == "admin"
        assert data["role"] == "admin"
        assert data["token_id"] == record.token_id

    def test_whoami_missing_token_returns_401(self):
        app, _, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_whoami_bad_token_returns_401(self):
        app, _, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/me", headers=auth_header("odcp_bad_bad"))
        assert resp.status_code == 401


# ── POST /api/auth/tokens ───────────────────────────────────────────────────


class TestCreateToken:
    def test_admin_can_create_token(self):
        app, plain, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "analyst-tok", "role": "analyst"},
            headers=auth_header(plain),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["token"].startswith("odcp_")
        assert data["role"] == "analyst"
        assert "warning" in data

    def test_non_admin_cannot_create_token(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        analyst_plain, _ = token_store.create("analyst", UserRole.analyst)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "new-tok", "role": "readonly"},
            headers=auth_header(analyst_plain),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_create_token(self):
        app, _, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "tok", "role": "readonly"},
        )
        assert resp.status_code == 401

    def test_create_agent_token_with_agent_id(self):
        app, plain, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "collector-agent", "role": "agent", "agent_id": "agent-001"},
            headers=auth_header(plain),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "agent"
        assert data["agent_id"] == "agent-001"


# ── GET /api/auth/tokens ────────────────────────────────────────────────────


class TestListTokens:
    def test_admin_can_list_tokens(self):
        app, plain, _, token_store, _ = _make_app_with_auth()
        token_store.create("extra1", UserRole.readonly)
        token_store.create("extra2", UserRole.analyst)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/tokens", headers=auth_header(plain))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3  # admin + 2 extra
        names = {t["name"] for t in data["tokens"]}
        assert "admin" in names

    def test_list_tokens_hides_plain_tokens(self):
        app, plain, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/tokens", headers=auth_header(plain))
        data = resp.json()
        for tok in data["tokens"]:
            # TokenPublic should not have token_hash field
            assert "token_hash" not in tok
            assert "token" not in tok

    def test_non_admin_cannot_list_tokens(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        ro_plain, _ = token_store.create("ro-user", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/tokens", headers=auth_header(ro_plain))
        assert resp.status_code == 403


# ── DELETE /api/auth/tokens/{id} ───────────────────────────────────────────


class TestRevokeToken:
    def test_admin_can_revoke_token(self):
        app, plain, _, token_store, _ = _make_app_with_auth()
        ro_plain, ro_record = token_store.create("victim", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.delete(
            f"/api/auth/tokens/{ro_record.token_id}",
            headers=auth_header(plain),
        )
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True
        # Token should now be invalid
        assert token_store.verify(ro_plain) is None

    def test_cannot_revoke_own_token(self):
        app, plain, admin_record, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.delete(
            f"/api/auth/tokens/{admin_record.token_id}",
            headers=auth_header(plain),
        )
        assert resp.status_code == 400

    def test_revoke_nonexistent_returns_404(self):
        app, plain, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.delete("/api/auth/tokens/nosuchid", headers=auth_header(plain))
        assert resp.status_code == 404

    def test_non_admin_cannot_revoke(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        analyst_plain, _ = token_store.create("analyst", UserRole.analyst)
        victim_plain, victim_rec = token_store.create("victim", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.delete(
            f"/api/auth/tokens/{victim_rec.token_id}",
            headers=auth_header(analyst_plain),
        )
        assert resp.status_code == 403


# ── GET /api/auth/audit ─────────────────────────────────────────────────────


class TestAuditLog:
    def test_admin_can_read_audit_log(self):
        app, plain, _, token_store, audit_logger = _make_app_with_auth()
        audit_logger.log("alice", "token.create", "token:abc", actor_role="admin")
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/audit", headers=auth_header(plain))
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert data["total_in_memory"] >= 1

    def test_analyst_can_read_audit_log(self):
        app, _, _, token_store, audit_logger = _make_app_with_auth()
        analyst_plain, _ = token_store.create("analyst", UserRole.analyst)
        audit_logger.log("someone", "act", "res")
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/audit", headers=auth_header(analyst_plain))
        assert resp.status_code == 200

    def test_readonly_cannot_read_audit_log(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        ro_plain, _ = token_store.create("ro", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/audit", headers=auth_header(ro_plain))
        assert resp.status_code == 403

    def test_audit_log_filter_by_action(self):
        app, plain, _, _, audit_logger = _make_app_with_auth()
        audit_logger.log("a", "token.create", "res")
        audit_logger.log("b", "agent.register", "res")
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/auth/audit?action=token", headers=auth_header(plain))
        data = resp.json()
        assert all("token" in e["action"] for e in data["events"])


# ── RBAC for data API endpoints ─────────────────────────────────────────────


class TestDataApiRbac:
    """With auth enabled, data endpoints should enforce reader_or_above."""

    def test_posture_requires_auth(self):
        app, _, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/posture")
        assert resp.status_code == 401

    def test_posture_accessible_with_readonly_token(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        ro_plain, _ = token_store.create("reader", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        # No report loaded → 404, but auth passes
        resp = client.get("/api/posture", headers=auth_header(ro_plain))
        assert resp.status_code == 404  # not 401/403

    def test_detections_requires_auth(self):
        app, _, _, _, _ = _make_app_with_auth()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/detections")
        assert resp.status_code == 401

    def test_report_load_requires_analyst_or_above(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        ro_plain, _ = token_store.create("reader", UserRole.readonly)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/report/load",
            json={"path": "/tmp/nonexistent.json"},
            headers=auth_header(ro_plain),
        )
        assert resp.status_code == 403

    def test_report_load_allowed_for_analyst(self):
        app, _, _, token_store, _ = _make_app_with_auth()
        analyst_plain, _ = token_store.create("analyst", UserRole.analyst)
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/report/load",
            json={"path": "/tmp/nonexistent.json"},
            headers=auth_header(analyst_plain),
        )
        # auth passes, but file not found → 404
        assert resp.status_code == 404  # not 401/403

    def test_auth_disabled_allows_all_data_endpoints(self):
        """Default (auth disabled) — no bearer token required."""
        app = create_app()
        client = TestClient(app, raise_server_exceptions=True)
        # With no report loaded these return 404, but they are NOT 401/403
        for path in ["/api/posture", "/api/detections", "/api/findings",
                     "/api/coverage", "/api/sources"]:
            resp = client.get(path)
            assert resp.status_code in (200, 404), f"{path} returned {resp.status_code}"
