"""Integration tests for the detection lifecycle API."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed; skipping server tests")
pytest.importorskip("httpx", reason="httpx not installed; skipping server tests")

from fastapi.testclient import TestClient

from odcp.lifecycle.manager import LifecycleManager
from odcp.models.lifecycle import DetectionState
from odcp.server.app import create_app


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_app(pre_populate: bool = False):
    lm = LifecycleManager()
    if pre_populate:
        lm.get_or_create("det-001", "Login Brute Force")
        lm.get_or_create("det-002", "Data Exfiltration")
        lm.get_or_create("det-003", "Lateral Movement")
        lm.promote("det-002", actor="alice")  # review
        lm.promote("det-003", actor="bob")    # review
        lm.promote("det-003", actor="carol")  # testing
    app = create_app(lifecycle_manager=lm)
    return app, lm


# ── GET /api/lifecycle/summary ──────────────────────────────────────────────


class TestSummaryEndpoint:
    def test_summary_empty(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.get("/api/lifecycle/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert "by_state" in data

    def test_summary_counts(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/api/lifecycle/summary")
        data = resp.json()
        assert data["total"] == 3
        assert data["by_state"]["draft"] == 1
        assert data["by_state"]["review"] == 1
        assert data["by_state"]["testing"] == 1


# ── GET /api/lifecycle/detections ──────────────────────────────────────────


class TestListEndpoint:
    def test_list_all(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/api/lifecycle/detections")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["detections"]) == 3

    def test_list_filter_by_state(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/api/lifecycle/detections?state=review")
        data = resp.json()
        assert data["total"] == 1
        assert data["detections"][0]["current_state"] == "review"

    def test_list_unknown_state_returns_empty(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/api/lifecycle/detections?state=nonexistent")
        data = resp.json()
        assert data["total"] == 0


# ── GET /api/lifecycle/detections/{id} ─────────────────────────────────────


class TestGetEndpoint:
    def test_get_existing(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/api/lifecycle/detections/det-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_id"] == "det-001"
        assert data["detection_name"] == "Login Brute Force"
        assert data["current_state"] == "draft"
        assert len(data["history"]) >= 1

    def test_get_nonexistent_returns_404(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.get("/api/lifecycle/detections/no-such-id")
        assert resp.status_code == 404


# ── POST /api/lifecycle/detections/{id}/register ───────────────────────────


class TestRegisterEndpoint:
    def test_register_new_detection(self):
        app, lm = _make_app()
        client = TestClient(app)
        resp = client.post(
            "/api/lifecycle/detections/new-det/register",
            json={"detection_name": "New Detection"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["detection_id"] == "new-det"
        assert data["current_state"] == "draft"

    def test_register_existing_is_idempotent(self):
        app, lm = _make_app()
        client = TestClient(app)
        client.post("/api/lifecycle/detections/d1/register", json={"detection_name": "Det1"})
        resp = client.post("/api/lifecycle/detections/d1/register", json={"detection_name": "Det1"})
        assert resp.status_code == 201  # still 201, idempotent


# ── POST /api/lifecycle/detections/{id}/promote ────────────────────────────


class TestPromoteEndpoint:
    def test_promote_advances_state(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.post(
            "/api/lifecycle/detections/det-001/promote",
            json={"actor": "alice", "comment": "Looks good"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["current_state"] == "review"

    def test_promote_records_comment(self):
        app, lm = _make_app(pre_populate=True)
        client = TestClient(app)
        client.post(
            "/api/lifecycle/detections/det-001/promote",
            json={"actor": "alice", "comment": "All checks pass"},
        )
        lc = lm.get("det-001")
        latest_event = lc.history[-1]
        assert latest_event.comment == "All checks pass"
        assert latest_event.actor == "alice"

    def test_promote_terminal_returns_422(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Det1")
        for _ in range(4):  # draft→review→testing→production→deprecated
            lm.promote("d1")
        resp = client.post("/api/lifecycle/detections/d1/promote", json={})
        assert resp.status_code == 422

    def test_promote_nonexistent_returns_404(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.post("/api/lifecycle/detections/no-such/promote", json={})
        assert resp.status_code == 404


# ── POST /api/lifecycle/detections/{id}/rollback ───────────────────────────


class TestRollbackEndpoint:
    def test_rollback_goes_back(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        # det-002 is in review
        resp = client.post(
            "/api/lifecycle/detections/det-002/rollback",
            json={"actor": "bob", "comment": "Needs revision"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["current_state"] == "draft"

    def test_rollback_initial_state_returns_422(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Test")
        resp = client.post("/api/lifecycle/detections/d1/rollback", json={})
        assert resp.status_code == 422

    def test_rollback_nonexistent_returns_404(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.post("/api/lifecycle/detections/no-such/rollback", json={})
        assert resp.status_code == 404


# ── POST /api/lifecycle/detections/{id}/transition ─────────────────────────


class TestTransitionEndpoint:
    def test_explicit_transition(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Det1")
        resp = client.post(
            "/api/lifecycle/detections/d1/transition",
            json={"to_state": "review", "actor": "alice"},
        )
        assert resp.status_code == 200
        assert resp.json()["current_state"] == "review"

    def test_transition_to_deprecated_direct(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Det1")
        resp = client.post(
            "/api/lifecycle/detections/d1/transition",
            json={"to_state": "deprecated"},
        )
        assert resp.status_code == 200
        assert resp.json()["current_state"] == "deprecated"

    def test_transition_invalid_state_name_returns_400(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Det1")
        resp = client.post(
            "/api/lifecycle/detections/d1/transition",
            json={"to_state": "garbage"},
        )
        assert resp.status_code == 400

    def test_transition_illegal_path_returns_422(self):
        app, lm = _make_app()
        client = TestClient(app)
        lm.get_or_create("d1", "Det1")
        resp = client.post(
            "/api/lifecycle/detections/d1/transition",
            json={"to_state": "production"},  # draft → production is invalid
        )
        assert resp.status_code == 422


# ── UI page ────────────────────────────────────────────────────────────────


class TestLifecyclePage:
    def test_page_renders(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/lifecycle")
        assert resp.status_code == 200
        assert b"Lifecycle" in resp.content

    def test_page_shows_detections(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/lifecycle")
        assert b"Login Brute Force" in resp.content
        assert b"Data Exfiltration" in resp.content

    def test_page_state_filter(self):
        app, _ = _make_app(pre_populate=True)
        client = TestClient(app)
        resp = client.get("/lifecycle?state=draft")
        assert resp.status_code == 200
        assert b"Login Brute Force" in resp.content
        assert b"Data Exfiltration" not in resp.content
