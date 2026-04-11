"""Integration tests for fleet API routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from odcp.collector.registry import AgentRegistry
from odcp.models.collector import (
    AgentConfig,
    AgentHeartbeat,
    AgentRegistration,
    AgentStatus,
)
from odcp.models.report import ScanReport, ReadinessSummary, DependencyStats
from odcp.models.environment import Environment
from odcp.server.app import create_app
from odcp.server.state import ReportStore


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture()
def registry():
    return AgentRegistry()


@pytest.fixture()
def app(registry):
    store = ReportStore()
    application = create_app(store=store, registry=registry)
    return application


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def _reg(agent_id: str = "agent-1") -> dict:
    return {
        "config": {
            "agent_id": agent_id,
            "environment_name": f"Env-{agent_id}",
            "platform": "splunk",
            "scan_path": "/tmp",
            "central_url": "http://localhost:8080",
            "scan_interval_seconds": 300,
            "tags": ["test"],
            "hostname": "test-host",
        },
        "odcp_version": "0.1.0",
        "python_version": "3.11.0",
    }


def _minimal_report() -> dict:
    return {
        "environment": {
            "name": "Test",
            "platforms": [{"name": "splunk", "vendor": "Splunk", "adapter_type": "splunk"}],
        },
        "scan_timestamp": "2024-01-01T00:00:00Z",
        "detections": [],
        "dependencies": [],
        "readiness_scores": [],
        "findings": [],
        "readiness_summary": {
            "total_detections": 0,
            "runnable": 0,
            "partially_runnable": 0,
            "blocked": 0,
            "unknown": 0,
            "overall_score": 0.0,
        },
        "dependency_stats": {
            "total": 0,
            "by_status": {},
            "by_kind": {},
        },
    }


# ── Health ─────────────────────────────────────────────────────────────────


def test_fleet_health(client):
    resp = client.get("/api/fleet/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


# ── Registration ───────────────────────────────────────────────────────────


def test_register_agent_returns_201(client):
    resp = client.post("/api/fleet/agents/register", json=_reg())
    assert resp.status_code == 201
    data = resp.json()
    assert data["agent_id"] == "agent-1"
    assert data["status"] == "active"


def test_register_agent_idempotent(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.post("/api/fleet/agents/register", json=_reg())
    assert resp.status_code == 201
    # registered_at preserved
    data = resp.json()
    assert data["agent_id"] == "agent-1"


def test_register_multiple_agents(client):
    for i in range(3):
        resp = client.post("/api/fleet/agents/register", json=_reg(f"agent-{i}"))
        assert resp.status_code == 201

    resp = client.get("/api/fleet/agents")
    assert resp.status_code == 200
    assert resp.json()["total"] == 3


# ── Report push ────────────────────────────────────────────────────────────


def test_push_report_accepted(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.post("/api/fleet/agents/agent-1/report", json=_minimal_report())
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] is True


def test_push_report_unknown_agent_returns_404(client):
    resp = client.post("/api/fleet/agents/ghost/report", json=_minimal_report())
    assert resp.status_code == 404


def test_get_agent_report(client):
    client.post("/api/fleet/agents/register", json=_reg())
    client.post("/api/fleet/agents/agent-1/report", json=_minimal_report())
    resp = client.get("/api/fleet/agents/agent-1/report")
    assert resp.status_code == 200
    data = resp.json()
    assert data["environment"]["name"] == "Test"


def test_get_report_before_push_returns_404(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.get("/api/fleet/agents/agent-1/report")
    assert resp.status_code == 404


# ── Heartbeat ──────────────────────────────────────────────────────────────


def test_heartbeat_accepted(client):
    client.post("/api/fleet/agents/register", json=_reg())
    hb = {
        "agent_id": "agent-1",
        "status": "active",
        "last_scan_total_detections": 10,
        "last_scan_readiness_score": 0.85,
    }
    resp = client.post("/api/fleet/agents/agent-1/heartbeat", json=hb)
    assert resp.status_code == 202
    assert resp.json()["accepted"] is True


def test_heartbeat_unknown_agent_returns_404(client):
    hb = {"agent_id": "ghost", "status": "active"}
    resp = client.post("/api/fleet/agents/ghost/heartbeat", json=hb)
    assert resp.status_code == 404


def test_heartbeat_updates_status(client, registry):
    client.post("/api/fleet/agents/register", json=_reg())
    hb = {"agent_id": "agent-1", "status": "degraded", "error_message": "scan failed"}
    client.post("/api/fleet/agents/agent-1/heartbeat", json=hb)
    assert registry.agents["agent-1"].status == AgentStatus.degraded
    assert registry.agents["agent-1"].error_message == "scan failed"


# ── Deregister ─────────────────────────────────────────────────────────────


def test_deregister_agent(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.delete("/api/fleet/agents/agent-1")
    assert resp.status_code == 200
    assert resp.json()["deregistered"] is True


def test_deregister_unknown_agent_returns_404(client):
    resp = client.delete("/api/fleet/agents/ghost")
    assert resp.status_code == 404


def test_deregister_then_get_returns_404(client):
    client.post("/api/fleet/agents/register", json=_reg())
    client.delete("/api/fleet/agents/agent-1")
    resp = client.get("/api/fleet/agents/agent-1")
    assert resp.status_code == 404


# ── List & filter ──────────────────────────────────────────────────────────


def test_list_agents_empty(client):
    resp = client.get("/api/fleet/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["agents"] == []


def test_list_agents_filter_by_status(client, registry):
    for i in range(3):
        client.post("/api/fleet/agents/register", json=_reg(f"agent-{i}"))
    # Mark one offline
    registry.agents["agent-0"].status = AgentStatus.offline

    resp = client.get("/api/fleet/agents?status=offline")
    assert resp.json()["total"] == 1
    assert resp.json()["agents"][0]["agent_id"] == "agent-0"


def test_list_agents_filter_by_platform(client):
    client.post("/api/fleet/agents/register", json=_reg("splunk-agent"))
    sigma_reg = _reg("sigma-agent")
    sigma_reg["config"]["platform"] = "sigma"
    client.post("/api/fleet/agents/register", json=sigma_reg)

    resp = client.get("/api/fleet/agents?platform=sigma")
    assert resp.json()["total"] == 1
    assert resp.json()["agents"][0]["platform"] == "sigma"


def test_get_single_agent(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.get("/api/fleet/agents/agent-1")
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "agent-1"


def test_get_single_agent_not_found(client):
    resp = client.get("/api/fleet/agents/ghost")
    assert resp.status_code == 404


# ── Fleet summary ──────────────────────────────────────────────────────────


def test_fleet_summary_empty(client):
    resp = client.get("/api/fleet/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_agents"] == 0
    assert data["active_agents"] == 0


def test_fleet_summary_counts(client, registry):
    for i in range(4):
        client.post("/api/fleet/agents/register", json=_reg(f"agent-{i}"))
    registry.agents["agent-0"].status = AgentStatus.offline
    registry.agents["agent-1"].status = AgentStatus.degraded

    resp = client.get("/api/fleet/summary")
    data = resp.json()
    assert data["total_agents"] == 4
    assert data["offline_agents"] == 1
    assert data["degraded_agents"] == 1
    assert data["active_agents"] == 2


# ── UI page ────────────────────────────────────────────────────────────────


def test_fleet_ui_page_renders(client):
    resp = client.get("/fleet")
    assert resp.status_code == 200
    assert b"Fleet" in resp.content or b"fleet" in resp.content


def test_fleet_ui_shows_registered_agent(client):
    client.post("/api/fleet/agents/register", json=_reg())
    resp = client.get("/fleet")
    assert resp.status_code == 200
    assert b"agent-1" in resp.content
