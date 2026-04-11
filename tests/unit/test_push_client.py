"""Unit tests for PushClient."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from odcp.collector.push_client import PushClient
from odcp.models.collector import (
    AgentConfig,
    AgentHeartbeat,
    AgentRegistration,
    AgentStatus,
)


# ── Fixtures ───────────────────────────────────────────────────────────────


def _client(token: str | None = None) -> PushClient:
    return PushClient(
        central_url="http://localhost:8080",
        agent_id="test-agent",
        api_token=token,
    )


def _registration() -> AgentRegistration:
    return AgentRegistration(
        config=AgentConfig(
            agent_id="test-agent",
            environment_name="Test",
            platform="splunk",
            scan_path="/tmp",
            central_url="http://localhost:8080",
        ),
        odcp_version="0.1.0",
    )


def _heartbeat() -> AgentHeartbeat:
    return AgentHeartbeat(
        agent_id="test-agent",
        status=AgentStatus.active,
        last_scan_timestamp=datetime.now(timezone.utc),
        last_scan_total_detections=5,
        last_scan_readiness_score=0.9,
    )


def _mock_response(status: int = 200, body: str = "{}") -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body.encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ── Header construction ─────────────────────────────────────────────────────


class TestHeaders:
    def test_no_token(self):
        client = _client()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_with_token(self):
        client = _client(token="secret-token")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer secret-token"

    def test_base_url_strips_trailing_slash(self):
        client = PushClient("http://localhost:8080/", "a")
        assert client.base == "http://localhost:8080"


# ── register ───────────────────────────────────────────────────────────────


class TestRegister:
    def test_register_success(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(201)):
            ok = _client().register(_registration())
        assert ok is True

    def test_register_failure_status(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(500)):
            ok = _client().register(_registration())
        assert ok is False

    def test_register_network_error(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            ok = _client().register(_registration())
        assert ok is False

    def test_register_http_error(self):
        err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            ok = _client().register(_registration())
        assert ok is False


# ── push_report ────────────────────────────────────────────────────────────


class TestPushReport:
    def test_push_report_success(self):
        from odcp.models.report import ScanReport, ReadinessSummary, DependencyStats
        from odcp.models.environment import Environment, Platform

        env = Environment(name="E", platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")])
        report = ScanReport(
            environment=env,
            detections=[],
            dependencies=[],
            readiness_scores=[],
            findings=[],
            readiness_summary=ReadinessSummary(
                total_detections=0, runnable=0, partially_runnable=0, blocked=0, unknown=0,
                overall_score=0.0,
            ),
            dependency_stats=DependencyStats(total=0, by_status={}, by_kind={}),
        )
        with patch("urllib.request.urlopen", return_value=_mock_response(202)):
            ok = _client().push_report(report)
        assert ok is True

    def test_push_report_server_error(self):
        from odcp.models.report import ScanReport, ReadinessSummary, DependencyStats
        from odcp.models.environment import Environment, Platform

        env = Environment(name="E", platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")])
        report = ScanReport(
            environment=env,
            detections=[],
            dependencies=[],
            readiness_scores=[],
            findings=[],
            readiness_summary=ReadinessSummary(
                total_detections=0, runnable=0, partially_runnable=0, blocked=0, unknown=0,
                overall_score=0.0,
            ),
            dependency_stats=DependencyStats(total=0, by_status={}, by_kind={}),
        )
        with patch("urllib.request.urlopen", return_value=_mock_response(503)):
            ok = _client().push_report(report)
        assert ok is False


# ── send_heartbeat ─────────────────────────────────────────────────────────


class TestHeartbeat:
    def test_heartbeat_success(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(202)):
            ok = _client().send_heartbeat(_heartbeat())
        assert ok is True

    def test_heartbeat_network_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            ok = _client().send_heartbeat(_heartbeat())
        assert ok is False


# ── deregister ─────────────────────────────────────────────────────────────


class TestDeregister:
    def test_deregister_success(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            ok = _client().deregister()
        assert ok is True

    def test_deregister_not_found(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(404)):
            ok = _client().deregister()
        assert ok is False


# ── check_health ───────────────────────────────────────────────────────────


class TestCheckHealth:
    def test_health_ok(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(200, '{"status":"ok"}')):
            ok = _client().check_health()
        assert ok is True

    def test_health_unreachable(self):
        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            ok = _client().check_health()
        assert ok is False


# ── get_fleet_summary ──────────────────────────────────────────────────────


class TestFleetSummary:
    def test_get_fleet_summary_success(self):
        payload = {"total_agents": 3, "active_agents": 2}
        with patch("urllib.request.urlopen", return_value=_mock_response(200, json.dumps(payload))):
            result = _client().get_fleet_summary()
        assert result is not None
        assert result["total_agents"] == 3

    def test_get_fleet_summary_error(self):
        with patch("urllib.request.urlopen", side_effect=Exception("unreachable")):
            result = _client().get_fleet_summary()
        assert result is None


# ── get_agent_list ─────────────────────────────────────────────────────────


class TestAgentList:
    def test_get_agent_list_success(self):
        payload = {"agents": [{"agent_id": "a1"}, {"agent_id": "a2"}]}
        with patch("urllib.request.urlopen", return_value=_mock_response(200, json.dumps(payload))):
            agents = _client().get_agent_list()
        assert agents is not None
        assert len(agents) == 2
        assert agents[0]["agent_id"] == "a1"

    def test_get_agent_list_error(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            agents = _client().get_agent_list()
        assert agents is None

    def test_get_agent_list_unexpected_format(self):
        # Server returns a list instead of {"agents": [...]}
        with patch("urllib.request.urlopen", return_value=_mock_response(200, "[]")):
            agents = _client().get_agent_list()
        # Returns None when result is not a dict
        assert agents is None
