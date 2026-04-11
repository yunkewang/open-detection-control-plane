"""Unit tests for CollectionAgent."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from odcp.collector.agent import CollectionAgent
from odcp.models.collector import AgentConfig, AgentStatus
from odcp.models.report import ScanReport, ReadinessSummary, DependencyStats
from odcp.models.environment import Environment, Platform


# ── Fixtures ───────────────────────────────────────────────────────────────


def _minimal_report() -> ScanReport:
    env = Environment(name="Test", platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")])
    return ScanReport(
        environment=env,
        detections=[],
        dependencies=[],
        readiness_scores=[],
        findings=[],
        readiness_summary=ReadinessSummary(
            total_detections=0, runnable=0, partially_runnable=0,
            blocked=0, unknown=0, overall_score=0.0,
        ),
        dependency_stats=DependencyStats(total=0, by_status={}, by_kind={}),
    )


def _config(**kwargs) -> AgentConfig:
    defaults = dict(
        agent_id="test-agent",
        environment_name="Test Env",
        platform="splunk",
        scan_path="/tmp",
        central_url="http://localhost:8080",
        scan_interval_seconds=300,
        hostname="test-host",
    )
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _agent(**kwargs) -> CollectionAgent:
    return CollectionAgent(config=_config(**kwargs), heartbeat_interval_seconds=60, dry_run=True)


# ── from_args factory ──────────────────────────────────────────────────────


class TestFromArgs:
    def test_from_args_creates_agent(self):
        agent = CollectionAgent.from_args(
            agent_id="my-agent",
            environment_name="Prod",
            platform="sigma",
            scan_path="/tmp/rules",
            central_url="http://server:8080",
        )
        assert agent.config.agent_id == "my-agent"
        assert agent.config.platform == "sigma"

    def test_from_args_default_interval(self):
        agent = CollectionAgent.from_args(
            agent_id="a",
            environment_name="E",
            platform="splunk",
            scan_path="/tmp",
            central_url="http://localhost",
        )
        assert agent.config.scan_interval_seconds == 300

    def test_from_args_hostname_set(self):
        agent = CollectionAgent.from_args(
            agent_id="a",
            environment_name="E",
            platform="splunk",
            scan_path="/tmp",
            central_url="http://localhost",
        )
        assert agent.config.hostname  # nonempty


# ── from_yaml factory ──────────────────────────────────────────────────────


class TestFromYaml:
    def test_from_yaml_loads_config(self, tmp_path):
        yaml_text = (
            "agent_id: yaml-agent\n"
            "environment_name: YAML Env\n"
            "platform: elastic\n"
            "scan_path: /tmp/elastic\n"
            "central_url: http://server:9000\n"
            "scan_interval_seconds: 120\n"
        )
        p = tmp_path / "agent.yaml"
        p.write_text(yaml_text)
        agent = CollectionAgent.from_yaml(p)
        assert agent.config.agent_id == "yaml-agent"
        assert agent.config.platform == "elastic"
        assert agent.config.scan_interval_seconds == 120

    def test_from_yaml_fills_hostname(self, tmp_path):
        yaml_text = (
            "agent_id: a\n"
            "environment_name: E\n"
            "platform: sigma\n"
            "scan_path: /tmp\n"
            "central_url: http://localhost\n"
        )
        p = tmp_path / "agent.yaml"
        p.write_text(yaml_text)
        agent = CollectionAgent.from_yaml(p)
        assert agent.config.hostname  # nonempty string


# ── _build_adapter ─────────────────────────────────────────────────────────


class TestBuildAdapter:
    @pytest.mark.parametrize("platform,adapter_class", [
        ("splunk", "SplunkAdapter"),
        ("sigma", "SigmaAdapter"),
        ("elastic", "ElasticAdapter"),
        ("sentinel", "SentinelAdapter"),
        ("chronicle", "ChronicleAdapter"),
    ])
    def test_build_adapter_returns_correct_type(self, platform, adapter_class):
        agent = _agent(platform=platform)
        adapter = agent._build_adapter()
        assert type(adapter).__name__ == adapter_class

    def test_build_adapter_case_insensitive(self):
        agent = _agent(platform="SPLUNK")
        adapter = agent._build_adapter()
        assert type(adapter).__name__ == "SplunkAdapter"

    def test_build_adapter_invalid_raises(self):
        agent = _agent(platform="unknown-platform")
        with pytest.raises(ValueError, match="Unknown platform"):
            agent._build_adapter()


# ── _heartbeat_due ─────────────────────────────────────────────────────────


class TestHeartbeatDue:
    def test_heartbeat_due_when_never_sent(self):
        agent = _agent()
        assert agent._heartbeat_due() is True

    def test_heartbeat_not_due_immediately_after_send(self):
        from datetime import datetime, timezone
        agent = _agent()
        agent._last_heartbeat_at = datetime.now(timezone.utc)
        assert agent._heartbeat_due() is False


# ── dry_run scan cycle ─────────────────────────────────────────────────────


class TestDryRunScan:
    def test_dry_run_scan_cycle_calls_run_scan(self):
        agent = _agent()
        report = _minimal_report()
        with patch.object(agent, "run_scan", return_value=report) as mock_scan:
            agent._run_scan_cycle()
        mock_scan.assert_called_once()
        assert agent._last_report is report
        assert agent._scan_errors == 0

    def test_dry_run_does_not_call_push(self):
        agent = _agent()
        report = _minimal_report()
        with patch.object(agent, "run_scan", return_value=report):
            with patch.object(agent.client, "push_report") as mock_push:
                agent._run_scan_cycle()
        mock_push.assert_not_called()

    def test_scan_error_increments_counter(self):
        agent = _agent()
        with patch.object(agent, "run_scan", side_effect=RuntimeError("boom")):
            agent._run_scan_cycle()
        assert agent._scan_errors == 1

    def test_scan_error_resets_on_success(self):
        agent = _agent()
        report = _minimal_report()
        with patch.object(agent, "run_scan", side_effect=RuntimeError("boom")):
            agent._run_scan_cycle()
        assert agent._scan_errors == 1
        with patch.object(agent, "run_scan", return_value=report):
            agent._run_scan_cycle()
        assert agent._scan_errors == 0


# ── start / stop ───────────────────────────────────────────────────────────


class TestStartStop:
    def test_stop_sets_running_false(self):
        agent = _agent()
        agent._running = True
        agent.stop()
        assert agent._running is False

    def test_start_runs_initial_scan_and_stops(self):
        """Agent starts, runs one scan, then stop() terminates the loop."""
        agent = CollectionAgent(
            config=_config(scan_interval_seconds=600),
            heartbeat_interval_seconds=600,
            dry_run=True,
        )
        report = _minimal_report()
        scan_count = []

        def fake_scan():
            scan_count.append(1)
            agent.stop()  # stop after first scan
            return report

        # signal.signal() can only be called from the main thread;
        # patch it out so we can run start() in a background thread.
        with patch.object(agent, "_setup_signal_handlers"):
            with patch.object(agent, "run_scan", side_effect=fake_scan):
                t = threading.Thread(target=agent.start, daemon=True)
                t.start()
                t.join(timeout=5.0)

        assert len(scan_count) >= 1
        assert not agent._running


# ── _odcp_version ──────────────────────────────────────────────────────────


class TestOdcpVersion:
    def test_version_returns_string(self):
        v = CollectionAgent._odcp_version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_hostname_returns_string(self):
        h = CollectionAgent.hostname()
        assert isinstance(h, str)
