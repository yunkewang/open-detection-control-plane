"""Unit tests for AgentRegistry."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from odcp.collector.registry import AgentRegistry
from odcp.models.collector import (
    AgentConfig,
    AgentHeartbeat,
    AgentInfo,
    AgentRegistration,
    AgentStatus,
)


# ── Fixtures ───────────────────────────────────────────────────────────────


def _make_config(agent_id: str = "test-agent", platform: str = "splunk") -> AgentConfig:
    return AgentConfig(
        agent_id=agent_id,
        environment_name="Test Env",
        platform=platform,
        scan_path="/tmp/scan",
        central_url="http://localhost:8080",
        scan_interval_seconds=60,
        tags=["test", "unit"],
        hostname="test-host",
    )


def _make_registration(agent_id: str = "test-agent", platform: str = "splunk") -> AgentRegistration:
    return AgentRegistration(
        config=_make_config(agent_id, platform),
        odcp_version="0.1.0",
        python_version="3.11.0",
    )


# ── Registration ───────────────────────────────────────────────────────────


class TestRegister:
    def test_register_returns_agent_info(self):
        registry = AgentRegistry()
        reg = _make_registration()
        info = registry.register(reg)
        assert isinstance(info, AgentInfo)
        assert info.agent_id == "test-agent"
        assert info.status == AgentStatus.active

    def test_register_stores_agent(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        assert "test-agent" in registry.agents

    def test_register_preserves_registered_at_on_reregister(self):
        registry = AgentRegistry()
        info1 = registry.register(_make_registration())
        first_registered_at = info1.registered_at
        # Re-register
        info2 = registry.register(_make_registration())
        assert info2.registered_at == first_registered_at

    def test_register_updates_platform(self):
        registry = AgentRegistry()
        registry.register(_make_registration("a1", "splunk"))
        info = registry.register(_make_registration("a1", "elastic"))
        assert info.platform == "elastic"

    def test_register_multiple_agents(self):
        registry = AgentRegistry()
        for i in range(5):
            registry.register(_make_registration(f"agent-{i}"))
        assert len(registry.agents) == 5

    def test_register_populates_tags(self):
        registry = AgentRegistry()
        info = registry.register(_make_registration())
        assert "test" in info.tags
        assert "unit" in info.tags


# ── Heartbeat ──────────────────────────────────────────────────────────────


class TestHeartbeat:
    def test_heartbeat_updates_status(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        hb = AgentHeartbeat(
            agent_id="test-agent",
            status=AgentStatus.degraded,
            error_message="scan timeout",
        )
        assert registry.receive_heartbeat("test-agent", hb) is True
        assert registry.agents["test-agent"].status == AgentStatus.degraded
        assert registry.agents["test-agent"].error_message == "scan timeout"

    def test_heartbeat_unknown_agent_returns_false(self):
        registry = AgentRegistry()
        hb = AgentHeartbeat(agent_id="ghost", status=AgentStatus.active)
        assert registry.receive_heartbeat("ghost", hb) is False

    def test_heartbeat_updates_scan_totals(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        now = datetime.now(timezone.utc)
        hb = AgentHeartbeat(
            agent_id="test-agent",
            status=AgentStatus.active,
            last_scan_timestamp=now,
            last_scan_total_detections=42,
            last_scan_readiness_score=0.87,
        )
        registry.receive_heartbeat("test-agent", hb)
        info = registry.agents["test-agent"]
        assert info.total_detections == 42
        assert info.readiness_score == pytest.approx(0.87)
        assert info.last_scan_timestamp == now


# ── Deregister ─────────────────────────────────────────────────────────────


class TestDeregister:
    def test_deregister_removes_agent(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        assert registry.deregister("test-agent") is True
        assert "test-agent" not in registry.agents

    def test_deregister_unknown_returns_false(self):
        registry = AgentRegistry()
        assert registry.deregister("ghost") is False

    def test_deregister_cleans_up_report(self, tmp_path):
        from odcp.models.report import ScanReport
        from odcp.models.environment import Environment, Platform
        from odcp.models.report import ReadinessSummary, DependencyStats

        registry = AgentRegistry()
        registry.register(_make_registration())

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
        registry.receive_report("test-agent", report)
        assert "test-agent" in registry.reports

        registry.deregister("test-agent")
        assert "test-agent" not in registry.reports


# ── Queries ────────────────────────────────────────────────────────────────


class TestQueries:
    def test_get_agent_returns_none_for_unknown(self):
        registry = AgentRegistry()
        assert registry.get_agent("ghost") is None

    def test_get_agent_returns_info(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        info = registry.get_agent("test-agent")
        assert info is not None
        assert info.agent_id == "test-agent"

    def test_all_agents_sorted_by_environment(self):
        registry = AgentRegistry()
        for env in ["Z-env", "A-env", "M-env"]:
            cfg = AgentConfig(
                agent_id=env.lower().replace("-", ""),
                environment_name=env,
                platform="splunk",
                scan_path="/tmp",
                central_url="http://localhost",
            )
            registry.register(AgentRegistration(config=cfg, odcp_version="0.1.0"))
        agents = registry.all_agents()
        names = [a.environment_name for a in agents]
        assert names == sorted(names)

    def test_fleet_summary_counts(self):
        registry = AgentRegistry()
        for i in range(3):
            registry.register(_make_registration(f"active-{i}"))
        # Mark one offline
        registry.agents["active-0"].status = AgentStatus.offline
        summary = registry.fleet_summary()
        assert summary.total_agents == 3
        assert summary.offline_agents == 1
        assert summary.active_agents == 2


# ── Staleness ──────────────────────────────────────────────────────────────


class TestStaleness:
    def test_stale_agent_marked_offline(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        # Manually wind back last_seen far in the past
        from datetime import timedelta
        info = registry.agents["test-agent"]
        info.last_seen = datetime.now(timezone.utc) - timedelta(hours=1)
        # scan_interval_seconds=60, threshold_multiplier=3.0 → stale after 180s
        registry._mark_stale_agents()
        assert registry.agents["test-agent"].status == AgentStatus.offline

    def test_active_agent_not_marked_offline(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        # last_seen is just now; should not be stale
        registry._mark_stale_agents()
        assert registry.agents["test-agent"].status == AgentStatus.active


# ── Persistence ────────────────────────────────────────────────────────────


class TestPersistence:
    def test_save_and_load_state(self, tmp_path):
        registry = AgentRegistry()
        registry.register(_make_registration("agent-a"))
        registry.register(_make_registration("agent-b"))

        path = tmp_path / "state.json"
        registry.save_state(path)

        registry2 = AgentRegistry()
        registry2.load_state(path)
        assert len(registry2.agents) == 2
        # Loaded agents start as offline
        for info in registry2.agents.values():
            assert info.status == AgentStatus.offline

    def test_load_missing_file_is_noop(self, tmp_path):
        registry = AgentRegistry()
        registry.load_state(tmp_path / "nonexistent.json")
        assert len(registry.agents) == 0

    def test_dump_state_returns_dict(self):
        registry = AgentRegistry()
        registry.register(_make_registration())
        state = registry.dump_state()
        assert "test-agent" in state
        assert state["test-agent"]["agent_id"] == "test-agent"


# ── Staleness asyncio task ─────────────────────────────────────────────────


def test_staleness_task_lifecycle():
    """start_staleness_checker / stop_staleness_checker round-trip."""
    registry = AgentRegistry(staleness_check_interval=0.05)

    async def run():
        await registry.start_staleness_checker()
        assert registry._staleness_task is not None
        assert not registry._staleness_task.done()
        await asyncio.sleep(0.15)
        await registry.stop_staleness_checker()
        assert registry._staleness_task.done()

    asyncio.run(run())
