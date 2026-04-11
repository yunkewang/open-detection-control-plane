"""Agent registry — server-side store of all registered collector agents.

``AgentRegistry`` is attached to ``app.state.agent_registry`` by the server
app factory.  It is thread-safe for read-heavy workloads (all mutations
hold a simple threading lock) and small fleet sizes (< 10k agents).

For larger deployments, swap this for a Redis- or Postgres-backed
implementation with the same interface.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from odcp.models.collector import (
    AgentHeartbeat,
    AgentInfo,
    AgentRegistration,
    AgentStatus,
    FleetSummary,
)
from odcp.models.report import ScanReport

logger = logging.getLogger(__name__)


class AgentRegistry:
    """In-memory store of registered agents and their latest reports.

    Attributes
    ----------
    agents:
        Map of ``agent_id → AgentInfo``.
    reports:
        Map of ``agent_id → ScanReport`` (latest report per agent).
    offline_threshold_multiplier:
        An agent is marked offline if it hasn't been seen for
        ``scan_interval_seconds * multiplier`` seconds.
    """

    def __init__(
        self,
        offline_threshold_multiplier: float = 3.0,
        staleness_check_interval: float = 30.0,
    ) -> None:
        self.agents: dict[str, AgentInfo] = {}
        self.reports: dict[str, ScanReport] = {}
        self.offline_threshold_multiplier = offline_threshold_multiplier
        self._lock = threading.Lock()
        self._staleness_interval = staleness_check_interval
        self._staleness_task: Optional[asyncio.Task] = None

    # ── CRUD ──────────────────────────────────────────────────────────────

    def register(self, registration: AgentRegistration) -> AgentInfo:
        """Register (or re-register) an agent and return its ``AgentInfo``."""
        cfg = registration.config
        now = datetime.now(timezone.utc)
        with self._lock:
            existing = self.agents.get(cfg.agent_id)
            info = AgentInfo(
                agent_id=cfg.agent_id,
                environment_name=cfg.environment_name,
                platform=cfg.platform,
                hostname=cfg.hostname or "unknown",
                status=AgentStatus.active,
                registered_at=existing.registered_at if existing else now,
                last_seen=now,
                scan_interval_seconds=cfg.scan_interval_seconds,
                tags=cfg.tags,
                odcp_version=registration.odcp_version,
                # Preserve last scan data if re-registering
                last_scan_timestamp=existing.last_scan_timestamp if existing else None,
                total_detections=existing.total_detections if existing else 0,
                readiness_score=existing.readiness_score if existing else 0.0,
            )
            self.agents[cfg.agent_id] = info
        logger.info("Registered agent '%s' (%s)", cfg.agent_id, cfg.environment_name)
        return info

    def receive_report(self, agent_id: str, report: ScanReport) -> bool:
        """Store the latest report from an agent and update its status."""
        with self._lock:
            info = self.agents.get(agent_id)
            if info is None:
                logger.warning("Report from unknown agent '%s' — ignoring.", agent_id)
                return False
            rs = report.readiness_summary
            info.last_seen = datetime.now(timezone.utc)
            info.last_scan_timestamp = report.scan_timestamp
            info.total_detections = rs.total_detections
            info.readiness_score = rs.overall_score
            info.status = AgentStatus.active
            info.error_message = None
            self.reports[agent_id] = report
        logger.info(
            "Received report from '%s': %d detections, score=%.0f%%",
            agent_id,
            report.readiness_summary.total_detections,
            report.readiness_summary.overall_score * 100,
        )
        return True

    def receive_heartbeat(self, agent_id: str, heartbeat: AgentHeartbeat) -> bool:
        """Update agent liveness from a heartbeat signal."""
        with self._lock:
            info = self.agents.get(agent_id)
            if info is None:
                return False
            info.last_seen = heartbeat.timestamp
            info.status = heartbeat.status
            info.error_message = heartbeat.error_message
            if heartbeat.last_scan_timestamp:
                info.last_scan_timestamp = heartbeat.last_scan_timestamp
            if heartbeat.last_scan_total_detections:
                info.total_detections = heartbeat.last_scan_total_detections
            if heartbeat.last_scan_readiness_score:
                info.readiness_score = heartbeat.last_scan_readiness_score
        return True

    def deregister(self, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        with self._lock:
            if agent_id not in self.agents:
                return False
            self.agents.pop(agent_id)
            self.reports.pop(agent_id, None)
        logger.info("Deregistered agent '%s'.", agent_id)
        return True

    # ── Queries ────────────────────────────────────────────────────────────

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        with self._lock:
            return self.agents.get(agent_id)

    def get_report(self, agent_id: str) -> Optional[ScanReport]:
        with self._lock:
            return self.reports.get(agent_id)

    def fleet_summary(self) -> FleetSummary:
        with self._lock:
            agents = list(self.agents.values())
        return FleetSummary.from_agents(agents)

    def all_agents(self) -> list[AgentInfo]:
        with self._lock:
            return sorted(self.agents.values(), key=lambda a: a.environment_name)

    # ── Staleness check ────────────────────────────────────────────────────

    async def start_staleness_checker(self) -> None:
        """Start background asyncio task that marks offline agents."""
        self._staleness_task = asyncio.create_task(self._staleness_loop())

    async def stop_staleness_checker(self) -> None:
        if self._staleness_task:
            self._staleness_task.cancel()
            try:
                await self._staleness_task
            except asyncio.CancelledError:
                pass

    async def _staleness_loop(self) -> None:
        while True:
            await asyncio.sleep(self._staleness_interval)
            self._mark_stale_agents()

    def _mark_stale_agents(self) -> None:
        with self._lock:
            for info in self.agents.values():
                if info.status == AgentStatus.offline:
                    continue
                if info.is_stale(self.offline_threshold_multiplier):
                    logger.warning("Agent '%s' marked offline (no heartbeat).", info.agent_id)
                    info.status = AgentStatus.offline

    # ── Persistence (optional) ─────────────────────────────────────────────

    def dump_state(self) -> dict:
        """Serialise registry state (agents only, not full reports)."""
        with self._lock:
            return {
                agent_id: info.model_dump(mode="json")
                for agent_id, info in self.agents.items()
            }

    def save_state(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.dump_state(), indent=2, default=str))

    def load_state(self, path: str | Path) -> None:
        """Restore agents from a saved state file."""
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text())
        with self._lock:
            for agent_id, info_dict in data.items():
                # Mark all loaded agents as offline until they re-register
                info_dict["status"] = AgentStatus.offline
                self.agents[agent_id] = AgentInfo.model_validate(info_dict)
        logger.info("Loaded %d agents from state file %s.", len(data), path)
