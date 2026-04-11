"""Distributed collection agent models.

These models describe the runtime state of remote collector agents and the
fleet-wide aggregate view of a multi-agent ODCP deployment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    """Operational status of a remote collector agent."""

    active = "active"
    degraded = "degraded"
    offline = "offline"
    unknown = "unknown"


class Platform(str, Enum):
    """Supported scan platforms for collector agents."""

    splunk = "splunk"
    sigma = "sigma"
    elastic = "elastic"
    sentinel = "sentinel"
    chronicle = "chronicle"


class AgentConfig(BaseModel):
    """Configuration for a single collector agent deployment.

    Can be serialised to/from YAML for file-based configuration or sent
    over the wire when the agent self-registers.
    """

    agent_id: str = Field(default_factory=lambda: str(uuid4()))
    environment_name: str
    platform: str
    scan_path: str
    central_url: str
    scan_interval_seconds: int = Field(300, ge=30, description="Minimum 30 s")
    api_token: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    hostname: Optional[str] = None
    # Optional platform-specific extras (e.g. Splunk REST API creds)
    extra: dict = Field(default_factory=dict)


class AgentHeartbeat(BaseModel):
    """Periodic liveness signal sent by a running collector agent."""

    agent_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: AgentStatus = AgentStatus.active
    last_scan_timestamp: Optional[datetime] = None
    last_scan_total_detections: int = 0
    last_scan_readiness_score: float = 0.0
    error_message: Optional[str] = None


class AgentRegistration(BaseModel):
    """Payload sent by an agent on startup to register with the central server."""

    config: AgentConfig
    odcp_version: str = "0.1.0"
    python_version: Optional[str] = None


class AgentInfo(BaseModel):
    """Server-side record of a registered collector agent."""

    agent_id: str
    environment_name: str
    platform: str
    hostname: str = "unknown"
    status: AgentStatus = AgentStatus.unknown
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None
    last_scan_timestamp: Optional[datetime] = None
    total_detections: int = 0
    readiness_score: float = 0.0
    scan_interval_seconds: int = 300
    tags: list[str] = Field(default_factory=list)
    odcp_version: str = "0.1.0"
    error_message: Optional[str] = None

    @property
    def seconds_since_last_seen(self) -> Optional[float]:
        if self.last_seen is None:
            return None
        return (datetime.now(timezone.utc) - self.last_seen).total_seconds()

    def is_stale(self, threshold_multiplier: float = 3.0) -> bool:
        """True if the agent has missed more than N heartbeat intervals."""
        secs = self.seconds_since_last_seen
        if secs is None:
            return False
        return secs > self.scan_interval_seconds * threshold_multiplier


class FleetSummary(BaseModel):
    """Aggregate view of all registered collector agents."""

    total_agents: int = 0
    active_agents: int = 0
    degraded_agents: int = 0
    offline_agents: int = 0
    unknown_agents: int = 0
    total_detections: int = 0
    avg_readiness_score: float = 0.0
    platforms: list[str] = Field(default_factory=list)
    agents: list[AgentInfo] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_agents(cls, agents: list[AgentInfo]) -> "FleetSummary":
        status_counts = {s: 0 for s in AgentStatus}
        for a in agents:
            status_counts[a.status] = status_counts.get(a.status, 0) + 1

        total_dets = sum(a.total_detections for a in agents)
        scores = [a.readiness_score for a in agents if a.total_detections > 0]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        platforms = sorted({a.platform for a in agents})

        return cls(
            total_agents=len(agents),
            active_agents=status_counts.get(AgentStatus.active, 0),
            degraded_agents=status_counts.get(AgentStatus.degraded, 0),
            offline_agents=status_counts.get(AgentStatus.offline, 0),
            unknown_agents=status_counts.get(AgentStatus.unknown, 0),
            total_detections=total_dets,
            avg_readiness_score=round(avg_score, 3),
            platforms=platforms,
            agents=sorted(agents, key=lambda a: a.environment_name),
        )
