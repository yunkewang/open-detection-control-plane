"""Report models."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from odcp.models.dependency import Dependency
from odcp.models.detection import Detection
from odcp.models.environment import Environment
from odcp.models.finding import Finding
from odcp.models.scoring import ReadinessScore


class DependencyStats(BaseModel):
    """Aggregate statistics about dependencies in a scan."""

    total: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class ReadinessSummary(BaseModel):
    """High-level summary of detection readiness across a scan."""

    total_detections: int = 0
    runnable: int = 0
    partially_runnable: int = 0
    blocked: int = 0
    unknown: int = 0
    overall_score: float = 0.0


class ScanReport(BaseModel):
    """Complete report produced by a scan of an environment."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    environment: Environment
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    detections: list[Detection] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    readiness_scores: list[ReadinessScore] = Field(default_factory=list)
    readiness_summary: ReadinessSummary = Field(default_factory=ReadinessSummary)
    dependency_stats: DependencyStats = Field(default_factory=DependencyStats)
    metadata: dict = Field(default_factory=dict)
