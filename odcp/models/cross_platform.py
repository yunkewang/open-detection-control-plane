"""Cross-platform readiness and migration models."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Unified cross-platform readiness
# ---------------------------------------------------------------------------


class PlatformReadiness(BaseModel):
    """Readiness summary for a single platform in a cross-platform view."""

    platform_name: str
    vendor: str
    total_detections: int = 0
    runnable: int = 0
    partially_runnable: int = 0
    blocked: int = 0
    unknown: int = 0
    overall_score: float = 0.0
    total_dependencies: int = 0
    resolved_dependencies: int = 0
    missing_dependencies: int = 0
    mitre_technique_ids: list[str] = Field(default_factory=list)


class CrossPlatformSummary(BaseModel):
    """Unified readiness view across all scanned platforms."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    platforms: list[PlatformReadiness] = Field(default_factory=list)
    total_detections: int = 0
    total_platforms: int = 0
    aggregate_score: float = 0.0
    shared_mitre_techniques: list[str] = Field(default_factory=list)
    unique_mitre_by_platform: dict[str, list[str]] = Field(default_factory=dict)
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="MITRE techniques not covered by any platform.",
    )
    recommendations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection migration analysis
# ---------------------------------------------------------------------------


class MigrationComplexity(str, Enum):
    """Complexity level for migrating a detection."""

    trivial = "trivial"
    low = "low"
    medium = "medium"
    high = "high"
    infeasible = "infeasible"


class MigrationBlocker(BaseModel):
    """A specific blocker preventing straightforward migration."""

    category: str  # e.g. "platform_feature", "query_language", "data_source"
    description: str
    severity: str = "medium"  # "low", "medium", "high"


class DetectionMigrationResult(BaseModel):
    """Migration analysis result for a single detection."""

    detection_id: str
    detection_name: str
    source_platform: str
    target_platform: str
    complexity: MigrationComplexity
    feasibility_score: float = Field(ge=0.0, le=1.0)
    blockers: list[MigrationBlocker] = Field(default_factory=list)
    mapped_features: list[str] = Field(
        default_factory=list,
        description="Source features that have direct equivalents on the target.",
    )
    unmapped_features: list[str] = Field(
        default_factory=list,
        description="Source features with no direct equivalent on the target.",
    )
    effort_hours: Optional[float] = None
    notes: str = ""


class MigrationSummary(BaseModel):
    """Summary of migration analysis from one platform to another."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_platform: str
    target_platform: str
    total_detections: int = 0
    trivial: int = 0
    low_complexity: int = 0
    medium_complexity: int = 0
    high_complexity: int = 0
    infeasible: int = 0
    overall_feasibility: float = 0.0
    estimated_total_hours: float = 0.0
    common_blockers: list[MigrationBlocker] = Field(default_factory=list)
    detection_results: list[DetectionMigrationResult] = Field(default_factory=list)
