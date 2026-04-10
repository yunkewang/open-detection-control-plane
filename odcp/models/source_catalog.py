"""Unified source catalog models for AI SOC workflows.

Provides a vendor-neutral representation of data source capabilities
across all platforms, including field-level detail, ATT&CK relevance,
and health status tracking.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Source health
# ---------------------------------------------------------------------------


class SourceHealthStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"
    unavailable = "unavailable"
    unknown = "unknown"


class SourceHealth(BaseModel):
    """Live health signal for a data source."""

    status: SourceHealthStatus = SourceHealthStatus.unknown
    last_event_time: Optional[datetime] = None
    event_rate: Optional[float] = None  # events/hour, if known
    latency_seconds: Optional[float] = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Unified source entry
# ---------------------------------------------------------------------------


class SourceField(BaseModel):
    """A field or entity provided by a data source."""

    name: str
    field_type: str = "string"  # string, ip, timestamp, integer, etc.
    description: str = ""
    sample_values: list[str] = Field(default_factory=list)


class UnifiedSource(BaseModel):
    """A single data source in the unified catalog, across any platform."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    platform: str  # splunk, sigma, elastic, sentinel, chronicle
    source_type: str  # index, sourcetype, data_model, logsource, index_pattern, table, connector, udm_entity, reference_list
    observed: bool = False
    detection_count: int = 0
    fields: list[SourceField] = Field(default_factory=list)
    provides: list[str] = Field(default_factory=list)
    attack_data_sources: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    health: SourceHealth = Field(default_factory=SourceHealth)
    metadata: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Catalog aggregate
# ---------------------------------------------------------------------------


class SourceCatalog(BaseModel):
    """Unified catalog of all data sources across platforms."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    sources: list[UnifiedSource] = Field(default_factory=list)
    total_sources: int = 0
    healthy_sources: int = 0
    degraded_sources: int = 0
    unavailable_sources: int = 0
    platforms_represented: list[str] = Field(default_factory=list)
    attack_data_source_coverage: dict[str, int] = Field(
        default_factory=dict,
        description="ATT&CK data source name -> number of sources providing it.",
    )
    field_coverage: dict[str, int] = Field(
        default_factory=dict,
        description="Common field name -> number of sources providing it.",
    )


# ---------------------------------------------------------------------------
# Drift and feedback models
# ---------------------------------------------------------------------------


class DriftEvent(BaseModel):
    """A single detected change between two catalog snapshots."""

    event_type: str  # source_added, source_removed, health_changed, field_added, field_removed, detection_count_changed
    source_name: str
    platform: str
    severity: str = "info"  # info, warning, critical
    description: str = ""
    old_value: Optional[str] = None
    new_value: Optional[str] = None


class DriftSummary(BaseModel):
    """Summary of environment drift between two time points."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    sources_added: int = 0
    sources_removed: int = 0
    health_changes: int = 0
    total_drift_events: int = 0
    events: list[DriftEvent] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    recommendations: list[str] = Field(default_factory=list)


class TuningProposal(BaseModel):
    """A proposed tuning action based on detection outcome analysis."""

    detection_id: str
    detection_name: str
    proposal_type: str  # disable, adjust_threshold, update_query, add_exclusion, escalate_severity, reduce_severity
    priority: str = "medium"  # low, medium, high
    rationale: str = ""
    current_value: str = ""
    suggested_value: str = ""


class FeedbackSummary(BaseModel):
    """Summary of detection outcome feedback analysis."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    total_detections_analyzed: int = 0
    noisy_detections: int = 0
    stale_detections: int = 0
    healthy_detections: int = 0
    proposals: list[TuningProposal] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AiSocCycleResult(BaseModel):
    """Complete result of one AI SOC automation cycle."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    environment_name: str = ""
    source_catalog: Optional[SourceCatalog] = None
    drift_summary: Optional[DriftSummary] = None
    feedback_summary: Optional[FeedbackSummary] = None
    readiness_score: float = 0.0
    detectable_now: int = 0
    blocked_by_data: int = 0
    blocked_by_logic: int = 0
    threat_intel_techniques: int = 0
    coverage_score: float = 0.0
    priority_actions: list[str] = Field(default_factory=list)
