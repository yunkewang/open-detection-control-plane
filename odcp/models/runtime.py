"""Runtime health signal models for live environment data."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RuntimeHealthStatus(str, Enum):
    """Health status derived from runtime signals."""

    healthy = "healthy"
    degraded = "degraded"
    unhealthy = "unhealthy"
    unknown = "unknown"


class SavedSearchHealth(BaseModel):
    """Runtime health of a Splunk saved search / detection."""

    name: str
    last_run_time: Optional[datetime] = None
    next_scheduled_time: Optional[datetime] = None
    last_run_status: Optional[str] = None
    last_run_error: Optional[str] = None
    is_scheduled: bool = False
    dispatch_ttl: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class LookupHealth(BaseModel):
    """Runtime health of a lookup table or KV store collection."""

    name: str
    exists: bool = False
    lookup_type: Optional[str] = None  # "csv", "kvstore", "external"
    row_count: Optional[int] = None
    last_modified: Optional[datetime] = None
    size_bytes: Optional[int] = None
    metadata: dict = Field(default_factory=dict)


class DataModelHealth(BaseModel):
    """Runtime health of a data model and its acceleration."""

    name: str
    exists: bool = False
    acceleration_enabled: bool = False
    acceleration_complete: bool = False
    acceleration_percent: float = 0.0
    earliest_time: Optional[str] = None
    size_bytes: Optional[int] = None
    metadata: dict = Field(default_factory=dict)


class IndexHealth(BaseModel):
    """Runtime health of a Splunk index / sourcetype data flow."""

    name: str
    exists: bool = False
    total_event_count: Optional[int] = None
    last_event_time: Optional[datetime] = None
    current_size_bytes: Optional[int] = None
    is_receiving_data: bool = False
    metadata: dict = Field(default_factory=dict)


class RuntimeSignal(BaseModel):
    """A single runtime health signal associated with a dependency or detection."""

    dependency_id: Optional[str] = None
    detection_id: Optional[str] = None
    signal_type: str  # "saved_search", "lookup", "data_model", "index"
    status: RuntimeHealthStatus = RuntimeHealthStatus.unknown
    title: str
    detail: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class RuntimeHealthScore(BaseModel):
    """Combined runtime health assessment for a detection."""

    detection_id: str
    detection_name: str
    runtime_status: RuntimeHealthStatus = RuntimeHealthStatus.unknown
    runtime_score: float = Field(ge=0.0, le=1.0, default=0.0)
    signals: list[RuntimeSignal] = Field(default_factory=list)
    details: dict = Field(default_factory=dict)


class CombinedReadinessScore(BaseModel):
    """Merged static readiness + runtime health for a detection."""

    detection_id: str
    detection_name: str
    static_score: float = Field(ge=0.0, le=1.0, default=0.0)
    runtime_score: float = Field(ge=0.0, le=1.0, default=0.0)
    combined_score: float = Field(ge=0.0, le=1.0, default=0.0)
    static_status: str = "unknown"
    runtime_status: str = "unknown"
    combined_status: str = "unknown"
    details: dict = Field(default_factory=dict)


class RuntimeHealthSummary(BaseModel):
    """Aggregate runtime health across all detections."""

    total_detections: int = 0
    healthy: int = 0
    degraded: int = 0
    unhealthy: int = 0
    unknown: int = 0
    overall_runtime_score: float = 0.0
    saved_searches_checked: int = 0
    lookups_checked: int = 0
    data_models_checked: int = 0
    indexes_checked: int = 0
