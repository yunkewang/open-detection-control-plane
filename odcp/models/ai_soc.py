"""Models for AI SOC prototyping workflows."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DataSourceCapability(BaseModel):
    """Describes a known data source and how detections can use it."""

    name: str
    source_type: str
    observed: bool = False
    detection_count: int = 0
    provides: list[str] = Field(default_factory=list)
    detection_uses: list[str] = Field(default_factory=list)


class DetectionDataDecision(BaseModel):
    """Data-aware decision for whether a detection is currently feasible."""

    detection_id: str
    detection_name: str
    decision: str  # detectable | blocked_data_gap | blocked_logic_gap | unknown
    data_supported: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    required_data_sources: list[str] = Field(default_factory=list)
    missing_data_sources: list[str] = Field(default_factory=list)
    rationale: str = ""


class AutomationActionItem(BaseModel):
    """A concrete action required to move the AI SOC loop forward."""

    phase: str
    action: str
    owner: str = "ai_soc_orchestrator"
    priority: str = "medium"


class AiSocPrototypeSummary(BaseModel):
    """Unified output for environment-aware AI SOC prototyping."""

    environment_name: str
    total_detections: int = 0
    detectable_now: int = 0
    blocked_by_data: int = 0
    blocked_by_logic: int = 0
    unknown: int = 0
    data_source_catalog: list[DataSourceCapability] = Field(default_factory=list)
    detection_decisions: list[DetectionDataDecision] = Field(default_factory=list)
    next_actions: list[AutomationActionItem] = Field(default_factory=list)
