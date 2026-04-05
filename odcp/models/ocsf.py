"""OCSF (Open Cybersecurity Schema Framework) taxonomy models.

Maps vendor-specific data sources and event types to OCSF event classes
for cross-platform normalization.
"""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class OcsfEventClass(BaseModel):
    """An OCSF event class from the framework catalog."""

    class_id: int
    class_name: str
    category: str  # e.g. "System Activity", "Network Activity"
    description: Optional[str] = None


class OcsfMapping(BaseModel):
    """Maps a vendor-specific data source to an OCSF event class."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    vendor_source: str  # e.g. "sysmon:process_creation", "logsource:dns_query"
    vendor_platform: str  # e.g. "splunk", "sigma", "elastic"
    ocsf_class_id: int
    ocsf_class_name: str
    ocsf_category: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    metadata: dict = Field(default_factory=dict)


class OcsfNormalizationResult(BaseModel):
    """Result of normalizing detections to OCSF taxonomy."""

    total_detections: int = 0
    mapped_detections: int = 0
    unmapped_detections: int = 0
    mappings: list[OcsfMapping] = Field(default_factory=list)
    coverage_by_category: dict[str, int] = Field(default_factory=dict)
