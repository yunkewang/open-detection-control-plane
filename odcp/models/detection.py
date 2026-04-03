"""Detection models."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class DetectionSeverity(str, Enum):
    """Severity levels for detections."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Detection(BaseModel):
    """A security detection rule or search."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    search_query: str = ""
    severity: DetectionSeverity = DetectionSeverity.medium
    source_file: Optional[str] = None
    source_app: Optional[str] = None
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    references: list[str] = Field(
        default_factory=list,
        description="List of dependency IDs this detection references.",
    )
