"""Readiness scoring models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ReadinessStatus(str, Enum):
    """Overall readiness status of a detection."""

    runnable = "runnable"
    partially_runnable = "partially_runnable"
    blocked = "blocked"
    unknown = "unknown"


class ReadinessScore(BaseModel):
    """Readiness score for a single detection."""

    detection_id: str
    detection_name: str
    status: ReadinessStatus
    score: float = Field(ge=0.0, le=1.0)
    total_dependencies: int = 0
    resolved_dependencies: int = 0
    missing_dependencies: int = 0
    findings: list[str] = Field(
        default_factory=list,
        description="Finding IDs associated with this detection.",
    )
    details: dict = Field(default_factory=dict)
