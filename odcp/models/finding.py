"""Finding and remediation models."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Severity levels for findings."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    """Categories of findings."""

    missing_dependency = "missing_dependency"
    unresolved_reference = "unresolved_reference"
    configuration_issue = "configuration_issue"
    data_gap = "data_gap"
    optimization_opportunity = "optimization_opportunity"


class RemediationAction(BaseModel):
    """A recommended action to remediate a finding."""

    title: str
    description: str
    effort: Literal["low", "medium", "high"]
    steps: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A finding produced by analyzing a detection against its environment."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    detection_id: str
    dependency_id: Optional[str] = None
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    remediation: Optional[RemediationAction] = None
