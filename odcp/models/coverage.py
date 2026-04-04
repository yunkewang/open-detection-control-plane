"""MITRE ATT&CK coverage and data source models."""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# MITRE ATT&CK taxonomy
# ---------------------------------------------------------------------------


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique or sub-technique."""

    technique_id: str  # e.g. "T1059", "T1059.001"
    name: str
    tactic: str  # e.g. "execution", "persistence"
    url: Optional[str] = None
    data_sources: list[str] = Field(default_factory=list)


class MitreMapping(BaseModel):
    """Mapping of a detection to one or more MITRE ATT&CK techniques."""

    detection_id: str
    detection_name: str
    technique_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Data source inventory
# ---------------------------------------------------------------------------


class DataSource(BaseModel):
    """A data source observed or expected in the environment."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    source_type: Optional[str] = None  # e.g. "index", "sourcetype", "data_model"
    observed: bool = False
    expected: bool = False
    detection_count: int = 0
    metadata: dict = Field(default_factory=dict)


class DataSourceInventory(BaseModel):
    """Inventory of data sources: what's present vs. what's needed."""

    sources: list[DataSource] = Field(default_factory=list)
    total_observed: int = 0
    total_expected: int = 0
    total_gaps: int = 0


# ---------------------------------------------------------------------------
# Coverage analysis results
# ---------------------------------------------------------------------------


class TechniqueCoverage(BaseModel):
    """Coverage status for a single MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    detection_count: int = 0
    runnable_count: int = 0
    blocked_count: int = 0
    detection_ids: list[str] = Field(default_factory=list)
    coverage_status: str = "uncovered"  # "covered", "partial", "uncovered"


class CoverageSummary(BaseModel):
    """Summary of MITRE ATT&CK coverage across the environment."""

    total_techniques_in_scope: int = 0
    covered: int = 0
    partially_covered: int = 0
    uncovered: int = 0
    coverage_score: float = Field(ge=0.0, le=1.0, default=0.0)
    by_tactic: dict[str, dict[str, int]] = Field(default_factory=dict)
    technique_details: list[TechniqueCoverage] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Optimization / what-if models
# ---------------------------------------------------------------------------


class RemediationPriority(BaseModel):
    """A prioritized remediation action with estimated impact."""

    rank: int
    dependency_id: Optional[str] = None
    dependency_name: str
    dependency_kind: str
    affected_detection_count: int = 0
    affected_detection_names: list[str] = Field(default_factory=list)
    blocked_detections_unblocked: int = 0
    effort: str = "medium"  # "low", "medium", "high"
    impact_score: float = Field(ge=0.0, le=1.0, default=0.0)
    description: str = ""


class WhatIfResult(BaseModel):
    """Result of a what-if analysis: if dependency X is fixed, what changes?"""

    fixed_dependency_name: str
    fixed_dependency_kind: str
    detections_unblocked: list[str] = Field(default_factory=list)
    detections_improved: list[str] = Field(default_factory=list)
    new_overall_score: float = 0.0
    score_improvement: float = 0.0


class OptimizationSummary(BaseModel):
    """Summary of optimization analysis."""

    total_blocked_detections: int = 0
    total_missing_dependencies: int = 0
    top_remediations: list[RemediationPriority] = Field(default_factory=list)
    what_if_results: list[WhatIfResult] = Field(default_factory=list)
    max_achievable_score: float = 0.0
    current_score: float = 0.0
