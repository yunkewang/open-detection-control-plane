"""Sigma correlation and filter models."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class CorrelationType(str, Enum):
    """Types of Sigma correlation rules."""

    event_count = "event_count"
    value_count = "value_count"
    temporal = "temporal"


class CorrelationRule(BaseModel):
    """A Sigma correlation meta-rule linking multiple detection rules.

    Correlation rules define relationships between Sigma rules, such as
    temporal ordering or threshold-based aggregation (event_count,
    value_count).  See Sigma spec v2.1.0.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    correlation_type: CorrelationType
    rule_references: list[str] = Field(
        default_factory=list,
        description="Sigma rule IDs or names referenced by this correlation.",
    )
    group_by: list[str] = Field(default_factory=list)
    timespan: Optional[str] = None  # e.g. "5m", "1h"
    condition: Optional[str] = None  # e.g. ">= 5", "< 10"
    enabled: bool = True
    source_file: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class SigmaFilter(BaseModel):
    """A Sigma filter or meta-filter for environment-specific exclusions.

    Filters modify existing Sigma rules by adding exclusion conditions
    without changing the original rule, enabling environment-specific
    tuning.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    target_rules: list[str] = Field(
        default_factory=list,
        description="Sigma rule IDs or logsource selectors this filter applies to.",
    )
    conditions: dict = Field(
        default_factory=dict,
        description="Detection-block-style exclusion conditions.",
    )
    logsource_filter: Optional[dict] = None
    enabled: bool = True
    source_file: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
