"""Dependency and KnowledgeObject models."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class DependencyKind(str, Enum):
    """The kind of dependency a detection relies on."""

    macro = "macro"
    eventtype = "eventtype"
    lookup = "lookup"
    data_model = "data_model"
    field = "field"
    tag = "tag"
    saved_search = "saved_search"
    transform = "transform"
    unknown = "unknown"


class DependencyStatus(str, Enum):
    """Resolution status of a dependency."""

    resolved = "resolved"
    missing = "missing"
    degraded = "degraded"
    unknown = "unknown"


class Dependency(BaseModel):
    """A dependency required by one or more detections."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: DependencyKind
    name: str
    status: DependencyStatus = DependencyStatus.unknown
    source_file: Optional[str] = None
    definition: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class KnowledgeObject(BaseModel):
    """A knowledge object that may satisfy a dependency."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: DependencyKind
    name: str
    source_file: Optional[str] = None
    definition: Optional[str] = None
    fields: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
