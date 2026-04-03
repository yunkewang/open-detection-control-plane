"""Environment and Platform models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Platform(BaseModel):
    """A security platform or technology stack within an environment."""

    name: str
    vendor: str
    version: Optional[str] = None
    adapter_type: str


class Environment(BaseModel):
    """A deployment environment containing one or more platforms."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    platforms: list[Platform] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = Field(default_factory=dict)
