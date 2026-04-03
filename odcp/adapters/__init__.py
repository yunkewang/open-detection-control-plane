"""Adapter interface for vendor-specific integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from odcp.models import Dependency, Detection, Environment, KnowledgeObject


class BaseAdapter(ABC):
    """Base interface all vendor adapters must implement.

    An adapter is responsible for translating vendor-specific artifacts
    (config files, API responses) into the unified ODCP model.
    """

    @abstractmethod
    def parse_environment(self, path: Path) -> Environment:
        """Parse environment metadata from the given path."""
        ...

    @abstractmethod
    def parse_detections(self, path: Path) -> list[Detection]:
        """Extract detection rules from the given path."""
        ...

    @abstractmethod
    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]:
        """Extract knowledge objects (macros, lookups, eventtypes, etc.)."""
        ...

    @abstractmethod
    def resolve_dependencies(
        self,
        detections: list[Detection],
        knowledge_objects: list[KnowledgeObject],
    ) -> list[Dependency]:
        """Resolve dependencies between detections and knowledge objects."""
        ...
