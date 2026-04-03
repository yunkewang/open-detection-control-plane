"""ODCP collectors — gather environment data from various sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class BaseCollector(ABC):
    """Base interface for environment data collectors.

    Collectors are responsible for gathering raw environment data
    (config files, API responses) and staging them for adapter processing.
    """

    @abstractmethod
    def collect(self, target: str | Path) -> Path:
        """Collect environment data and return path to collected artifacts."""
        ...
