"""Local filesystem collector."""

from __future__ import annotations

from pathlib import Path

from odcp.collectors import BaseCollector


class LocalCollector(BaseCollector):
    """Collects environment data from a local filesystem path.

    This is the simplest collector — it validates that the target path
    exists and returns it. Future collectors may pull from APIs, S3,
    or remote hosts.
    """

    def collect(self, target: str | Path) -> Path:
        path = Path(target)
        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")
        if not path.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {path}")
        return path
