"""API collector — gathers runtime data from Splunk REST API."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from odcp.adapters.splunk.api_client import SplunkAPIClient, SplunkAPIError
from odcp.models import Dependency, DependencyKind, Detection
from odcp.models.runtime import (
    DataModelHealth,
    IndexHealth,
    LookupHealth,
    SavedSearchHealth,
)

logger = logging.getLogger(__name__)


@dataclass
class RuntimeData:
    """Container for all runtime health data collected from the API."""

    server_info: dict = field(default_factory=dict)
    saved_search_health: dict[str, SavedSearchHealth] = field(default_factory=dict)
    lookup_health: dict[str, LookupHealth] = field(default_factory=dict)
    data_model_health: dict[str, DataModelHealth] = field(default_factory=dict)
    index_health: dict[str, IndexHealth] = field(default_factory=dict)
    saved_search_history: dict[str, list[dict]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class APICollector:
    """Collects runtime signals from a live Splunk instance via REST API.

    Given a set of detections and their resolved dependencies, this collector
    queries the Splunk REST API for execution status, lookup health, data model
    acceleration, and index data flow.
    """

    def __init__(self, client: SplunkAPIClient) -> None:
        self.client = client

    def test_connection(self) -> dict:
        """Verify connectivity to the Splunk instance."""
        return self.client.test_connection()

    def collect(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
    ) -> RuntimeData:
        """Collect all runtime health data for the given detections/dependencies."""
        runtime_data = RuntimeData()

        # Test connection first
        try:
            runtime_data.server_info = self.client.test_connection()
            logger.info(
                "Connected to Splunk: %s (version %s)",
                runtime_data.server_info.get("serverName", "unknown"),
                runtime_data.server_info.get("version", "unknown"),
            )
        except SplunkAPIError as exc:
            runtime_data.errors.append(f"Connection failed: {exc}")
            logger.error("Failed to connect to Splunk: %s", exc)
            return runtime_data

        # Collect saved search health for each detection
        self._collect_saved_search_health(detections, runtime_data)

        # Collect dependency-specific runtime health
        self._collect_dependency_health(dependencies, runtime_data)

        return runtime_data

    def _collect_saved_search_health(
        self, detections: list[Detection], data: RuntimeData
    ) -> None:
        """Collect execution status for each detection's saved search."""
        for det in detections:
            name = det.name
            if name in data.saved_search_health:
                continue

            try:
                health = self.client.get_saved_search_health(name)
                data.saved_search_health[name] = health
            except SplunkAPIError as exc:
                data.errors.append(f"Saved search '{name}': {exc}")
                logger.warning("Failed to get health for saved search '%s': %s", name, exc)

            # Also get recent dispatch history
            try:
                history = self.client.get_saved_search_history(name, count=3)
                if history:
                    data.saved_search_history[name] = history
            except SplunkAPIError as exc:
                logger.debug("Failed to get history for '%s': %s", name, exc)

    def _collect_dependency_health(
        self, dependencies: list[Dependency], data: RuntimeData
    ) -> None:
        """Collect runtime health for each dependency by kind."""
        for dep in dependencies:
            try:
                if dep.kind == DependencyKind.lookup:
                    if dep.name not in data.lookup_health:
                        data.lookup_health[dep.name] = self.client.get_lookup_health(dep.name)

                elif dep.kind == DependencyKind.data_model:
                    if dep.name not in data.data_model_health:
                        data.data_model_health[dep.name] = self.client.get_data_model_health(
                            dep.name
                        )

            except SplunkAPIError as exc:
                data.errors.append(f"{dep.kind.value} '{dep.name}': {exc}")
                logger.warning(
                    "Failed to get runtime health for %s '%s': %s",
                    dep.kind.value,
                    dep.name,
                    exc,
                )

    def collect_index_health(self, index_names: list[str], data: RuntimeData) -> None:
        """Collect health for specific indexes (called separately as indexes
        aren't always discoverable from detection SPL)."""
        for name in index_names:
            if name in data.index_health:
                continue
            try:
                data.index_health[name] = self.client.get_index_health(name)
            except SplunkAPIError as exc:
                data.errors.append(f"Index '{name}': {exc}")
                logger.warning("Failed to get index health for '%s': %s", name, exc)
