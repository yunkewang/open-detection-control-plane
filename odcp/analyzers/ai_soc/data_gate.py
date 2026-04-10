"""Data-aware gating for detection migration and generation.

Checks whether target platform data sources can support a detection
before recommending migration or enabling it in production.
"""

from __future__ import annotations

import logging
from typing import Sequence

from odcp.models.cross_platform import (
    DetectionMigrationResult,
    MigrationBlocker,
    MigrationSummary,
)
from odcp.models.source_catalog import SourceCatalog, UnifiedSource

logger = logging.getLogger(__name__)


class DataGateVerdict:
    """Result of a data-gate check for a single detection."""

    def __init__(
        self,
        detection_id: str,
        detection_name: str,
        *,
        supported: bool,
        required_sources: list[str],
        available_sources: list[str],
        missing_sources: list[str],
        confidence: float,
        rationale: str,
    ) -> None:
        self.detection_id = detection_id
        self.detection_name = detection_name
        self.supported = supported
        self.required_sources = required_sources
        self.available_sources = available_sources
        self.missing_sources = missing_sources
        self.confidence = confidence
        self.rationale = rationale


class DataAwareMigrationGate:
    """Enrich migration results with data-availability checks on the target."""

    def gate(
        self,
        migration: MigrationSummary,
        target_catalog: SourceCatalog,
    ) -> MigrationSummary:
        """Enrich a migration summary with data-aware gating.

        For each detection migration result, check whether the target
        platform catalog has the data sources needed.  Adds blockers
        when data sources are missing on the target.
        """
        target_names = {s.name.lower() for s in target_catalog.sources}
        target_types = {s.source_type.lower() for s in target_catalog.sources}

        updated_results: list[DetectionMigrationResult] = []
        data_blocked = 0

        for result in migration.detection_results:
            new_blockers = list(result.blockers)
            data_available = True

            # Check mapped features that involve data sources
            for mapped in result.mapped_features:
                # e.g. "datamodel -> udm" or "lookup -> reference_list"
                if " -> " in mapped:
                    _, target_feature = mapped.split(" -> ", 1)
                    # Check if the target feature type exists in the catalog
                    if target_feature.lower() not in target_types and target_feature.lower() not in target_names:
                        data_available = False
                        new_blockers.append(MigrationBlocker(
                            category="data_availability",
                            description=(
                                f"Target feature '{target_feature}' has no matching "
                                f"data source on {migration.target_platform}"
                            ),
                            severity="medium",
                        ))

            # Check for unmapped features that are data-related
            data_features = {"datamodel", "lookup", "data_connector", "index_pattern", "udm", "reference_list"}
            for unmapped in result.unmapped_features:
                if unmapped.lower() in data_features:
                    data_available = False
                    if not any(b.category == "data_availability" for b in new_blockers):
                        new_blockers.append(MigrationBlocker(
                            category="data_availability",
                            description=(
                                f"Data-dependent feature '{unmapped}' cannot be mapped "
                                f"and no equivalent data source found on target"
                            ),
                            severity="high",
                        ))

            if not data_available:
                data_blocked += 1

            updated_result = result.model_copy(update={"blockers": new_blockers})
            updated_results.append(updated_result)

        # Re-count common blockers
        blocker_counts: dict[str, int] = {}
        all_blockers: dict[str, MigrationBlocker] = {}
        for r in updated_results:
            for b in r.blockers:
                key = f"{b.category}:{b.description}"
                blocker_counts[key] = blocker_counts.get(key, 0) + 1
                all_blockers[key] = b
        common_blockers = [
            all_blockers[key]
            for key, count in sorted(blocker_counts.items(), key=lambda x: -x[1])
            if count >= 2
        ][:10]

        return migration.model_copy(update={
            "detection_results": updated_results,
            "common_blockers": common_blockers,
        })

    def check_detection_feasibility(
        self,
        detection_name: str,
        detection_id: str,
        required_source_types: list[str],
        catalog: SourceCatalog,
    ) -> DataGateVerdict:
        """Check if a detection's required sources exist in the catalog.

        Args:
            detection_name: Human-readable detection name.
            detection_id: Detection ID.
            required_source_types: Source types the detection needs
                (e.g. ["index:winsec", "sourcetype:sysmon"]).
            catalog: Current environment source catalog.

        Returns:
            DataGateVerdict with supported=True/False and rationale.
        """
        catalog_keys = {
            f"{s.source_type}:{s.name}".lower() for s in catalog.sources
        }
        catalog_names = {s.name.lower() for s in catalog.sources}

        available: list[str] = []
        missing: list[str] = []

        for req in required_source_types:
            if req.lower() in catalog_keys or req.split(":")[-1].lower() in catalog_names:
                available.append(req)
            else:
                missing.append(req)

        if not required_source_types:
            return DataGateVerdict(
                detection_id=detection_id,
                detection_name=detection_name,
                supported=True,
                required_sources=[],
                available_sources=[],
                missing_sources=[],
                confidence=0.5,
                rationale="No specific data source requirements identified.",
            )

        supported = len(missing) == 0
        confidence = len(available) / len(required_source_types) if required_source_types else 1.0

        if supported:
            rationale = "All required data sources are available in the environment."
        elif missing:
            rationale = f"Missing data sources: {', '.join(missing[:5])}"
        else:
            rationale = "Unable to determine data source availability."

        return DataGateVerdict(
            detection_id=detection_id,
            detection_name=detection_name,
            supported=supported,
            required_sources=required_source_types,
            available_sources=available,
            missing_sources=missing,
            confidence=round(confidence, 3),
            rationale=rationale,
        )
