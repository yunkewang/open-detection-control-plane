"""Environment drift detector.

Compares two source catalogs or scan reports taken at different times
to identify changes in data source availability, health degradation,
new/removed sources, and auto-prioritize remediation actions.
"""

from __future__ import annotations

import logging

from odcp.models.report import ScanReport
from odcp.models.source_catalog import (
    DriftEvent,
    DriftSummary,
    SourceCatalog,
    SourceHealthStatus,
    UnifiedSource,
)

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detect environment drift between two catalog snapshots."""

    def compare_catalogs(
        self,
        baseline: SourceCatalog,
        current: SourceCatalog,
    ) -> DriftSummary:
        """Compare two source catalogs and produce a drift summary."""
        events: list[DriftEvent] = []

        base_map = {
            f"{s.platform}:{s.source_type}:{s.name}": s
            for s in baseline.sources
        }
        curr_map = {
            f"{s.platform}:{s.source_type}:{s.name}": s
            for s in current.sources
        }

        base_keys = set(base_map.keys())
        curr_keys = set(curr_map.keys())

        # New sources
        for key in sorted(curr_keys - base_keys):
            src = curr_map[key]
            events.append(DriftEvent(
                event_type="source_added",
                source_name=src.name,
                platform=src.platform,
                severity="info",
                description=f"New {src.source_type} source '{src.name}' appeared on {src.platform}",
                new_value=src.source_type,
            ))

        # Removed sources
        for key in sorted(base_keys - curr_keys):
            src = base_map[key]
            severity = "critical" if src.detection_count > 0 else "warning"
            events.append(DriftEvent(
                event_type="source_removed",
                source_name=src.name,
                platform=src.platform,
                severity=severity,
                description=(
                    f"Source '{src.name}' ({src.source_type}) removed from {src.platform}"
                    + (f"; {src.detection_count} detections affected" if src.detection_count > 0 else "")
                ),
                old_value=src.source_type,
            ))

        # Changes in existing sources
        for key in sorted(base_keys & curr_keys):
            base_src = base_map[key]
            curr_src = curr_map[key]
            events.extend(self._compare_sources(base_src, curr_src))

        # Score
        sources_added = sum(1 for e in events if e.event_type == "source_added")
        sources_removed = sum(1 for e in events if e.event_type == "source_removed")
        health_changes = sum(1 for e in events if e.event_type == "health_changed")

        risk_score = self._calculate_risk(events)
        recommendations = self._generate_recommendations(events, sources_removed, health_changes)

        return DriftSummary(
            sources_added=sources_added,
            sources_removed=sources_removed,
            health_changes=health_changes,
            total_drift_events=len(events),
            events=events,
            risk_score=round(risk_score, 3),
            recommendations=recommendations,
        )

    def compare_reports(
        self,
        baseline: ScanReport,
        current: ScanReport,
    ) -> DriftSummary:
        """Compare two scan reports by building catalogs and comparing them."""
        from odcp.analyzers.ai_soc.source_inventory import SourceInventoryBuilder

        builder = SourceInventoryBuilder()
        base_catalog = builder.build_from_single(baseline)
        curr_catalog = builder.build_from_single(current)
        return self.compare_catalogs(base_catalog, curr_catalog)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _compare_sources(
        self, base: UnifiedSource, curr: UnifiedSource
    ) -> list[DriftEvent]:
        """Compare two versions of the same source."""
        events: list[DriftEvent] = []

        # Health change
        if base.health.status != curr.health.status:
            severity = "info"
            if curr.health.status == SourceHealthStatus.unavailable:
                severity = "critical"
            elif curr.health.status == SourceHealthStatus.degraded:
                severity = "warning"
            elif (
                base.health.status in (SourceHealthStatus.unavailable, SourceHealthStatus.degraded)
                and curr.health.status == SourceHealthStatus.healthy
            ):
                severity = "info"

            events.append(DriftEvent(
                event_type="health_changed",
                source_name=curr.name,
                platform=curr.platform,
                severity=severity,
                description=(
                    f"Source '{curr.name}' health changed: "
                    f"{base.health.status.value} -> {curr.health.status.value}"
                ),
                old_value=base.health.status.value,
                new_value=curr.health.status.value,
            ))

        # Observation change
        if base.observed and not curr.observed:
            events.append(DriftEvent(
                event_type="source_removed",
                source_name=curr.name,
                platform=curr.platform,
                severity="critical" if curr.detection_count > 0 else "warning",
                description=f"Source '{curr.name}' was observed but is now unobserved",
                old_value="observed",
                new_value="unobserved",
            ))
        elif not base.observed and curr.observed:
            events.append(DriftEvent(
                event_type="source_added",
                source_name=curr.name,
                platform=curr.platform,
                severity="info",
                description=f"Source '{curr.name}' is now observed (previously unobserved)",
                old_value="unobserved",
                new_value="observed",
            ))

        # Detection count change
        if curr.detection_count != base.detection_count:
            delta = curr.detection_count - base.detection_count
            events.append(DriftEvent(
                event_type="detection_count_changed",
                source_name=curr.name,
                platform=curr.platform,
                severity="info",
                description=(
                    f"Source '{curr.name}' detection count changed: "
                    f"{base.detection_count} -> {curr.detection_count} "
                    f"({delta:+d})"
                ),
                old_value=str(base.detection_count),
                new_value=str(curr.detection_count),
            ))

        # New/removed fields
        base_field_names = {f.name for f in base.fields}
        curr_field_names = {f.name for f in curr.fields}
        for new_field in sorted(curr_field_names - base_field_names):
            events.append(DriftEvent(
                event_type="field_added",
                source_name=curr.name,
                platform=curr.platform,
                severity="info",
                description=f"New field '{new_field}' available on source '{curr.name}'",
                new_value=new_field,
            ))
        for old_field in sorted(base_field_names - curr_field_names):
            events.append(DriftEvent(
                event_type="field_removed",
                source_name=curr.name,
                platform=curr.platform,
                severity="warning",
                description=f"Field '{old_field}' no longer available on source '{curr.name}'",
                old_value=old_field,
            ))

        return events

    @staticmethod
    def _calculate_risk(events: list[DriftEvent]) -> float:
        """Calculate a risk score (0-1) based on drift events."""
        if not events:
            return 0.0

        severity_weights = {"critical": 1.0, "warning": 0.5, "info": 0.1}
        total_weight = sum(
            severity_weights.get(e.severity, 0.1) for e in events
        )
        # Normalize: cap at 1.0, scale so ~5 critical events = 1.0
        return min(1.0, total_weight / 5.0)

    @staticmethod
    def _generate_recommendations(
        events: list[DriftEvent],
        sources_removed: int,
        health_changes: int,
    ) -> list[str]:
        """Generate actionable recommendations based on drift events."""
        recs: list[str] = []

        critical_events = [e for e in events if e.severity == "critical"]
        if critical_events:
            removed_names = [
                e.source_name for e in critical_events
                if e.event_type == "source_removed"
            ]
            if removed_names:
                recs.append(
                    f"URGENT: {len(removed_names)} data source(s) removed that have active detections: "
                    f"{', '.join(removed_names[:5])}. Investigate immediately."
                )

            degraded = [
                e.source_name for e in critical_events
                if e.event_type == "health_changed"
            ]
            if degraded:
                recs.append(
                    f"Source health degraded to unavailable: {', '.join(degraded[:5])}. "
                    f"Check data pipeline and ingestion."
                )

        if sources_removed > 0:
            recs.append(
                f"{sources_removed} source(s) removed. Re-run readiness analysis "
                f"to identify newly blocked detections."
            )

        if health_changes > 0:
            recs.append(
                f"{health_changes} source health change(s) detected. "
                f"Review runtime health dashboard for degradation trends."
            )

        new_sources = [e for e in events if e.event_type == "source_added" and e.old_value is None]
        if new_sources:
            recs.append(
                f"{len(new_sources)} new source(s) available. "
                f"Evaluate whether previously blocked detections can now run."
            )

        return recs
