"""AI SOC cycle orchestrator.

Ties together all AI SOC components — source inventory, drift detection,
data-aware feasibility, feedback analysis — into a single automation
cycle that can be invoked from the CLI or a scheduled job.
"""

from __future__ import annotations

import logging
from typing import Optional

from odcp.analyzers.ai_soc.drift_detector import DriftDetector
from odcp.analyzers.ai_soc.feedback import FeedbackAnalyzer
from odcp.analyzers.ai_soc.prototype import AiSocPrototypeAnalyzer
from odcp.analyzers.ai_soc.source_inventory import SourceInventoryBuilder
from odcp.models.report import ScanReport
from odcp.models.source_catalog import (
    AiSocCycleResult,
    DriftSummary,
    FeedbackSummary,
    SourceCatalog,
)

logger = logging.getLogger(__name__)


class AiSocOrchestrator:
    """Run a full AI SOC automation cycle.

    A cycle consists of:
    1. Build unified source catalog from the current scan report.
    2. Run data-aware feasibility analysis (prototype analyzer).
    3. If a baseline is provided, detect environment drift.
    4. Run feedback analysis for tuning proposals.
    5. Aggregate results and produce priority actions.
    """

    def __init__(
        self,
        *,
        stale_threshold_days: float = 30.0,
        noisy_volume_threshold: int = 1000,
    ) -> None:
        self.inventory_builder = SourceInventoryBuilder()
        self.prototype_analyzer = AiSocPrototypeAnalyzer()
        self.drift_detector = DriftDetector()
        self.feedback_analyzer = FeedbackAnalyzer(
            stale_threshold_days=stale_threshold_days,
            noisy_volume_threshold=noisy_volume_threshold,
        )

    def run_cycle(
        self,
        current: ScanReport,
        baseline: Optional[ScanReport] = None,
    ) -> AiSocCycleResult:
        """Execute a complete AI SOC automation cycle."""

        # 1. Build source catalog
        catalog = self.inventory_builder.build_from_single(current)
        logger.info(
            "Source catalog: %d sources across %s",
            catalog.total_sources,
            catalog.platforms_represented,
        )

        # 2. Data-aware feasibility
        prototype_summary = self.prototype_analyzer.analyze(current)

        # 3. Drift detection (optional)
        drift: Optional[DriftSummary] = None
        if baseline is not None:
            drift = self.drift_detector.compare_reports(baseline, current)
            logger.info(
                "Drift: %d events, risk=%.0f%%",
                drift.total_drift_events,
                drift.risk_score * 100,
            )

        # 4. Feedback analysis
        feedback = self.feedback_analyzer.analyze(current)
        logger.info(
            "Feedback: %d proposals, %d noisy, %d stale",
            len(feedback.proposals),
            feedback.noisy_detections,
            feedback.stale_detections,
        )

        # 5. Coverage score (from metadata if available)
        coverage_meta = current.metadata.get("coverage_summary", {})
        coverage_score = coverage_meta.get("coverage_score", 0.0)
        threat_intel_count = coverage_meta.get("total_techniques_in_scope", 0)

        # 6. Build priority actions
        priority_actions = self._build_priority_actions(
            catalog, prototype_summary, drift, feedback, current,
        )

        return AiSocCycleResult(
            environment_name=current.environment.name,
            source_catalog=catalog,
            drift_summary=drift,
            feedback_summary=feedback,
            readiness_score=current.readiness_summary.overall_score,
            detectable_now=prototype_summary.detectable_now,
            blocked_by_data=prototype_summary.blocked_by_data,
            blocked_by_logic=prototype_summary.blocked_by_logic,
            threat_intel_techniques=threat_intel_count,
            coverage_score=coverage_score,
            priority_actions=priority_actions,
        )

    def _build_priority_actions(
        self,
        catalog: SourceCatalog,
        prototype_summary,
        drift: Optional[DriftSummary],
        feedback: FeedbackSummary,
        report: ScanReport,
    ) -> list[str]:
        """Generate a prioritized list of actions for the SOC team."""
        actions: list[str] = []

        # Critical drift events first
        if drift and drift.risk_score > 0.5:
            actions.append(
                f"[CRITICAL] Environment drift risk at {drift.risk_score:.0%}. "
                f"Review {drift.total_drift_events} drift events."
            )
            for rec in drift.recommendations[:2]:
                actions.append(f"  - {rec}")

        # Data gaps blocking detections
        if prototype_summary.blocked_by_data > 0:
            actions.append(
                f"[HIGH] {prototype_summary.blocked_by_data} detection(s) blocked by missing data sources. "
                f"Prioritize data onboarding."
            )

        # High-priority tuning
        high_priority = [p for p in feedback.proposals if p.priority == "high"]
        if high_priority:
            actions.append(
                f"[HIGH] {len(high_priority)} detection(s) need immediate tuning "
                f"(runtime failures or excessive noise)."
            )

        # Logic gaps
        if prototype_summary.blocked_by_logic > 0:
            actions.append(
                f"[MEDIUM] {prototype_summary.blocked_by_logic} detection(s) blocked by "
                f"logic/dependency issues despite data availability."
            )

        # Stale detections
        if feedback.stale_detections > 0:
            actions.append(
                f"[MEDIUM] {feedback.stale_detections} stale detection(s) should be "
                f"disabled or have dependencies resolved."
            )

        # Coverage gaps
        rs = report.readiness_summary
        if rs.overall_score < 0.5:
            actions.append(
                f"[MEDIUM] Overall readiness at {rs.overall_score:.0%}. "
                f"Focus on resolving high-impact missing dependencies."
            )

        # Source health
        if catalog.unavailable_sources > 0:
            actions.append(
                f"[HIGH] {catalog.unavailable_sources} source(s) unavailable. "
                f"Check data pipeline health."
            )
        if catalog.degraded_sources > 0:
            actions.append(
                f"[MEDIUM] {catalog.degraded_sources} source(s) in degraded state."
            )

        # ATT&CK coverage
        if catalog.attack_data_source_coverage:
            covered = len(catalog.attack_data_source_coverage)
            total = len(set().union(
                *[[ds] for ds in catalog.attack_data_source_coverage.keys()]
            ))
            if covered < 5:
                actions.append(
                    f"[LOW] ATT&CK data source coverage is limited ({covered} data sources). "
                    f"Consider expanding telemetry."
                )

        # New sources opportunity
        if drift and drift.sources_added > 0:
            actions.append(
                f"[LOW] {drift.sources_added} new data source(s) available. "
                f"Evaluate for new detection opportunities."
            )

        if not actions:
            actions.append("No immediate actions required. Environment is stable.")

        return actions
