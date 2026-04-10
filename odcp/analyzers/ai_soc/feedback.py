"""Detection outcome feedback loop.

Analyzes detection execution outcomes from runtime health data and
readiness scores to identify noisy, stale, or misconfigured detections,
then proposes tuning actions.
"""

from __future__ import annotations

import logging
from typing import Sequence

from odcp.models.report import ScanReport
from odcp.models.scoring import ReadinessStatus
from odcp.models.source_catalog import FeedbackSummary, TuningProposal

logger = logging.getLogger(__name__)


class FeedbackAnalyzer:
    """Analyze detection outcomes and propose tuning actions."""

    def __init__(
        self,
        *,
        stale_threshold_days: float = 30.0,
        noisy_volume_threshold: int = 1000,
        degraded_score_threshold: float = 0.4,
    ) -> None:
        self.stale_threshold_days = stale_threshold_days
        self.noisy_volume_threshold = noisy_volume_threshold
        self.degraded_score_threshold = degraded_score_threshold

    def analyze(self, report: ScanReport) -> FeedbackSummary:
        """Analyze a scan report's detection outcomes and propose tuning."""
        proposals: list[TuningProposal] = []
        noisy_count = 0
        stale_count = 0
        healthy_count = 0

        score_map = {s.detection_id: s for s in report.readiness_scores}
        runtime = report.metadata.get("runtime_enabled", False)
        combined_scores = report.metadata.get("combined_scores", [])
        combined_map = {c.get("detection_id"): c for c in combined_scores}

        for det in report.detections:
            readiness = score_map.get(det.id)
            combined = combined_map.get(det.id, {})

            det_proposals = []

            # --- Stale detection: blocked + no runtime activity ---
            if readiness and readiness.status == ReadinessStatus.blocked:
                if det.enabled:
                    det_proposals.append(TuningProposal(
                        detection_id=det.id,
                        detection_name=det.name,
                        proposal_type="disable",
                        priority="medium",
                        rationale=(
                            "Detection is blocked by missing dependencies and "
                            "cannot produce results. Disable until dependencies are resolved."
                        ),
                        current_value="enabled=true",
                        suggested_value="enabled=false",
                    ))
                stale_count += 1
                proposals.extend(det_proposals)
                continue

            # --- Disabled detection that could run ---
            if not det.enabled and readiness and readiness.status == ReadinessStatus.runnable:
                det_proposals.append(TuningProposal(
                    detection_id=det.id,
                    detection_name=det.name,
                    proposal_type="adjust_threshold",
                    priority="low",
                    rationale=(
                        "Detection is disabled but all dependencies are resolved. "
                        "Consider re-enabling if it was disabled due to noise."
                    ),
                    current_value="enabled=false",
                    suggested_value="enabled=true",
                ))
                proposals.extend(det_proposals)
                continue

            # --- Runtime-based analysis ---
            if runtime and combined:
                runtime_status = combined.get("runtime_status", "")
                combined_status = combined.get("combined_status", "")
                runtime_score = combined.get("runtime_score", 1.0)

                # Unhealthy runtime: scheduling failures, missing lookups
                if runtime_status == "unhealthy":
                    det_proposals.append(TuningProposal(
                        detection_id=det.id,
                        detection_name=det.name,
                        proposal_type="escalate_severity",
                        priority="high",
                        rationale=(
                            "Detection has unhealthy runtime status — "
                            "scheduling failures or missing dependencies at runtime. "
                            "Investigate and fix before relying on this detection."
                        ),
                        current_value=f"runtime_score={runtime_score:.0%}",
                        suggested_value="investigate_runtime_health",
                    ))
                    stale_count += 1

                # Degraded runtime
                elif runtime_status == "degraded" and runtime_score < self.degraded_score_threshold:
                    det_proposals.append(TuningProposal(
                        detection_id=det.id,
                        detection_name=det.name,
                        proposal_type="update_query",
                        priority="medium",
                        rationale=(
                            f"Detection has degraded runtime score ({runtime_score:.0%}). "
                            f"Review data model acceleration, lookup health, or scheduling."
                        ),
                        current_value=f"runtime_score={runtime_score:.0%}",
                        suggested_value="review_runtime_dependencies",
                    ))

                elif combined_status in ("healthy", "runnable"):
                    healthy_count += 1
                    continue
            elif readiness and readiness.status == ReadinessStatus.runnable:
                healthy_count += 1
                continue

            # --- Low readiness score (partially runnable) ---
            if readiness and readiness.status == ReadinessStatus.partially_runnable:
                if readiness.missing_dependencies > 0:
                    det_proposals.append(TuningProposal(
                        detection_id=det.id,
                        detection_name=det.name,
                        proposal_type="update_query",
                        priority="medium",
                        rationale=(
                            f"Detection is partially runnable with "
                            f"{readiness.missing_dependencies} missing dependencies. "
                            f"Consider simplifying the query or resolving dependencies."
                        ),
                        current_value=f"score={readiness.score:.0%}",
                        suggested_value="resolve_dependencies_or_simplify",
                    ))

            # --- Disabled detection that could run ---
            if not det.enabled and readiness and readiness.status == ReadinessStatus.runnable:
                det_proposals.append(TuningProposal(
                    detection_id=det.id,
                    detection_name=det.name,
                    proposal_type="adjust_threshold",
                    priority="low",
                    rationale=(
                        "Detection is disabled but all dependencies are resolved. "
                        "Consider re-enabling if it was disabled due to noise."
                    ),
                    current_value="enabled=false",
                    suggested_value="enabled=true",
                ))

            if not det_proposals and readiness:
                if readiness.status == ReadinessStatus.unknown:
                    stale_count += 1
                else:
                    healthy_count += 1

            proposals.extend(det_proposals)
            if any(p.proposal_type == "disable" for p in det_proposals):
                stale_count += 1

        # Noisy detection heuristic from metadata
        noisy_count = self._detect_noisy(report, proposals)

        recommendations = self._generate_recommendations(
            proposals, noisy_count, stale_count, healthy_count, len(report.detections)
        )

        return FeedbackSummary(
            total_detections_analyzed=len(report.detections),
            noisy_detections=noisy_count,
            stale_detections=stale_count,
            healthy_detections=healthy_count,
            proposals=proposals,
            recommendations=recommendations,
        )

    def _detect_noisy(
        self,
        report: ScanReport,
        proposals: list[TuningProposal],
    ) -> int:
        """Check for noisy detections based on runtime metadata."""
        noisy_count = 0
        runtime_summary = report.metadata.get("runtime_summary", {})
        if not runtime_summary:
            return 0

        # Look for detections with high alert volumes in combined scores
        combined = report.metadata.get("combined_scores", [])
        for entry in combined:
            alert_count = entry.get("alert_count", 0)
            if alert_count > self.noisy_volume_threshold:
                noisy_count += 1
                proposals.append(TuningProposal(
                    detection_id=entry.get("detection_id", ""),
                    detection_name=entry.get("detection_name", ""),
                    proposal_type="adjust_threshold",
                    priority="high",
                    rationale=(
                        f"Detection fired {alert_count} times — "
                        f"exceeds noise threshold of {self.noisy_volume_threshold}. "
                        f"Consider tuning thresholds or adding exclusions."
                    ),
                    current_value=f"alert_count={alert_count}",
                    suggested_value="add_exclusion_or_raise_threshold",
                ))
        return noisy_count

    @staticmethod
    def _generate_recommendations(
        proposals: list[TuningProposal],
        noisy: int,
        stale: int,
        healthy: int,
        total: int,
    ) -> list[str]:
        """Generate summary recommendations."""
        recs: list[str] = []

        if total == 0:
            return ["No detections to analyze."]

        health_ratio = healthy / total if total > 0 else 0
        if health_ratio >= 0.8:
            recs.append(
                f"Good: {healthy}/{total} ({health_ratio:.0%}) detections are healthy."
            )
        elif health_ratio >= 0.5:
            recs.append(
                f"Moderate: {healthy}/{total} ({health_ratio:.0%}) detections healthy. "
                f"Review {total - healthy} non-healthy detections."
            )
        else:
            recs.append(
                f"Attention needed: Only {healthy}/{total} ({health_ratio:.0%}) detections healthy."
            )

        if stale > 0:
            recs.append(
                f"{stale} stale/blocked detection(s) should be disabled or have dependencies resolved."
            )

        if noisy > 0:
            recs.append(
                f"{noisy} noisy detection(s) need threshold tuning or exclusion rules."
            )

        disable_proposals = [p for p in proposals if p.proposal_type == "disable"]
        if disable_proposals:
            recs.append(
                f"Consider disabling {len(disable_proposals)} blocked detection(s) "
                f"to reduce noise and focus on actionable content."
            )

        high_priority = [p for p in proposals if p.priority == "high"]
        if high_priority:
            recs.append(
                f"{len(high_priority)} high-priority tuning action(s) require immediate attention."
            )

        return recs
