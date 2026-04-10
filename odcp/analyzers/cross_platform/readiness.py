"""Unified cross-platform readiness analyzer.

Aggregates scan reports from multiple platforms into a single readiness
view, highlighting per-platform health, shared MITRE coverage, and gaps.
"""

from __future__ import annotations

import logging
import re

from odcp.models import ScanReport
from odcp.models.cross_platform import (
    CrossPlatformSummary,
    PlatformReadiness,
)

logger = logging.getLogger(__name__)

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


class CrossPlatformReadinessAnalyzer:
    """Produce a unified readiness view across multiple platform scan reports."""

    def analyze(self, reports: list[ScanReport]) -> CrossPlatformSummary:
        """Analyze multiple scan reports and return a unified summary."""
        platforms: list[PlatformReadiness] = []
        all_technique_sets: dict[str, set[str]] = {}

        for report in reports:
            pr = self._build_platform_readiness(report)
            platforms.append(pr)
            all_technique_sets[pr.platform_name] = set(pr.mitre_technique_ids)

        # Aggregate scores
        total_dets = sum(p.total_detections for p in platforms)
        if total_dets > 0:
            agg_score = sum(
                p.overall_score * p.total_detections for p in platforms
            ) / total_dets
        else:
            agg_score = 0.0

        # Cross-platform MITRE analysis
        all_techniques: set[str] = set()
        for techs in all_technique_sets.values():
            all_techniques |= techs

        # Shared: covered by 2+ platforms
        shared: list[str] = []
        for tech in sorted(all_techniques):
            count = sum(1 for ts in all_technique_sets.values() if tech in ts)
            if count >= 2:
                shared.append(tech)

        # Unique per platform
        unique_by_platform: dict[str, list[str]] = {}
        for name, techs in all_technique_sets.items():
            others = set()
            for other_name, other_techs in all_technique_sets.items():
                if other_name != name:
                    others |= other_techs
            unique = sorted(techs - others)
            if unique:
                unique_by_platform[name] = unique

        # Recommendations
        recommendations = self._generate_recommendations(platforms, shared, unique_by_platform)

        return CrossPlatformSummary(
            platforms=platforms,
            total_detections=total_dets,
            total_platforms=len(platforms),
            aggregate_score=round(agg_score, 3),
            shared_mitre_techniques=shared,
            unique_mitre_by_platform=unique_by_platform,
            recommendations=recommendations,
        )

    @staticmethod
    def _build_platform_readiness(report: ScanReport) -> PlatformReadiness:
        """Extract a PlatformReadiness from a single scan report."""
        rs = report.readiness_summary
        platform = report.environment.platforms[0] if report.environment.platforms else None

        # Extract MITRE technique IDs from all detection tags
        technique_ids: list[str] = []
        seen: set[str] = set()
        for det in report.detections:
            for tag in det.tags:
                for match in _TECHNIQUE_RE.finditer(tag):
                    tid = match.group(0)
                    if tid not in seen:
                        seen.add(tid)
                        technique_ids.append(tid)

        # Dependency stats
        ds = report.dependency_stats
        resolved = ds.by_status.get("resolved", 0)
        missing = ds.by_status.get("missing", 0)

        return PlatformReadiness(
            platform_name=platform.name if platform else "unknown",
            vendor=platform.vendor if platform else "unknown",
            total_detections=rs.total_detections,
            runnable=rs.runnable,
            partially_runnable=rs.partially_runnable,
            blocked=rs.blocked,
            unknown=rs.unknown,
            overall_score=rs.overall_score,
            total_dependencies=ds.total,
            resolved_dependencies=resolved,
            missing_dependencies=missing,
            mitre_technique_ids=technique_ids,
        )

    @staticmethod
    def _generate_recommendations(
        platforms: list[PlatformReadiness],
        shared: list[str],
        unique_by_platform: dict[str, list[str]],
    ) -> list[str]:
        """Generate actionable recommendations based on the cross-platform view."""
        recs: list[str] = []

        # Flag platforms with low readiness
        for p in platforms:
            if p.overall_score < 0.5:
                recs.append(
                    f"{p.platform_name}: Low readiness ({p.overall_score:.0%}). "
                    f"{p.missing_dependencies} missing dependencies require attention."
                )

        # Flag platforms with high blocked counts
        for p in platforms:
            if p.total_detections > 0 and p.blocked / p.total_detections > 0.3:
                recs.append(
                    f"{p.platform_name}: {p.blocked}/{p.total_detections} "
                    f"detections blocked. Resolve dependencies to improve coverage."
                )

        # Unique coverage opportunities
        for name, techs in unique_by_platform.items():
            if len(techs) > 3:
                recs.append(
                    f"{name} is the sole provider of {len(techs)} MITRE techniques. "
                    f"Consider cross-platform redundancy for resilience."
                )

        # Shared coverage benefit
        if shared:
            recs.append(
                f"{len(shared)} MITRE techniques are covered by multiple platforms, "
                f"providing detection redundancy."
            )

        return recs
