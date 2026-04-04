"""Optimization analyzer — prioritizes remediation and runs what-if analysis."""

from __future__ import annotations

import logging

from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    DependencyStatus,
    Detection,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReadinessScore,
    ReadinessStatus,
    RemediationAction,
)
from odcp.models.coverage import (
    OptimizationSummary,
    RemediationPriority,
    WhatIfResult,
)

logger = logging.getLogger(__name__)

_EFFORT_BY_KIND: dict[str, str] = {
    "macro": "low",
    "eventtype": "low",
    "lookup": "medium",
    "data_model": "high",
    "saved_search": "medium",
    "transform": "low",
    "tag": "low",
    "field": "medium",
    "unknown": "medium",
}


class OptimizationAnalyzer:
    """Prioritizes remediation actions and simulates what-if scenarios.

    This analyzer answers:
    - What should be fixed first to unblock the most detections?
    - If I fix dependency X, how many detections unblock?
    - What is the maximum achievable readiness score?
    """

    def analyze(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
        readiness_scores: list[ReadinessScore],
        graph: DependencyGraph,
        top_n: int = 20,
    ) -> tuple[OptimizationSummary, list[Finding]]:
        """Run optimization analysis."""
        score_index = {s.detection_id: s for s in readiness_scores}
        dep_index = {d.id: d for d in dependencies}
        det_index = {d.id: d for d in detections}

        missing_deps = [
            d for d in dependencies
            if d.status == DependencyStatus.missing
        ]
        blocked = [
            s for s in readiness_scores
            if s.status == ReadinessStatus.blocked
        ]

        # 1. Rank remediation by impact
        priorities = self._rank_remediations(
            missing_deps, det_index, graph, top_n
        )

        # 2. What-if analysis for top remediation targets
        what_ifs = self._what_if_analysis(
            priorities[:top_n],
            detections,
            dependencies,
            score_index,
            dep_index,
            graph,
        )

        # 3. Compute max achievable score
        current_score = (
            sum(s.score for s in readiness_scores) / len(readiness_scores)
            if readiness_scores
            else 0.0
        )
        max_score = self._compute_max_score(
            detections, dependencies, graph
        )

        # 4. Generate findings
        findings = self._generate_findings(priorities[:5])

        summary = OptimizationSummary(
            total_blocked_detections=len(blocked),
            total_missing_dependencies=len(missing_deps),
            top_remediations=priorities[:top_n],
            what_if_results=what_ifs,
            max_achievable_score=round(max_score, 3),
            current_score=round(current_score, 3),
        )

        return summary, findings

    def _rank_remediations(
        self,
        missing_deps: list[Dependency],
        det_index: dict[str, Detection],
        graph: DependencyGraph,
        top_n: int,
    ) -> list[RemediationPriority]:
        """Rank missing dependencies by how many detections they unblock."""
        # Count unique missing dependency names (may appear multiple times)
        dep_impact: dict[str, dict] = {}

        for dep in missing_deps:
            key = f"{dep.kind.value}:{dep.name}"
            if key not in dep_impact:
                dep_impact[key] = {
                    "dep": dep,
                    "affected_det_ids": set(),
                    "blocked_ids": set(),
                }

            # Find detections that reference this dependency
            dependents = graph.get_dependency_dependents(dep.id)
            for det_id in dependents:
                dep_impact[key]["affected_det_ids"].add(det_id)
                # Check if this detection is fully blocked
                det_deps = graph.get_detection_dependencies(det_id)
                missing_count = sum(
                    1 for did in det_deps
                    if graph._g.nodes.get(did, {}).get("status")
                    == "missing"
                )
                if missing_count == 1:
                    # This is the only missing dep — fixing it unblocks
                    dep_impact[key]["blocked_ids"].add(det_id)

        # Build ranked list
        priorities: list[RemediationPriority] = []
        for rank_idx, (key, info) in enumerate(
            sorted(
                dep_impact.items(),
                key=lambda x: (
                    len(x[1]["blocked_ids"]),
                    len(x[1]["affected_det_ids"]),
                ),
                reverse=True,
            ),
            start=1,
        ):
            dep = info["dep"]
            affected_names = [
                det_index[d].name
                for d in info["affected_det_ids"]
                if d in det_index
            ]
            priorities.append(
                RemediationPriority(
                    rank=rank_idx,
                    dependency_id=dep.id,
                    dependency_name=dep.name,
                    dependency_kind=dep.kind.value,
                    affected_detection_count=len(
                        info["affected_det_ids"]
                    ),
                    affected_detection_names=affected_names,
                    blocked_detections_unblocked=len(
                        info["blocked_ids"]
                    ),
                    effort=_EFFORT_BY_KIND.get(
                        dep.kind.value, "medium"
                    ),
                    impact_score=self._compute_impact(
                        len(info["blocked_ids"]),
                        len(info["affected_det_ids"]),
                        dep.kind.value,
                    ),
                    description=(
                        f"Resolve missing {dep.kind.value} "
                        f"'{dep.name}' to unblock "
                        f"{len(info['blocked_ids'])} detection(s) "
                        f"and improve "
                        f"{len(info['affected_det_ids'])} total."
                    ),
                )
            )
            if rank_idx >= top_n:
                break

        return priorities

    def _what_if_analysis(
        self,
        priorities: list[RemediationPriority],
        detections: list[Detection],
        dependencies: list[Dependency],
        score_index: dict[str, ReadinessScore],
        dep_index: dict[str, Dependency],
        graph: DependencyGraph,
    ) -> list[WhatIfResult]:
        """Simulate what happens if each top dependency is fixed."""
        results: list[WhatIfResult] = []

        for priority in priorities:
            dep_name = priority.dependency_name
            dep_kind = priority.dependency_kind

            # Find all dependency IDs matching this name+kind
            matching_dep_ids = {
                d.id
                for d in dependencies
                if d.name == dep_name
                and d.kind.value == dep_kind
                and d.status == DependencyStatus.missing
            }

            unblocked: list[str] = []
            improved: list[str] = []

            for det in detections:
                score = score_index.get(det.id)
                if not score:
                    continue

                det_dep_ids = set(
                    graph.get_detection_dependencies(det.id)
                )
                overlap = det_dep_ids & matching_dep_ids
                if not overlap:
                    continue

                # Count remaining missing after fix
                remaining_missing = sum(
                    1
                    for did in det_dep_ids
                    if did not in overlap
                    and graph._g.nodes.get(did, {}).get("status")
                    == "missing"
                )

                if (
                    score.status == ReadinessStatus.blocked
                    and remaining_missing == 0
                ):
                    unblocked.append(det.name)
                elif score.status == ReadinessStatus.blocked:
                    improved.append(det.name)

            # Simulate new overall score
            new_scores: list[float] = []
            for s in score_index.values():
                det_dep_ids = set(
                    graph.get_detection_dependencies(s.detection_id)
                )
                overlap = det_dep_ids & matching_dep_ids
                if overlap:
                    total = s.total_dependencies
                    new_resolved = s.resolved_dependencies + len(
                        overlap
                    )
                    new_scores.append(
                        new_resolved / total if total else s.score
                    )
                else:
                    new_scores.append(s.score)

            current_avg = (
                sum(s.score for s in score_index.values())
                / len(score_index)
                if score_index
                else 0.0
            )
            new_avg = (
                sum(new_scores) / len(new_scores)
                if new_scores
                else 0.0
            )

            results.append(
                WhatIfResult(
                    fixed_dependency_name=dep_name,
                    fixed_dependency_kind=dep_kind,
                    detections_unblocked=unblocked,
                    detections_improved=improved,
                    new_overall_score=round(new_avg, 3),
                    score_improvement=round(new_avg - current_avg, 3),
                )
            )

        return results

    def _compute_max_score(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
        graph: DependencyGraph,
    ) -> float:
        """Compute the score if all missing dependencies were fixed."""
        if not detections:
            return 0.0

        scores: list[float] = []
        for det in detections:
            dep_ids = graph.get_detection_dependencies(det.id)
            total = len(dep_ids)
            if total == 0:
                scores.append(1.0)
                continue
            # With all missing resolved, only degraded remain
            degraded = sum(
                1
                for did in dep_ids
                if graph._g.nodes.get(did, {}).get("status")
                == "degraded"
            )
            scores.append((total - degraded) / total)

        return sum(scores) / len(scores) if scores else 0.0

    @staticmethod
    def _compute_impact(
        blocked_unblocked: int,
        total_affected: int,
        kind: str,
    ) -> float:
        """Compute a 0-1 impact score for a remediation."""
        # Weight: unblocking is worth more than just improving
        raw = (blocked_unblocked * 3 + total_affected) / 4
        # Normalize roughly (cap at 10 affected)
        normalized = min(raw / 10.0, 1.0)
        # Lower effort = higher impact
        effort_mult = {
            "low": 1.2, "medium": 1.0, "high": 0.8,
        }
        mult = effort_mult.get(
            _EFFORT_BY_KIND.get(kind, "medium"), 1.0
        )
        return round(min(normalized * mult, 1.0), 3)

    def _generate_findings(
        self, top_priorities: list[RemediationPriority]
    ) -> list[Finding]:
        """Generate optimization findings for top remediations."""
        findings: list[Finding] = []

        for p in top_priorities:
            if p.blocked_detections_unblocked == 0:
                continue
            findings.append(
                Finding(
                    detection_id="",
                    dependency_id=p.dependency_id,
                    category=FindingCategory.optimization_opportunity,
                    severity=FindingSeverity.high
                    if p.blocked_detections_unblocked >= 2
                    else FindingSeverity.medium,
                    title=(
                        f"Fix '{p.dependency_name}' to unblock "
                        f"{p.blocked_detections_unblocked} detection(s)"
                    ),
                    description=(
                        f"Resolving {p.dependency_kind} "
                        f"'{p.dependency_name}' would unblock "
                        f"{p.blocked_detections_unblocked} detection(s)"
                        f" and improve "
                        f"{p.affected_detection_count} total. "
                        f"Estimated effort: {p.effort}."
                    ),
                    remediation=RemediationAction(
                        title=f"Resolve {p.dependency_kind} "
                        f"'{p.dependency_name}'",
                        description=p.description,
                        effort=p.effort,
                        steps=[
                            f"Create or install the missing "
                            f"{p.dependency_kind} "
                            f"'{p.dependency_name}'",
                            "Test that dependent detections run",
                            "Verify readiness score improvement",
                        ],
                    ),
                )
            )

        return findings
