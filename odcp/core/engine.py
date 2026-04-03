"""Scan engine — orchestrates the full analysis pipeline."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from odcp.adapters import BaseAdapter
from odcp.analyzers.dependency import DependencyAnalyzer
from odcp.analyzers.readiness import ReadinessAnalyzer
from odcp.core.graph import DependencyGraph
from odcp.models import (
    DependencyStats,
    ReadinessSummary,
    ScanReport,
)

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates a full detection readiness scan."""

    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    def scan(self, path: Path) -> ScanReport:
        """Run a complete scan against the given path."""
        logger.info("Starting scan: %s", path)

        # 1. Parse environment
        environment = self.adapter.parse_environment(path)
        logger.info("Environment: %s", environment.name)

        # 2. Parse detections
        detections = self.adapter.parse_detections(path)
        logger.info("Found %d detections", len(detections))

        # 3. Parse knowledge objects
        knowledge_objects = self.adapter.parse_knowledge_objects(path)
        logger.info("Found %d knowledge objects", len(knowledge_objects))

        # 4. Resolve dependencies
        dependencies = self.adapter.resolve_dependencies(detections, knowledge_objects)
        logger.info("Resolved %d dependencies", len(dependencies))

        # 5. Build dependency graph
        graph = DependencyGraph()
        graph.build_from_scan(detections, dependencies)
        logger.info("Graph: %d nodes, %d edges", graph.node_count, graph.edge_count)

        # 6. Run readiness analysis
        readiness_analyzer = ReadinessAnalyzer()
        scores, readiness_findings = readiness_analyzer.analyze(
            detections, dependencies, graph
        )

        # 7. Run dependency analysis
        dep_analyzer = DependencyAnalyzer()
        dep_findings = dep_analyzer.analyze(dependencies, graph)

        # 8. Combine all findings
        all_findings = readiness_findings + dep_findings

        # 9. Compute statistics
        dep_stats = self._compute_dep_stats(dependencies)
        readiness_summary = self._compute_readiness_summary(scores)

        logger.info(
            "Scan complete: %d detections, %d runnable, %d blocked",
            readiness_summary.total_detections,
            readiness_summary.runnable,
            readiness_summary.blocked,
        )

        return ScanReport(
            environment=environment,
            detections=detections,
            dependencies=dependencies,
            findings=all_findings,
            readiness_scores=scores,
            readiness_summary=readiness_summary,
            dependency_stats=dep_stats,
        )

    @staticmethod
    def _compute_dep_stats(dependencies: list) -> DependencyStats:
        kind_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        for dep in dependencies:
            kind_counts[dep.kind.value] += 1
            status_counts[dep.status.value] += 1
        return DependencyStats(
            total=len(dependencies),
            by_kind=dict(kind_counts),
            by_status=dict(status_counts),
        )

    @staticmethod
    def _compute_readiness_summary(scores: list) -> ReadinessSummary:
        total = len(scores)
        if total == 0:
            return ReadinessSummary()

        runnable = sum(1 for s in scores if s.status.value == "runnable")
        partial = sum(1 for s in scores if s.status.value == "partially_runnable")
        blocked = sum(1 for s in scores if s.status.value == "blocked")
        unknown = sum(1 for s in scores if s.status.value == "unknown")
        avg_score = sum(s.score for s in scores) / total

        return ReadinessSummary(
            total_detections=total,
            runnable=runnable,
            partially_runnable=partial,
            blocked=blocked,
            unknown=unknown,
            overall_score=round(avg_score, 3),
        )
