"""Scan engine — orchestrates the full analysis pipeline."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Optional

from odcp.adapters import BaseAdapter
from odcp.analyzers.dependency import DependencyAnalyzer
from odcp.analyzers.readiness import ReadinessAnalyzer
from odcp.analyzers.runtime import RuntimeHealthAnalyzer
from odcp.collectors.api import APICollector, RuntimeData
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

        report = ScanReport(
            environment=environment,
            detections=detections,
            dependencies=dependencies,
            findings=all_findings,
            readiness_scores=scores,
            readiness_summary=readiness_summary,
            dependency_stats=dep_stats,
        )

        return report

    def enrich_with_coverage(
        self,
        report: ScanReport,
        graph: DependencyGraph,
        known_indexes: Optional[list[str]] = None,
        known_sourcetypes: Optional[list[str]] = None,
    ) -> ScanReport:
        """Enrich an existing report with coverage and optimization analysis.

        Adds MITRE ATT&CK coverage, data source inventory, prioritized
        remediation, and what-if analysis to the report metadata.
        """
        from odcp.analyzers.coverage import CoverageAnalyzer, OptimizationAnalyzer

        logger.info("Running coverage and optimization analysis...")

        # Coverage analysis
        coverage_analyzer = CoverageAnalyzer()
        coverage, mappings, ds_inventory, coverage_findings = (
            coverage_analyzer.analyze(
                report.detections,
                report.readiness_scores,
                known_indexes=known_indexes,
                known_sourcetypes=known_sourcetypes,
            )
        )

        # Optimization analysis
        opt_analyzer = OptimizationAnalyzer()
        opt_summary, opt_findings = opt_analyzer.analyze(
            report.detections,
            report.dependencies,
            report.readiness_scores,
            graph,
        )

        logger.info(
            "Coverage: %d/%d techniques covered, %d data source gaps",
            coverage.covered,
            coverage.total_techniques_in_scope,
            ds_inventory.total_gaps,
        )
        logger.info(
            "Optimization: %d blocked, max achievable score %.0f%%",
            opt_summary.total_blocked_detections,
            opt_summary.max_achievable_score * 100,
        )

        # Merge findings
        all_findings = (
            list(report.findings)
            + coverage_findings
            + opt_findings
        )

        # Update metadata
        meta = dict(report.metadata)
        meta["coverage_enabled"] = True
        meta["coverage_summary"] = coverage.model_dump()
        meta["mitre_mappings"] = [m.model_dump() for m in mappings]
        meta["data_source_inventory"] = ds_inventory.model_dump()
        meta["optimization_summary"] = opt_summary.model_dump()

        return report.model_copy(
            update={
                "findings": all_findings,
                "metadata": meta,
            }
        )

    def scan_with_runtime(
        self,
        path: Path,
        api_collector: APICollector,
        index_names: Optional[list[str]] = None,
        static_weight: float = 0.5,
        runtime_weight: float = 0.5,
    ) -> ScanReport:
        """Run a combined static + runtime scan.

        This extends the standard scan by collecting live signals from the
        Splunk REST API and merging them with static readiness scores.
        """
        logger.info("Starting combined static + runtime scan: %s", path)

        # --- Static analysis (same as scan) ---
        environment = self.adapter.parse_environment(path)
        detections = self.adapter.parse_detections(path)
        knowledge_objects = self.adapter.parse_knowledge_objects(path)
        dependencies = self.adapter.resolve_dependencies(detections, knowledge_objects)

        graph = DependencyGraph()
        graph.build_from_scan(detections, dependencies)

        readiness_analyzer = ReadinessAnalyzer()
        static_scores, readiness_findings = readiness_analyzer.analyze(
            detections, dependencies, graph
        )

        dep_analyzer = DependencyAnalyzer()
        dep_findings = dep_analyzer.analyze(dependencies, graph)

        # --- Runtime analysis ---
        logger.info("Collecting runtime signals from Splunk API...")
        runtime_data: RuntimeData = api_collector.collect(detections, dependencies)

        # Optionally check specific indexes
        if index_names:
            api_collector.collect_index_health(index_names, runtime_data)

        runtime_analyzer = RuntimeHealthAnalyzer()
        runtime_scores, runtime_findings = runtime_analyzer.analyze(
            detections, dependencies, runtime_data, graph
        )

        # Compute combined scores
        combined_scores = runtime_analyzer.compute_combined_scores(
            static_scores, runtime_scores,
            static_weight=static_weight,
            runtime_weight=runtime_weight,
        )

        runtime_summary = runtime_analyzer.compute_runtime_summary(runtime_scores)

        # --- Merge results ---
        all_findings = readiness_findings + dep_findings + runtime_findings
        dep_stats = self._compute_dep_stats(dependencies)
        readiness_summary = self._compute_readiness_summary(static_scores)

        logger.info(
            "Combined scan complete: %d detections, %d runtime signals, %d total findings",
            len(detections),
            sum(len(s.signals) for s in runtime_scores),
            len(all_findings),
        )

        return ScanReport(
            environment=environment,
            detections=detections,
            dependencies=dependencies,
            findings=all_findings,
            readiness_scores=static_scores,
            readiness_summary=readiness_summary,
            dependency_stats=dep_stats,
            metadata={
                "runtime_enabled": True,
                "runtime_summary": runtime_summary.model_dump(),
                "combined_scores": [c.model_dump() for c in combined_scores],
                "runtime_errors": runtime_data.errors,
                "server_info": runtime_data.server_info,
                "static_weight": static_weight,
                "runtime_weight": runtime_weight,
            },
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
