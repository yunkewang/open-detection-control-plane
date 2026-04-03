"""Dependency analyzer — identifies structural dependency issues."""

from __future__ import annotations

from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    Finding,
    FindingCategory,
    FindingSeverity,
)


class DependencyAnalyzer:
    """Analyzes dependency graph for structural issues and optimization opportunities."""

    def analyze(
        self,
        dependencies: list[Dependency],
        graph: DependencyGraph,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Orphaned knowledge objects (defined but unreferenced)
        for dep_id in graph.get_orphaned_dependencies():
            node_data = graph._g.nodes.get(dep_id, {})
            name = node_data.get("name", dep_id)
            kind = node_data.get("kind", "unknown")
            findings.append(
                Finding(
                    detection_id="",
                    dependency_id=dep_id,
                    category=FindingCategory.optimization_opportunity,
                    severity=FindingSeverity.info,
                    title=f"Unreferenced {kind}: {name}",
                    description=(
                        f"Knowledge object '{name}' ({kind}) is defined but not "
                        f"referenced by any detection. Consider removing if unused."
                    ),
                )
            )

        # High fan-out dependencies (single points of failure)
        for dep_id, name, count in graph.get_most_depended_on(top_n=20):
            if count >= 5:
                findings.append(
                    Finding(
                        detection_id="",
                        dependency_id=dep_id,
                        category=FindingCategory.optimization_opportunity,
                        severity=FindingSeverity.medium,
                        title=f"High-impact dependency: {name}",
                        description=(
                            f"Dependency '{name}' is referenced by {count} detections. "
                            f"If this dependency breaks, {count} detections will be affected."
                        ),
                    )
                )

        return findings
