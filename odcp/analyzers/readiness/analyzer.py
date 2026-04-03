"""Readiness analyzer — classifies detections by operational readiness."""

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

logger = logging.getLogger(__name__)

_KIND_SEVERITY: dict[str, FindingSeverity] = {
    "macro": FindingSeverity.high,
    "lookup": FindingSeverity.high,
    "eventtype": FindingSeverity.medium,
    "data_model": FindingSeverity.medium,
    "saved_search": FindingSeverity.medium,
    "transform": FindingSeverity.low,
}

_KIND_REMEDIATION: dict[str, str] = {
    "macro": "Define the missing macro in macros.conf or install the app that provides it.",
    "lookup": "Ensure the lookup table or definition exists in transforms.conf and the CSV/KVStore is available.",
    "eventtype": "Define the missing eventtype in eventtypes.conf.",
    "data_model": "Verify the data model is installed and accelerated. Check for CIM compliance.",
    "saved_search": "Ensure the referenced saved search exists in savedsearches.conf.",
    "transform": "Define the missing transform in transforms.conf.",
}


class ReadinessAnalyzer:
    """Classifies detections as runnable, partially_runnable, blocked, or unknown."""

    def analyze(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
        graph: DependencyGraph,
    ) -> tuple[list[ReadinessScore], list[Finding]]:
        dep_index: dict[str, Dependency] = {d.id: d for d in dependencies}
        scores: list[ReadinessScore] = []
        findings: list[Finding] = []

        for det in detections:
            dep_ids = graph.get_detection_dependencies(det.id)
            det_deps = [dep_index[d] for d in dep_ids if d in dep_index]

            total = len(det_deps)
            resolved = sum(1 for d in det_deps if d.status == DependencyStatus.resolved)
            missing = sum(1 for d in det_deps if d.status == DependencyStatus.missing)
            degraded = sum(1 for d in det_deps if d.status == DependencyStatus.degraded)

            # Classify
            if total == 0:
                status = ReadinessStatus.unknown
                score_val = 1.0
            elif missing == 0 and degraded == 0:
                status = ReadinessStatus.runnable
                score_val = 1.0
            elif missing > 0:
                status = ReadinessStatus.blocked
                score_val = resolved / total if total else 0.0
            else:
                status = ReadinessStatus.partially_runnable
                score_val = resolved / total if total else 0.0

            # Generate findings for missing/degraded deps
            det_finding_ids: list[str] = []
            for dep in det_deps:
                if dep.status in (DependencyStatus.missing, DependencyStatus.degraded):
                    finding = self._make_finding(det, dep)
                    findings.append(finding)
                    det_finding_ids.append(finding.id)

            scores.append(
                ReadinessScore(
                    detection_id=det.id,
                    detection_name=det.name,
                    status=status,
                    score=round(score_val, 3),
                    total_dependencies=total,
                    resolved_dependencies=resolved,
                    missing_dependencies=missing,
                    findings=det_finding_ids,
                )
            )

        return scores, findings

    @staticmethod
    def _make_finding(det: Detection, dep: Dependency) -> Finding:
        kind_str = dep.kind.value
        severity = _KIND_SEVERITY.get(kind_str, FindingSeverity.medium)

        if dep.status == DependencyStatus.missing:
            category = FindingCategory.missing_dependency
            title = f"Missing {kind_str}: {dep.name}"
            desc = (
                f"Detection '{det.name}' references {kind_str} '{dep.name}' "
                f"which is not defined in the environment."
            )
        else:
            category = FindingCategory.unresolved_reference
            title = f"Degraded {kind_str}: {dep.name}"
            desc = (
                f"Detection '{det.name}' references {kind_str} '{dep.name}' "
                f"which exists but may not be fully functional."
            )

        remediation_text = _KIND_REMEDIATION.get(kind_str, "Review and resolve the dependency.")

        return Finding(
            detection_id=det.id,
            dependency_id=dep.id,
            category=category,
            severity=severity,
            title=title,
            description=desc,
            remediation=RemediationAction(
                title=f"Resolve {kind_str} '{dep.name}'",
                description=remediation_text,
                effort="medium",
                steps=[remediation_text],
            ),
        )
