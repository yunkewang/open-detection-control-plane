"""Coverage analyzer — maps detections to MITRE ATT&CK and finds gaps."""

from __future__ import annotations

import logging

from odcp.analyzers.coverage.data_sources import build_data_source_inventory
from odcp.analyzers.coverage.mitre_catalog import (
    TECHNIQUE_CATALOG,
    TECHNIQUE_INDEX,
    map_detection_to_techniques,
)
from odcp.models import (
    Detection,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReadinessScore,
    ReadinessStatus,
    RemediationAction,
)
from odcp.models.coverage import (
    CoverageSummary,
    DataSourceInventory,
    MitreMapping,
    TechniqueCoverage,
)

logger = logging.getLogger(__name__)


class CoverageAnalyzer:
    """Analyzes MITRE ATT&CK coverage and data source gaps.

    Given a set of detections and their readiness scores, this analyzer:
    1. Maps detections to MITRE ATT&CK techniques via heuristics.
    2. Identifies which techniques are covered, partial, or uncovered.
    3. Builds a data source inventory and identifies gaps.
    4. Generates findings for coverage gaps.
    """

    def analyze(
        self,
        detections: list[Detection],
        readiness_scores: list[ReadinessScore],
        known_indexes: list[str] | None = None,
        known_sourcetypes: list[str] | None = None,
    ) -> tuple[
        CoverageSummary,
        list[MitreMapping],
        DataSourceInventory,
        list[Finding],
    ]:
        """Run full coverage analysis."""
        score_index = {s.detection_id: s for s in readiness_scores}

        # 1. Map detections to techniques
        mappings = self._map_detections(detections)
        logger.info(
            "Mapped %d detections to MITRE techniques",
            sum(1 for m in mappings if m.technique_ids),
        )

        # 2. Build technique coverage
        coverage = self._build_coverage(
            mappings, detections, score_index
        )

        # 3. Build data source inventory
        ds_inventory = build_data_source_inventory(
            detections,
            known_indexes=known_indexes,
            known_sourcetypes=known_sourcetypes,
        )

        # 4. Generate findings
        findings = self._generate_findings(coverage, ds_inventory)

        return coverage, mappings, ds_inventory, findings

    def _map_detections(
        self, detections: list[Detection]
    ) -> list[MitreMapping]:
        """Map each detection to MITRE techniques."""
        mappings: list[MitreMapping] = []
        for det in detections:
            technique_ids = map_detection_to_techniques(
                name=det.name,
                description=det.description,
                search_query=det.search_query,
                tags=det.tags,
            )
            mappings.append(
                MitreMapping(
                    detection_id=det.id,
                    detection_name=det.name,
                    technique_ids=technique_ids,
                )
            )
        return mappings

    def _build_coverage(
        self,
        mappings: list[MitreMapping],
        detections: list[Detection],
        score_index: dict[str, ReadinessScore],
    ) -> CoverageSummary:
        """Build per-technique coverage from detection mappings."""
        # Initialize coverage for all catalog techniques
        tech_coverage: dict[str, TechniqueCoverage] = {}
        for tech in TECHNIQUE_CATALOG:
            tech_coverage[tech.technique_id] = TechniqueCoverage(
                technique_id=tech.technique_id,
                technique_name=tech.name,
                tactic=tech.tactic,
            )

        # Populate from mappings
        for mapping in mappings:
            score = score_index.get(mapping.detection_id)
            is_runnable = (
                score is not None
                and score.status == ReadinessStatus.runnable
            )
            is_blocked = (
                score is not None
                and score.status == ReadinessStatus.blocked
            )

            for tid in mapping.technique_ids:
                if tid not in tech_coverage:
                    # Technique from tag not in our catalog
                    tech_coverage[tid] = TechniqueCoverage(
                        technique_id=tid,
                        technique_name=tid,
                        tactic="unknown",
                    )
                tc = tech_coverage[tid]
                tc.detection_count += 1
                tc.detection_ids.append(mapping.detection_id)
                if is_runnable:
                    tc.runnable_count += 1
                if is_blocked:
                    tc.blocked_count += 1

        # Set coverage status
        for tc in tech_coverage.values():
            if tc.detection_count == 0:
                tc.coverage_status = "uncovered"
            elif tc.runnable_count > 0:
                tc.coverage_status = "covered"
            else:
                tc.coverage_status = "partial"

        # Compute summary
        details = list(tech_coverage.values())
        total = len(details)
        covered = sum(1 for t in details if t.coverage_status == "covered")
        partial = sum(
            1 for t in details if t.coverage_status == "partial"
        )
        uncovered = sum(
            1 for t in details if t.coverage_status == "uncovered"
        )
        score = covered / total if total else 0.0

        # By-tactic breakdown
        by_tactic: dict[str, dict[str, int]] = {}
        for tc in details:
            tactic = tc.tactic
            if tactic not in by_tactic:
                by_tactic[tactic] = {
                    "covered": 0, "partial": 0, "uncovered": 0,
                }
            by_tactic[tactic][tc.coverage_status] += 1

        return CoverageSummary(
            total_techniques_in_scope=total,
            covered=covered,
            partially_covered=partial,
            uncovered=uncovered,
            coverage_score=round(score, 3),
            by_tactic=by_tactic,
            technique_details=sorted(
                details, key=lambda t: t.coverage_status
            ),
        )

    def _generate_findings(
        self,
        coverage: CoverageSummary,
        ds_inventory: DataSourceInventory,
    ) -> list[Finding]:
        """Generate findings for coverage gaps and data source issues."""
        findings: list[Finding] = []

        # Findings for uncovered high-value techniques
        for tc in coverage.technique_details:
            if tc.coverage_status != "uncovered":
                continue
            tech = TECHNIQUE_INDEX.get(tc.technique_id)
            if not tech:
                continue

            findings.append(
                Finding(
                    detection_id="",
                    category=FindingCategory.data_gap,
                    severity=FindingSeverity.medium,
                    title=f"No coverage for {tc.technique_id}: "
                    f"{tc.technique_name}",
                    description=(
                        f"MITRE ATT&CK technique {tc.technique_id} "
                        f"({tc.technique_name}, tactic: {tc.tactic}) "
                        f"has no detections in this environment."
                    ),
                    remediation=RemediationAction(
                        title=f"Add detection for {tc.technique_id}",
                        description=(
                            f"Create a detection rule targeting "
                            f"{tc.technique_name}."
                        ),
                        effort="high",
                        steps=[
                            f"Review MITRE ATT&CK page for "
                            f"{tc.technique_id}",
                            "Identify relevant data sources: "
                            + ", ".join(tech.data_sources),
                            "Create and test a detection rule",
                            "Deploy and schedule the detection",
                        ],
                    ),
                )
            )

        # Findings for data source gaps
        for ds in ds_inventory.sources:
            if ds.expected and not ds.observed:
                findings.append(
                    Finding(
                        detection_id="",
                        category=FindingCategory.data_gap,
                        severity=(
                            FindingSeverity.high
                            if ds.detection_count >= 3
                            else FindingSeverity.medium
                        ),
                        title=f"Data source gap: {ds.source_type} "
                        f"'{ds.name}'",
                        description=(
                            f"Data source '{ds.name}' "
                            f"({ds.source_type}) is referenced by "
                            f"{ds.detection_count} detection(s) but "
                            f"has not been confirmed as active."
                        ),
                        remediation=RemediationAction(
                            title=f"Verify {ds.source_type} '{ds.name}'",
                            description=(
                                f"Confirm that {ds.source_type} "
                                f"'{ds.name}' is actively receiving "
                                f"data."
                            ),
                            effort="low",
                            steps=[
                                f"Check if {ds.source_type} "
                                f"'{ds.name}' exists in Splunk",
                                "Verify data is being ingested",
                                "Check for any data pipeline issues",
                            ],
                        ),
                    )
                )

        return findings
