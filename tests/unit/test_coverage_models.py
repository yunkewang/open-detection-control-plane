"""Tests for coverage and optimization models."""

from odcp.models.coverage import (
    CoverageSummary,
    DataSource,
    DataSourceInventory,
    MitreMapping,
    MitreTechnique,
    OptimizationSummary,
    RemediationPriority,
    TechniqueCoverage,
    WhatIfResult,
)


class TestCoverageModels:
    def test_mitre_technique(self):
        t = MitreTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            tactic="execution",
            data_sources=["Process", "Script"],
        )
        assert t.technique_id == "T1059.001"
        assert len(t.data_sources) == 2

    def test_mitre_mapping(self):
        m = MitreMapping(
            detection_id="d1",
            detection_name="PS Detection",
            technique_ids=["T1059.001", "T1027"],
        )
        assert len(m.technique_ids) == 2

    def test_data_source(self):
        ds = DataSource(
            name="main", source_type="index",
            observed=True, expected=True, detection_count=5,
        )
        assert ds.observed is True
        assert ds.detection_count == 5

    def test_data_source_inventory(self):
        inv = DataSourceInventory(
            sources=[
                DataSource(name="main", source_type="index", observed=True, expected=True),
                DataSource(name="missing_st", source_type="sourcetype", expected=True),
            ],
            total_observed=1,
            total_expected=2,
            total_gaps=1,
        )
        assert inv.total_gaps == 1

    def test_technique_coverage(self):
        tc = TechniqueCoverage(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="credential-access",
            detection_count=2,
            runnable_count=1,
            coverage_status="covered",
        )
        assert tc.coverage_status == "covered"

    def test_coverage_summary(self):
        cs = CoverageSummary(
            total_techniques_in_scope=25,
            covered=5,
            partially_covered=3,
            uncovered=17,
            coverage_score=0.2,
        )
        assert cs.coverage_score == 0.2

    def test_remediation_priority(self):
        rp = RemediationPriority(
            rank=1,
            dependency_name="missing_macro",
            dependency_kind="macro",
            affected_detection_count=5,
            blocked_detections_unblocked=3,
            effort="low",
            impact_score=0.9,
        )
        assert rp.rank == 1
        assert rp.blocked_detections_unblocked == 3

    def test_what_if_result(self):
        w = WhatIfResult(
            fixed_dependency_name="my_lookup",
            fixed_dependency_kind="lookup",
            detections_unblocked=["Det A", "Det B"],
            new_overall_score=0.85,
            score_improvement=0.15,
        )
        assert w.score_improvement == 0.15
        assert len(w.detections_unblocked) == 2

    def test_optimization_summary(self):
        opt = OptimizationSummary(
            total_blocked_detections=3,
            total_missing_dependencies=5,
            current_score=0.6,
            max_achievable_score=1.0,
        )
        assert opt.max_achievable_score == 1.0

    def test_json_roundtrip(self):
        cs = CoverageSummary(
            total_techniques_in_scope=10,
            covered=5,
            partially_covered=2,
            uncovered=3,
            coverage_score=0.5,
            technique_details=[
                TechniqueCoverage(
                    technique_id="T1110",
                    technique_name="Brute Force",
                    tactic="credential-access",
                    detection_count=1,
                    coverage_status="covered",
                )
            ],
        )
        json_str = cs.model_dump_json()
        restored = CoverageSummary.model_validate_json(json_str)
        assert restored.covered == 5
        assert len(restored.technique_details) == 1
