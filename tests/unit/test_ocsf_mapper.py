"""Unit tests for OCSF taxonomy mapper."""

from __future__ import annotations

import pytest

from odcp.analyzers.ocsf_mapper import OCSF_CATALOG, OCSF_INDEX, OcsfMapper
from odcp.models import Dependency, DependencyKind, DependencyStatus, Detection
from odcp.models.ocsf import OcsfEventClass, OcsfMapping, OcsfNormalizationResult


@pytest.fixture()
def mapper():
    return OcsfMapper()


@pytest.fixture()
def sigma_detections_and_deps():
    """Sigma-style detections with logsource dependencies."""
    dep1 = Dependency(
        id="d1",
        kind=DependencyKind.field,
        name="logsource:process_creation",
        status=DependencyStatus.unknown,
    )
    dep2 = Dependency(
        id="d2",
        kind=DependencyKind.field,
        name="logsource:dns_query",
        status=DependencyStatus.unknown,
    )
    dep3 = Dependency(
        id="d3",
        kind=DependencyKind.field,
        name="product:windows",
        status=DependencyStatus.unknown,
    )

    det1 = Detection(
        name="PowerShell Encoded",
        search_query="test",
        references=["d1", "d3"],
    )
    det2 = Detection(
        name="DNS Exfiltration",
        search_query="test",
        references=["d2"],
    )
    det3 = Detection(
        name="No Deps",
        search_query="test",
        references=[],
    )

    return [det1, det2, det3], [dep1, dep2, dep3]


class TestOcsfCatalog:
    def test_catalog_not_empty(self):
        assert len(OCSF_CATALOG) > 0

    def test_index_matches_catalog(self):
        assert len(OCSF_INDEX) == len(OCSF_CATALOG)

    def test_event_class_fields(self):
        for cls in OCSF_CATALOG:
            assert cls.class_id > 0
            assert cls.class_name
            assert cls.category


class TestOcsfMapper:
    def test_sigma_process_creation_maps_to_process_activity(
        self, mapper, sigma_detections_and_deps
    ):
        detections, deps = sigma_detections_and_deps
        result = mapper.normalize(detections, deps, "sigma")

        assert isinstance(result, OcsfNormalizationResult)
        assert result.total_detections == 3
        assert result.mapped_detections >= 2  # det1, det2 have mappable deps
        assert result.unmapped_detections <= 1

    def test_dns_maps_to_dns_activity(self, mapper, sigma_detections_and_deps):
        detections, deps = sigma_detections_and_deps
        result = mapper.normalize(detections, deps, "sigma")

        dns_mappings = [
            m for m in result.mappings if m.ocsf_class_name == "DNS Activity"
        ]
        assert len(dns_mappings) >= 1

    def test_process_maps_to_process_activity(self, mapper, sigma_detections_and_deps):
        detections, deps = sigma_detections_and_deps
        result = mapper.normalize(detections, deps, "sigma")

        proc_mappings = [
            m for m in result.mappings if m.ocsf_class_name == "Process Activity"
        ]
        assert len(proc_mappings) >= 1

    def test_category_coverage_populated(self, mapper, sigma_detections_and_deps):
        detections, deps = sigma_detections_and_deps
        result = mapper.normalize(detections, deps, "sigma")
        assert len(result.coverage_by_category) > 0

    def test_empty_detections(self, mapper):
        result = mapper.normalize([], [], "sigma")
        assert result.total_detections == 0
        assert result.mapped_detections == 0
        assert result.mappings == []

    def test_no_matching_deps(self, mapper):
        dep = Dependency(
            id="dx",
            kind=DependencyKind.macro,
            name="custom_macro",
            status=DependencyStatus.unknown,
        )
        det = Detection(name="Test", search_query="x", references=["dx"])
        result = mapper.normalize([det], [dep], "sigma")
        assert result.unmapped_detections == 1

    def test_splunk_platform_mappings(self, mapper):
        dep = Dependency(
            id="ds",
            kind=DependencyKind.field,
            name="sysmon",
            status=DependencyStatus.unknown,
        )
        det = Detection(name="Sysmon", search_query="x", references=["ds"])
        result = mapper.normalize([det], [dep], "splunk")
        assert result.mapped_detections == 1

    def test_sentinel_platform_mappings(self, mapper):
        dep = Dependency(
            id="ds",
            kind=DependencyKind.field,
            name="SigninLogs",
            status=DependencyStatus.unknown,
        )
        det = Detection(name="Signin", search_query="x", references=["ds"])
        result = mapper.normalize([det], [dep], "sentinel")
        assert result.mapped_detections == 1


class TestOcsfModels:
    def test_event_class_creation(self):
        ec = OcsfEventClass(
            class_id=1001, class_name="File Activity", category="System Activity"
        )
        assert ec.class_id == 1001

    def test_mapping_serialization(self):
        m = OcsfMapping(
            vendor_source="logsource:process_creation",
            vendor_platform="sigma",
            ocsf_class_id=1007,
            ocsf_class_name="Process Activity",
            ocsf_category="System Activity",
            confidence=0.95,
        )
        data = m.model_dump()
        assert data["ocsf_class_id"] == 1007
        assert data["confidence"] == 0.95

    def test_normalization_result(self):
        r = OcsfNormalizationResult(
            total_detections=10,
            mapped_detections=7,
            unmapped_detections=3,
        )
        assert r.total_detections == 10
