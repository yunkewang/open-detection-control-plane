"""Tests for data-aware migration gate."""

from odcp.analyzers.ai_soc.data_gate import DataAwareMigrationGate
from odcp.models.cross_platform import (
    DetectionMigrationResult,
    MigrationBlocker,
    MigrationComplexity,
    MigrationSummary,
)
from odcp.models.source_catalog import SourceCatalog, UnifiedSource


def _catalog(sources: list[UnifiedSource]) -> SourceCatalog:
    return SourceCatalog(
        sources=sources,
        total_sources=len(sources),
        platforms_represented=sorted({s.platform for s in sources}),
    )


def _migration(results: list[DetectionMigrationResult]) -> MigrationSummary:
    return MigrationSummary(
        source_platform="splunk",
        target_platform="chronicle",
        total_detections=len(results),
        detection_results=results,
    )


class TestDataGate:
    def test_gate_adds_blocker_for_missing_target(self) -> None:
        result = DetectionMigrationResult(
            detection_id="d1", detection_name="D1",
            source_platform="splunk", target_platform="chronicle",
            complexity=MigrationComplexity.medium,
            feasibility_score=0.7,
            mapped_features=["datamodel -> udm"],
            unmapped_features=[],
        )
        migration = _migration([result])
        target_catalog = _catalog([])  # empty target

        gated = DataAwareMigrationGate().gate(migration, target_catalog)
        d1 = gated.detection_results[0]
        data_blockers = [b for b in d1.blockers if b.category == "data_availability"]
        assert len(data_blockers) >= 1

    def test_gate_no_blocker_when_target_has_data(self) -> None:
        result = DetectionMigrationResult(
            detection_id="d1", detection_name="D1",
            source_platform="splunk", target_platform="chronicle",
            complexity=MigrationComplexity.trivial,
            feasibility_score=1.0,
            mapped_features=["datamodel -> udm"],
            unmapped_features=[],
        )
        migration = _migration([result])
        target_catalog = _catalog([
            UnifiedSource(name="udm", platform="chronicle", source_type="udm"),
        ])

        gated = DataAwareMigrationGate().gate(migration, target_catalog)
        d1 = gated.detection_results[0]
        data_blockers = [b for b in d1.blockers if b.category == "data_availability"]
        assert len(data_blockers) == 0

    def test_gate_flags_unmapped_data_features(self) -> None:
        result = DetectionMigrationResult(
            detection_id="d1", detection_name="D1",
            source_platform="splunk", target_platform="sentinel",
            complexity=MigrationComplexity.high,
            feasibility_score=0.3,
            mapped_features=[],
            unmapped_features=["datamodel", "lookup"],
        )
        migration = _migration([result])
        target_catalog = _catalog([])

        gated = DataAwareMigrationGate().gate(migration, target_catalog)
        d1 = gated.detection_results[0]
        data_blockers = [b for b in d1.blockers if b.category == "data_availability"]
        assert len(data_blockers) >= 1

    def test_common_blockers_updated(self) -> None:
        results = [
            DetectionMigrationResult(
                detection_id=f"d{i}", detection_name=f"D{i}",
                source_platform="splunk", target_platform="chronicle",
                complexity=MigrationComplexity.medium,
                feasibility_score=0.5,
                mapped_features=["datamodel -> udm"],
                unmapped_features=[],
            )
            for i in range(3)
        ]
        migration = _migration(results)
        target_catalog = _catalog([])

        gated = DataAwareMigrationGate().gate(migration, target_catalog)
        assert len(gated.common_blockers) > 0


class TestDetectionFeasibility:
    def test_all_sources_available(self) -> None:
        catalog = _catalog([
            UnifiedSource(name="auth", platform="splunk", source_type="index"),
            UnifiedSource(name="linux_secure", platform="splunk", source_type="sourcetype"),
        ])
        verdict = DataAwareMigrationGate().check_detection_feasibility(
            "Brute Force", "d1",
            ["index:auth", "sourcetype:linux_secure"],
            catalog,
        )
        assert verdict.supported is True
        assert verdict.confidence == 1.0
        assert len(verdict.missing_sources) == 0

    def test_missing_source(self) -> None:
        catalog = _catalog([
            UnifiedSource(name="auth", platform="splunk", source_type="index"),
        ])
        verdict = DataAwareMigrationGate().check_detection_feasibility(
            "D1", "d1",
            ["index:auth", "sourcetype:sysmon"],
            catalog,
        )
        assert verdict.supported is False
        assert "sysmon" in verdict.missing_sources[0]
        assert verdict.confidence == 0.5

    def test_no_requirements(self) -> None:
        catalog = _catalog([])
        verdict = DataAwareMigrationGate().check_detection_feasibility(
            "D1", "d1", [], catalog,
        )
        assert verdict.supported is True
        assert verdict.confidence == 0.5

    def test_partial_availability(self) -> None:
        catalog = _catalog([
            UnifiedSource(name="auth", platform="splunk", source_type="index"),
        ])
        verdict = DataAwareMigrationGate().check_detection_feasibility(
            "D1", "d1",
            ["index:auth", "sourcetype:missing1", "sourcetype:missing2"],
            catalog,
        )
        assert verdict.supported is False
        assert len(verdict.missing_sources) == 2
        assert len(verdict.available_sources) == 1
