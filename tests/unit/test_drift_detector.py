"""Tests for drift detector."""

from odcp.analyzers.ai_soc.drift_detector import DriftDetector
from odcp.models import (
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary
from odcp.models.source_catalog import (
    SourceCatalog,
    SourceField,
    SourceHealth,
    SourceHealthStatus,
    UnifiedSource,
)


def _make_catalog(sources: list[UnifiedSource]) -> SourceCatalog:
    return SourceCatalog(
        sources=sources,
        total_sources=len(sources),
        platforms_represented=sorted({s.platform for s in sources}),
    )


def _src(name: str, **kw) -> UnifiedSource:
    defaults = dict(
        platform="splunk", source_type="index", observed=True, detection_count=1,
    )
    defaults.update(kw)
    return UnifiedSource(name=name, **defaults)


class TestDriftDetectorCatalogs:
    def test_no_drift(self) -> None:
        cat = _make_catalog([_src("auth"), _src("winsec")])
        drift = DriftDetector().compare_catalogs(cat, cat)
        assert drift.total_drift_events == 0
        assert drift.risk_score == 0.0

    def test_source_added(self) -> None:
        base = _make_catalog([_src("auth")])
        curr = _make_catalog([_src("auth"), _src("sysmon")])
        drift = DriftDetector().compare_catalogs(base, curr)
        assert drift.sources_added >= 1
        added = [e for e in drift.events if e.event_type == "source_added"]
        assert any(e.source_name == "sysmon" for e in added)

    def test_source_removed_critical(self) -> None:
        base = _make_catalog([_src("auth", detection_count=5), _src("winsec")])
        curr = _make_catalog([_src("winsec")])
        drift = DriftDetector().compare_catalogs(base, curr)
        assert drift.sources_removed >= 1
        removed = [e for e in drift.events if e.event_type == "source_removed"]
        assert any(e.source_name == "auth" and e.severity == "critical" for e in removed)

    def test_source_removed_no_detections_warning(self) -> None:
        base = _make_catalog([_src("auth", detection_count=0)])
        curr = _make_catalog([])
        drift = DriftDetector().compare_catalogs(base, curr)
        removed = [e for e in drift.events if e.event_type == "source_removed"]
        assert any(e.severity == "warning" for e in removed)

    def test_health_change_detected(self) -> None:
        base = _make_catalog([
            _src("auth", health=SourceHealth(status=SourceHealthStatus.healthy)),
        ])
        curr = _make_catalog([
            _src("auth", health=SourceHealth(status=SourceHealthStatus.unavailable)),
        ])
        drift = DriftDetector().compare_catalogs(base, curr)
        assert drift.health_changes >= 1
        health_evts = [e for e in drift.events if e.event_type == "health_changed"]
        assert any(e.severity == "critical" for e in health_evts)

    def test_health_recovery(self) -> None:
        base = _make_catalog([
            _src("auth", health=SourceHealth(status=SourceHealthStatus.unavailable)),
        ])
        curr = _make_catalog([
            _src("auth", health=SourceHealth(status=SourceHealthStatus.healthy)),
        ])
        drift = DriftDetector().compare_catalogs(base, curr)
        health_evts = [e for e in drift.events if e.event_type == "health_changed"]
        assert any(e.severity == "info" for e in health_evts)

    def test_detection_count_changed(self) -> None:
        base = _make_catalog([_src("auth", detection_count=3)])
        curr = _make_catalog([_src("auth", detection_count=7)])
        drift = DriftDetector().compare_catalogs(base, curr)
        count_evts = [e for e in drift.events if e.event_type == "detection_count_changed"]
        assert len(count_evts) >= 1

    def test_field_added(self) -> None:
        base = _make_catalog([_src("auth", fields=[])])
        curr = _make_catalog([
            _src("auth", fields=[SourceField(name="user.name")]),
        ])
        drift = DriftDetector().compare_catalogs(base, curr)
        field_evts = [e for e in drift.events if e.event_type == "field_added"]
        assert any(e.new_value == "user.name" for e in field_evts)

    def test_field_removed(self) -> None:
        base = _make_catalog([
            _src("auth", fields=[SourceField(name="user.name"), SourceField(name="src.ip")]),
        ])
        curr = _make_catalog([
            _src("auth", fields=[SourceField(name="user.name")]),
        ])
        drift = DriftDetector().compare_catalogs(base, curr)
        field_evts = [e for e in drift.events if e.event_type == "field_removed"]
        assert any(e.old_value == "src.ip" for e in field_evts)

    def test_risk_score_scales(self) -> None:
        base = _make_catalog([
            _src("s1", detection_count=5),
            _src("s2", detection_count=5),
            _src("s3", detection_count=5),
        ])
        curr = _make_catalog([])  # All removed with detections
        drift = DriftDetector().compare_catalogs(base, curr)
        assert drift.risk_score > 0.5

    def test_recommendations_generated(self) -> None:
        base = _make_catalog([_src("auth", detection_count=5)])
        curr = _make_catalog([])
        drift = DriftDetector().compare_catalogs(base, curr)
        assert len(drift.recommendations) > 0


class TestDriftDetectorReports:
    def test_compare_reports(self) -> None:
        base_report = ScanReport(
            environment=Environment(
                name="Lab",
                platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
            ),
            detections=[
                Detection(id="d1", name="D1", search_query="index=auth | stats count"),
            ],
            readiness_summary=ReadinessSummary(total_detections=1, runnable=1, overall_score=1.0),
        )
        curr_report = ScanReport(
            environment=Environment(
                name="Lab",
                platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
            ),
            detections=[
                Detection(id="d1", name="D1", search_query="index=auth | stats count"),
                Detection(id="d2", name="D2", search_query="index=winsec | stats count"),
            ],
            readiness_summary=ReadinessSummary(total_detections=2, runnable=2, overall_score=1.0),
        )
        drift = DriftDetector().compare_reports(base_report, curr_report)
        assert isinstance(drift.total_drift_events, int)
        # winsec index should appear as new
        new_evts = [e for e in drift.events if e.event_type == "source_added"]
        source_names = {e.source_name for e in new_evts}
        assert "winsec" in source_names
