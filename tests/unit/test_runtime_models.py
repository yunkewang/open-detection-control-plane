"""Tests for runtime health models."""

from odcp.models.runtime import (
    CombinedReadinessScore,
    DataModelHealth,
    IndexHealth,
    LookupHealth,
    RuntimeHealthScore,
    RuntimeHealthStatus,
    RuntimeHealthSummary,
    RuntimeSignal,
    SavedSearchHealth,
)


class TestRuntimeModels:
    def test_saved_search_health_defaults(self):
        h = SavedSearchHealth(name="test_search")
        assert h.name == "test_search"
        assert h.last_run_time is None
        assert h.is_scheduled is False

    def test_lookup_health(self):
        h = LookupHealth(name="my_lookup", exists=True, lookup_type="csv", row_count=1000)
        assert h.exists is True
        assert h.row_count == 1000

    def test_data_model_health(self):
        h = DataModelHealth(
            name="Network_Traffic",
            exists=True,
            acceleration_enabled=True,
            acceleration_complete=False,
            acceleration_percent=0.75,
        )
        assert h.acceleration_percent == 0.75
        assert h.acceleration_complete is False

    def test_index_health(self):
        h = IndexHealth(
            name="main",
            exists=True,
            total_event_count=1_000_000,
            is_receiving_data=True,
        )
        assert h.is_receiving_data is True
        assert h.total_event_count == 1_000_000

    def test_runtime_signal(self):
        sig = RuntimeSignal(
            detection_id="det-1",
            signal_type="saved_search",
            status=RuntimeHealthStatus.healthy,
            title="Scheduled: my_search",
        )
        assert sig.status == RuntimeHealthStatus.healthy

    def test_runtime_health_score(self):
        score = RuntimeHealthScore(
            detection_id="det-1",
            detection_name="My Detection",
            runtime_status=RuntimeHealthStatus.degraded,
            runtime_score=0.5,
        )
        assert score.runtime_score == 0.5

    def test_combined_readiness_score(self):
        cs = CombinedReadinessScore(
            detection_id="det-1",
            detection_name="My Detection",
            static_score=0.8,
            runtime_score=0.6,
            combined_score=0.7,
            static_status="runnable",
            runtime_status="degraded",
            combined_status="degraded",
        )
        assert cs.combined_score == 0.7
        assert cs.combined_status == "degraded"

    def test_runtime_health_summary(self):
        summary = RuntimeHealthSummary(
            total_detections=10,
            healthy=6,
            degraded=2,
            unhealthy=1,
            unknown=1,
            overall_runtime_score=0.75,
        )
        assert summary.total_detections == 10
        assert summary.overall_runtime_score == 0.75

    def test_json_roundtrip(self):
        score = RuntimeHealthScore(
            detection_id="det-1",
            detection_name="Test",
            runtime_status=RuntimeHealthStatus.healthy,
            runtime_score=1.0,
            signals=[
                RuntimeSignal(
                    detection_id="det-1",
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.healthy,
                    title="OK",
                )
            ],
        )
        json_str = score.model_dump_json()
        restored = RuntimeHealthScore.model_validate_json(json_str)
        assert restored.detection_id == "det-1"
        assert len(restored.signals) == 1
        assert restored.signals[0].status == RuntimeHealthStatus.healthy
