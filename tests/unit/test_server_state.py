"""Unit tests for the ReportStore server state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from odcp.models import Detection, Environment, Platform, ReadinessScore, ReadinessStatus, ScanReport
from odcp.models.report import ReadinessSummary
from odcp.server.state import ReportStore


def _make_report(name: str = "TestEnv") -> ScanReport:
    return ScanReport(
        environment=Environment(
            name=name,
            platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(id="d1", name="Rule A", search_query="index=auth"),
            Detection(id="d2", name="Rule B", search_query="index=net"),
        ],
        readiness_scores=[
            ReadinessScore(detection_id="d1", detection_name="Rule A", status=ReadinessStatus.runnable, score=1.0),
            ReadinessScore(detection_id="d2", detection_name="Rule B", status=ReadinessStatus.blocked, score=0.0,
                           total_dependencies=1, missing_dependencies=1),
        ],
        readiness_summary=ReadinessSummary(total_detections=2, runnable=1, blocked=1, overall_score=0.5),
    )


class TestReportStore:
    def test_empty_store(self):
        store = ReportStore()
        assert not store.loaded
        assert store.report is None

    def test_load_from_path(self, tmp_path: Path):
        p = tmp_path / "r.json"
        p.write_text(_make_report().model_dump_json())
        store = ReportStore(str(p))
        assert store.loaded
        assert store.report is not None
        assert store.report.environment.name == "TestEnv"

    def test_posture_dict_empty(self):
        store = ReportStore()
        assert store.posture_dict() == {}

    def test_posture_dict_loaded(self, tmp_path: Path):
        p = tmp_path / "r.json"
        p.write_text(_make_report().model_dump_json())
        store = ReportStore(str(p))
        pos = store.posture_dict()
        assert pos["environment"] == "TestEnv"
        assert pos["total"] == 2
        assert pos["runnable"] == 1
        assert pos["blocked"] == 1
        assert pos["overall_score"] == 50

    def test_missing_file_does_not_crash(self):
        store = ReportStore("/does/not/exist.json")
        assert not store.loaded

    def test_subscribe_unsubscribe(self):
        store = ReportStore()
        q = store.subscribe()
        assert q in store._subscribers
        store.unsubscribe(q)
        assert q not in store._subscribers

    def test_reload_from_path(self, tmp_path: Path):
        import asyncio
        p = tmp_path / "r.json"
        p.write_text(_make_report("EnvA").model_dump_json())
        store = ReportStore(str(p))
        assert store.report.environment.name == "EnvA"

        # Write a new report
        p.write_text(_make_report("EnvB").model_dump_json())
        asyncio.run(store.load_from_path(str(p)))
        assert store.report.environment.name == "EnvB"
