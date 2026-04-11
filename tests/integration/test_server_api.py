"""Integration tests for the ODCP web server API and UI routes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed; skipping server tests")
pytest.importorskip("httpx", reason="httpx not installed; skipping server tests")

from fastapi.testclient import TestClient

from odcp.models import Detection, Environment, Platform, ReadinessScore, ReadinessStatus, ScanReport
from odcp.models.report import ReadinessSummary
from odcp.server.app import create_app
from odcp.server.state import ReportStore


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_report(name: str = "TestEnv", with_coverage: bool = False) -> ScanReport:
    meta = {}
    if with_coverage:
        meta["coverage_summary"] = {
            "coverage_score": 0.6,
            "covered_techniques": 6,
            "partial_techniques": 2,
            "uncovered_techniques": 2,
            "tactic_breakdown": {"credential_access": {"covered": 2, "total": 3}},
            "techniques": [
                {"technique_id": "T1110", "technique_name": "Brute Force",
                 "tactic": "credential_access", "coverage": "covered", "detection_count": 1},
                {"technique_id": "T1566", "technique_name": "Phishing",
                 "tactic": "initial_access", "coverage": "uncovered", "detection_count": 0},
            ],
        }
    return ScanReport(
        environment=Environment(
            name=name,
            platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(id="d1", name="Login Brute Force", search_query="index=auth"),
            Detection(id="d2", name="Data Exfil", search_query="index=network"),
        ],
        readiness_scores=[
            ReadinessScore(detection_id="d1", detection_name="Login Brute Force",
                           status=ReadinessStatus.runnable, score=1.0),
            ReadinessScore(detection_id="d2", detection_name="Data Exfil",
                           status=ReadinessStatus.blocked, score=0.0,
                           total_dependencies=1, missing_dependencies=1),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=2, runnable=1, blocked=1, overall_score=0.5
        ),
        metadata=meta,
    )


def _client(report: ScanReport | None = None) -> TestClient:
    store = ReportStore()
    store.report = report or _make_report()
    app = create_app(store)
    return TestClient(app)


# ── API: /api/posture ─────────────────────────────────────────────────────────


class TestApiPosture:
    def test_returns_posture(self):
        c = _client()
        r = c.get("/api/posture")
        assert r.status_code == 200
        data = r.json()
        assert data["environment"] == "TestEnv"
        assert data["total"] == 2
        assert data["runnable"] == 1
        assert data["overall_score"] == 50

    def test_no_report_returns_404(self):
        store = ReportStore()
        app = create_app(store)
        c = TestClient(app)
        r = c.get("/api/posture")
        assert r.status_code == 404


# ── API: /api/detections ──────────────────────────────────────────────────────


class TestApiDetections:
    def test_returns_all_detections(self):
        c = _client()
        r = c.get("/api/detections")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2

    def test_filter_blocked(self):
        c = _client()
        r = c.get("/api/detections?status=blocked")
        data = r.json()
        assert data["total"] == 1
        assert data["detections"][0]["name"] == "Data Exfil"

    def test_filter_runnable(self):
        c = _client()
        r = c.get("/api/detections?status=runnable")
        data = r.json()
        assert data["total"] == 1
        assert data["detections"][0]["status"] == "runnable"

    def test_detection_has_expected_fields(self):
        c = _client()
        det = c.get("/api/detections").json()["detections"][0]
        for field in ["name", "severity", "status", "score", "missing_deps", "enabled"]:
            assert field in det


# ── API: /api/findings ────────────────────────────────────────────────────────


class TestApiFindings:
    def test_returns_findings(self):
        c = _client()
        r = c.get("/api/findings")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "findings" in data


# ── API: /api/coverage ────────────────────────────────────────────────────────


class TestApiCoverage:
    def test_no_coverage_returns_unavailable(self):
        c = _client(_make_report(with_coverage=False))
        r = c.get("/api/coverage")
        assert r.status_code == 200
        data = r.json()
        assert data["available"] is False

    def test_with_coverage_returns_data(self):
        c = _client(_make_report(with_coverage=True))
        r = c.get("/api/coverage")
        data = r.json()
        assert data["available"] is True
        assert data["coverage_score"] == 60
        assert len(data["techniques"]) == 2


# ── API: /api/sources ─────────────────────────────────────────────────────────


class TestApiSources:
    def test_returns_sources(self):
        c = _client()
        r = c.get("/api/sources")
        assert r.status_code == 200
        data = r.json()
        assert "available" in data


# ── API: /api/report/load ─────────────────────────────────────────────────────


class TestApiReportLoad:
    def test_load_valid_report(self, tmp_path: Path):
        report_file = tmp_path / "r.json"
        report_file.write_text(_make_report("Loaded").model_dump_json())
        store = ReportStore()
        app = create_app(store)
        c = TestClient(app)
        r = c.post("/api/report/load", json={"path": str(report_file)})
        assert r.status_code == 200
        assert r.json()["environment"] == "Loaded"

    def test_load_missing_file_returns_404(self):
        c = _client()
        r = c.post("/api/report/load", json={"path": "/does/not/exist.json"})
        assert r.status_code == 404

    def test_load_missing_path_param_returns_400(self):
        c = _client()
        r = c.post("/api/report/load", json={})
        assert r.status_code == 400


# ── API: /api/agent/tools ─────────────────────────────────────────────────────


class TestApiAgentTools:
    def test_returns_tool_schemas(self):
        c = _client()
        r = c.get("/api/agent/tools")
        assert r.status_code == 200
        schemas = r.json()
        assert isinstance(schemas, list)
        assert len(schemas) > 0
        assert "name" in schemas[0]


# ── UI pages ──────────────────────────────────────────────────────────────────


class TestUiPages:
    def test_dashboard_returns_html(self):
        c = _client()
        r = c.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert b"ODCP" in r.content

    def test_detections_page(self):
        c = _client()
        r = c.get("/detections")
        assert r.status_code == 200
        assert b"Detections" in r.content

    def test_coverage_page(self):
        c = _client()
        r = c.get("/coverage")
        assert r.status_code == 200
        assert b"Coverage" in r.content or b"coverage" in r.content

    def test_findings_page(self):
        c = _client()
        r = c.get("/findings")
        assert r.status_code == 200

    def test_sources_page(self):
        c = _client()
        r = c.get("/sources")
        assert r.status_code == 200

    def test_agent_page(self):
        c = _client()
        r = c.get("/agent")
        assert r.status_code == 200
        assert b"agent" in r.content.lower() or b"Agent" in r.content

    def test_detections_filter_by_status(self):
        c = _client()
        r = c.get("/detections?status=blocked")
        assert r.status_code == 200

    def test_findings_filter_by_severity(self):
        c = _client()
        r = c.get("/findings?severity=critical")
        assert r.status_code == 200

    def test_api_docs_available(self):
        c = _client()
        r = c.get("/api/docs")
        assert r.status_code == 200

    def test_dashboard_shows_environment_name(self):
        c = _client(_make_report("ProdSIEM"))
        r = c.get("/")
        assert b"ProdSIEM" in r.content

    def test_dashboard_no_report_shows_empty(self):
        store = ReportStore()
        app = create_app(store)
        c = TestClient(app)
        r = c.get("/")
        assert r.status_code == 200
        assert b"No report" in r.content
