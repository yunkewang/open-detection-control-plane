"""Integration tests for observability routes — health, metrics, SLA, compliance."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("httpx", reason="httpx not installed")

from fastapi.testclient import TestClient

from odcp.lifecycle.manager import LifecycleManager
from odcp.server.app import create_app
from odcp.server.audit import AuditLogger


# ── Health probes ─────────────────────────────────────────────────────────────


class TestHealthProbes:
    def test_liveness_always_200(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_readiness_503_when_no_report(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/health/ready")
        assert resp.status_code == 503
        assert resp.json()["report_loaded"] is False

    def test_readiness_200_when_report_loaded(self):
        from odcp.models import Detection, Environment, Platform, ScanReport
        from odcp.server.state import ReportStore

        store = ReportStore()
        store.report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
        )
        app = create_app(store=store)
        client = TestClient(app)
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        assert resp.json()["report_loaded"] is True


# ── Prometheus metrics ────────────────────────────────────────────────────────


class TestPrometheusMetrics:
    def test_metrics_endpoint_returns_text(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_contains_expected_gauges(self):
        app = create_app()
        client = TestClient(app)
        text = client.get("/metrics").text
        assert "odcp_report_loaded" in text
        assert "odcp_agents_total" in text
        assert "odcp_lifecycle_total" in text
        assert "odcp_audit_events_total" in text

    def test_metrics_report_loaded_zero_by_default(self):
        app = create_app()
        client = TestClient(app)
        text = client.get("/metrics").text
        # Should have odcp_report_loaded 0
        lines = [l for l in text.splitlines() if l.startswith("odcp_report_loaded ")]
        assert lines, "odcp_report_loaded gauge not found"
        assert lines[0].endswith(" 0")

    def test_metrics_lifecycle_by_state(self):
        lm = LifecycleManager()
        lm.get_or_create("d1", "Det1")
        app = create_app(lifecycle_manager=lm)
        client = TestClient(app)
        text = client.get("/metrics").text
        assert "odcp_lifecycle_by_state" in text
        assert 'state="draft"' in text

    def test_metrics_intel_gauges(self):
        from odcp.intel.manager import IntelManager
        from odcp.models.intel import ThreatCampaign

        intel = IntelManager()
        intel.add_campaign(ThreatCampaign(name="C1", techniques=["T1"], active=True))
        app = create_app(intel_manager=intel)
        client = TestClient(app)
        text = client.get("/metrics").text
        assert "odcp_intel_campaigns_total" in text


# ── SLA status ────────────────────────────────────────────────────────────────


class TestSlaStatus:
    def test_sla_status_empty(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/sla/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tracked"] == 0
        assert data["breached"] == 0

    def test_sla_status_with_detections(self):
        lm = LifecycleManager()
        lm.get_or_create("d1", "Healthy Det")
        lm.get_or_create("d2", "Another Det")
        app = create_app(lifecycle_manager=lm)
        client = TestClient(app)
        resp = client.get("/api/sla/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tracked"] == 2

    def test_sla_custom_limits(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/sla/status?max_days_draft=5&max_days_review=3")
        assert resp.status_code == 200


# ── Compliance report ─────────────────────────────────────────────────────────


class TestComplianceReport:
    def test_soc2_json_report(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=soc2&fmt=json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "soc2"
        assert "sections" in data
        assert len(data["sections"]) > 0
        assert 0.0 <= data["overall_score"] <= 1.0

    def test_nist_csf_json_report(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=nist_csf&fmt=json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "nist_csf"
        section_ids = [s["section_id"] for s in data["sections"]]
        assert "ID" in section_ids
        assert "DE" in section_ids

    def test_soc2_markdown_report(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=soc2&fmt=markdown")
        assert resp.status_code == 200
        assert "SOC 2" in resp.text
        assert "## CC6" in resp.text

    def test_unknown_framework_returns_400(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=garbage")
        assert resp.status_code == 400

    def test_report_with_loaded_data(self):
        from odcp.models import Detection, Environment, Platform, ScanReport
        from odcp.server.state import ReportStore

        store = ReportStore()
        store.report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
            detections=[Detection(id="d1", name="D1", search_query="*")],
        )
        lm = LifecycleManager()
        lm.get_or_create("d1", "D1")
        audit = AuditLogger()
        audit.log("alice", "token.create", "token:abc")

        app = create_app(store=store, lifecycle_manager=lm, audit_logger=audit)
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=soc2&fmt=json")
        assert resp.status_code == 200
        # With data loaded, overall score should be higher
        data = resp.json()
        assert data["overall_score"] > 0

    def test_report_period_label(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/compliance/report?framework=soc2&period=2025-Q1&fmt=json")
        assert resp.json()["period_label"] == "2025-Q1"
