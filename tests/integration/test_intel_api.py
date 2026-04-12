"""Integration tests for the threat intelligence API."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("httpx", reason="httpx not installed")

from fastapi.testclient import TestClient

from odcp.intel.manager import IntelManager
from odcp.models.intel import IocEntry, IocType, ThreatCampaign
from odcp.server.app import create_app


def _make_app():
    intel = IntelManager()
    app = create_app(intel_manager=intel)
    return app, intel


# ── /api/intel/summary ────────────────────────────────────────────────────────


def test_summary_empty():
    app, _ = _make_app()
    client = TestClient(app)
    resp = client.get("/api/intel/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_campaigns"] == 0


# ── /api/intel/campaigns ─────────────────────────────────────────────────────


class TestCampaignEndpoints:
    def test_list_empty(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.get("/api/intel/campaigns")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_add_and_list(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.post("/api/intel/campaigns", json={
            "name": "APT29 Test", "techniques": ["T1059", "T1078"],
            "confidence": 0.85, "active": True,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "APT29 Test"
        assert "campaign_id" in data

        list_resp = client.get("/api/intel/campaigns")
        assert list_resp.json()["total"] == 1

    def test_get_specific(self):
        app, intel = _make_app()
        c = ThreatCampaign(name="SolarWinds", techniques=["T1195"])
        intel.add_campaign(c)
        client = TestClient(app)
        resp = client.get(f"/api/intel/campaigns/{c.campaign_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "SolarWinds"

    def test_get_nonexistent_404(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.get("/api/intel/campaigns/no-such")
        assert resp.status_code == 404

    def test_remove_campaign(self):
        app, intel = _make_app()
        c = ThreatCampaign(name="To Remove", techniques=["T1059"])
        intel.add_campaign(c)
        client = TestClient(app)
        resp = client.delete(f"/api/intel/campaigns/{c.campaign_id}")
        assert resp.status_code == 200
        assert resp.json()["removed"] is True

    def test_invalid_campaign_returns_400(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.post("/api/intel/campaigns", json={"bad": "data"})
        # name is required
        assert resp.status_code == 400

    def test_filter_active_only(self):
        app, intel = _make_app()
        intel.add_campaign(ThreatCampaign(name="Active", techniques=["T1"], active=True))
        intel.add_campaign(ThreatCampaign(name="Inactive", techniques=["T2"], active=False))
        client = TestClient(app)
        resp = client.get("/api/intel/campaigns?active_only=true")
        assert resp.json()["total"] == 1
        assert resp.json()["campaigns"][0]["name"] == "Active"


# ── /api/intel/iocs ───────────────────────────────────────────────────────────


class TestIocEndpoints:
    def test_add_ioc(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.post("/api/intel/iocs", json={
            "value": "192.168.1.1",
            "ioc_type": "ip",
            "related_techniques": ["T1071"],
            "confidence": 0.9,
        })
        assert resp.status_code == 201
        assert resp.json()["value"] == "192.168.1.1"

    def test_bulk_add_iocs(self):
        app, _ = _make_app()
        client = TestClient(app)
        iocs = [
            {"value": f"evil{i}.com", "ioc_type": "domain", "confidence": 0.7}
            for i in range(5)
        ]
        resp = client.post("/api/intel/iocs/bulk", json={"iocs": iocs})
        assert resp.status_code == 201
        assert resp.json()["added"] == 5

    def test_list_iocs_filtered(self):
        app, intel = _make_app()
        intel.add_ioc(IocEntry(value="1.2.3.4", ioc_type=IocType.ip))
        intel.add_ioc(IocEntry(value="bad.com", ioc_type=IocType.domain))
        client = TestClient(app)
        resp = client.get("/api/intel/iocs?ioc_type=ip")
        assert resp.json()["total"] == 1


# ── /api/intel/gap-analysis ───────────────────────────────────────────────────


class TestGapAnalysis:
    def test_no_report_returns_404(self):
        app, _ = _make_app()
        client = TestClient(app)
        resp = client.get("/api/intel/gap-analysis")
        assert resp.status_code == 404

    def test_with_report_returns_gap_report(self):
        from odcp.models import Detection, Environment, Platform, ScanReport
        from odcp.server.state import ReportStore
        from odcp.models.report import ReadinessSummary

        store = ReportStore()
        intel = IntelManager()
        intel.add_campaign(ThreatCampaign(
            name="Test Campaign", techniques=["T1059"], confidence=0.9, active=True,
        ))
        store.report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
            detections=[Detection(id="d1", name="PS Script", search_query="index=win")],
        )
        app = create_app(store=store, intel_manager=intel)
        client = TestClient(app)
        resp = client.get("/api/intel/gap-analysis")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_techniques_in_scope" in data
        assert "technique_risks" in data


# ── /api/intel/actors ─────────────────────────────────────────────────────────


def test_add_and_list_actors():
    app, _ = _make_app()
    client = TestClient(app)
    resp = client.post("/api/intel/actors", json={
        "name": "APT29", "motivation": "espionage", "sophistication": "nation-state",
    })
    assert resp.status_code == 201
    list_resp = client.get("/api/intel/actors")
    assert list_resp.json()["total"] == 1


# ── /api/intel/feeds ─────────────────────────────────────────────────────────


def test_add_and_list_feeds():
    app, _ = _make_app()
    client = TestClient(app)
    resp = client.post("/api/intel/feeds", json={"name": "MISP Test", "feed_type": "misp"})
    assert resp.status_code == 201
    list_resp = client.get("/api/intel/feeds")
    assert list_resp.json()["total"] == 1


# ── /intel UI page ────────────────────────────────────────────────────────────


def test_intel_page_renders():
    app, _ = _make_app()
    client = TestClient(app)
    resp = client.get("/intel")
    assert resp.status_code == 200
    assert b"Threat Intel" in resp.content
