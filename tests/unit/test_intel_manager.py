"""Unit tests for IntelManager and threat intelligence models."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from odcp.intel.manager import IntelManager
from odcp.models.intel import (
    IocEntry,
    IocType,
    ThreatActor,
    ThreatCampaign,
    IntelFeed,
    FeedType,
)


def _campaign(**kwargs) -> ThreatCampaign:
    defaults = {"name": "Test Campaign", "techniques": ["T1059"], "confidence": 0.8, "active": True}
    return ThreatCampaign(**(defaults | kwargs))


def _ioc(**kwargs) -> IocEntry:
    defaults = {"value": "1.2.3.4", "ioc_type": IocType.ip, "related_techniques": ["T1059"], "confidence": 0.7}
    return IocEntry(**(defaults | kwargs))


# ── Campaigns ────────────────────────────────────────────────────────────────


class TestCampaigns:
    def test_add_and_get(self):
        mgr = IntelManager()
        c = _campaign()
        mgr.add_campaign(c)
        found = mgr.get_campaign(c.campaign_id)
        assert found is not None
        assert found.name == "Test Campaign"

    def test_get_nonexistent_returns_none(self):
        mgr = IntelManager()
        assert mgr.get_campaign("no-such") is None

    def test_get_campaigns_all(self):
        mgr = IntelManager()
        mgr.add_campaign(_campaign(name="C1"))
        mgr.add_campaign(_campaign(name="C2"))
        campaigns = mgr.get_campaigns()
        assert len(campaigns) == 2

    def test_get_campaigns_active_only(self):
        mgr = IntelManager()
        mgr.add_campaign(_campaign(name="Active", active=True))
        mgr.add_campaign(_campaign(name="Inactive", active=False))
        active = mgr.get_campaigns(active_only=True)
        assert len(active) == 1
        assert active[0].name == "Active"

    def test_remove_campaign(self):
        mgr = IntelManager()
        c = _campaign()
        mgr.add_campaign(c)
        ok = mgr.remove_campaign(c.campaign_id)
        assert ok is True
        assert mgr.get_campaign(c.campaign_id) is None

    def test_remove_nonexistent_returns_false(self):
        mgr = IntelManager()
        assert mgr.remove_campaign("ghost") is False


# ── IOCs ──────────────────────────────────────────────────────────────────────


class TestIocs:
    def test_add_and_list(self):
        mgr = IntelManager()
        mgr.add_ioc(_ioc())
        iocs = mgr.get_iocs()
        assert len(iocs) == 1

    def test_filter_by_type(self):
        mgr = IntelManager()
        mgr.add_ioc(_ioc(value="1.2.3.4", ioc_type=IocType.ip))
        mgr.add_ioc(_ioc(value="evil.com", ioc_type=IocType.domain))
        assert len(mgr.get_iocs(ioc_type="ip")) == 1
        assert len(mgr.get_iocs(ioc_type="domain")) == 1

    def test_bulk_add(self):
        mgr = IntelManager()
        iocs = [_ioc(value=f"1.2.3.{i}") for i in range(5)]
        count = mgr.add_iocs_bulk(iocs)
        assert count == 5
        assert len(mgr.get_iocs()) == 5


# ── Actors and Feeds ──────────────────────────────────────────────────────────


class TestActorsAndFeeds:
    def test_add_actor(self):
        mgr = IntelManager()
        actor = ThreatActor(name="APT29", motivation="espionage")
        mgr.add_actor(actor)
        actors = mgr.get_actors()
        assert len(actors) == 1
        assert actors[0].name == "APT29"

    def test_add_feed(self):
        mgr = IntelManager()
        feed = IntelFeed(name="MISP Test", feed_type=FeedType.misp)
        mgr.add_feed(feed)
        feeds = mgr.get_feeds()
        assert len(feeds) == 1
        assert feeds[0].name == "MISP Test"

    def test_update_feed_sync(self):
        mgr = IntelManager()
        feed = IntelFeed(name="Test Feed")
        mgr.add_feed(feed)
        ok = mgr.update_feed_sync(feed.feed_id, entry_count=42)
        assert ok is True
        updated = mgr.get_feeds()[0]
        assert updated.entry_count == 42
        assert updated.last_synced is not None


# ── Active techniques ─────────────────────────────────────────────────────────


class TestActiveTechniques:
    def test_active_techniques_from_campaigns(self):
        mgr = IntelManager()
        mgr.add_campaign(_campaign(techniques=["T1059", "T1078"], active=True))
        mgr.add_campaign(_campaign(techniques=["T1059", "T1195"], active=True))
        active = mgr.get_active_techniques()
        assert "T1059" in active
        assert len(active["T1059"]) == 2  # in 2 campaigns
        assert "T1078" in active
        assert "T1195" in active

    def test_inactive_campaigns_excluded(self):
        mgr = IntelManager()
        mgr.add_campaign(_campaign(techniques=["T1234"], active=False))
        active = mgr.get_active_techniques()
        assert "T1234" not in active


# ── Summary ───────────────────────────────────────────────────────────────────


class TestSummary:
    def test_empty_summary(self):
        mgr = IntelManager()
        s = mgr.summary()
        assert s.total_campaigns == 0
        assert s.active_campaigns == 0
        assert s.total_iocs == 0

    def test_summary_counts(self):
        mgr = IntelManager()
        mgr.add_campaign(_campaign(name="C1", confidence=0.9, techniques=["T1059"]))
        mgr.add_campaign(_campaign(name="C2", active=False, confidence=0.4, techniques=["T1078"]))
        mgr.add_ioc(_ioc())
        s = mgr.summary()
        assert s.total_campaigns == 2
        assert s.active_campaigns == 1
        assert s.total_iocs == 1
        assert s.tracked_techniques == 2
        assert s.high_confidence_techniques == 1  # only C1 has conf >= 0.7


# ── Persistence ───────────────────────────────────────────────────────────────


class TestPersistence:
    def test_save_and_reload(self, tmp_path: Path):
        db = tmp_path / "intel.json"
        mgr = IntelManager(persist_path=db)
        mgr.add_campaign(_campaign(name="APT-Test"))
        mgr.add_ioc(_ioc(value="evil.com", ioc_type=IocType.domain))

        mgr2 = IntelManager(persist_path=db)
        assert len(mgr2.get_campaigns()) == 1
        assert mgr2.get_campaigns()[0].name == "APT-Test"
        assert len(mgr2.get_iocs()) == 1

    def test_load_empty_path_no_error(self, tmp_path: Path):
        db = tmp_path / "no_file.json"
        mgr = IntelManager(persist_path=db)
        assert mgr.get_campaigns() == []
