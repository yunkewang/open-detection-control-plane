"""Unit tests for SlaTracker and SlaPolicy."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from odcp.models.lifecycle import DetectionLifecycle, DetectionState, LifecycleEvent
from odcp.sla.tracker import SlaPolicy, SlaTracker


def _record(
    detection_id: str = "d1",
    state: DetectionState = DetectionState.draft,
    days_ago: float = 0,
    name: str = "Test Det",
) -> DetectionLifecycle:
    """Build a lifecycle record updated `days_ago` days ago."""
    now = datetime.now(timezone.utc)
    updated = now - timedelta(days=days_ago)
    r = DetectionLifecycle(
        detection_id=detection_id,
        detection_name=name,
        current_state=state,
        updated_at=updated,
    )
    r.history.append(LifecycleEvent(
        detection_id=detection_id,
        from_state=None,
        to_state=state,
        actor="system",
        timestamp=updated,
    ))
    return r


class TestSlaPolicy:
    def test_default_policy(self):
        p = SlaPolicy()
        assert p.max_days_in_draft == 30
        assert p.max_days_in_review == 14
        assert p.max_days_in_testing == 21
        assert p.max_days_in_production == 0  # no limit


class TestSlaTrackerEvaluateOne:
    def test_healthy_detection(self):
        tracker = SlaTracker(SlaPolicy(max_days_in_draft=30))
        r = _record(state=DetectionState.draft, days_ago=5)
        s = tracker.evaluate_one(r)
        assert not s.breached
        assert not s.at_risk
        assert s.days_in_current_state == pytest.approx(5.0, abs=0.1)

    def test_at_risk_detection(self):
        # 81% of limit
        tracker = SlaTracker(SlaPolicy(max_days_in_draft=10))
        r = _record(state=DetectionState.draft, days_ago=8.5)
        s = tracker.evaluate_one(r)
        assert not s.breached
        assert s.at_risk

    def test_breached_detection(self):
        tracker = SlaTracker(SlaPolicy(max_days_in_draft=10))
        r = _record(state=DetectionState.draft, days_ago=15)
        s = tracker.evaluate_one(r)
        assert s.breached
        assert "SLA breached" in s.message

    def test_production_no_limit(self):
        tracker = SlaTracker(SlaPolicy(max_days_in_production=0))
        r = _record(state=DetectionState.production, days_ago=999)
        s = tracker.evaluate_one(r)
        assert not s.breached
        assert not s.at_risk
        assert s.sla_limit_days == 0

    def test_deprecated_no_limit(self):
        # Deprecated is terminal — no SLA limit defined
        tracker = SlaTracker()
        r = _record(state=DetectionState.deprecated, days_ago=500)
        s = tracker.evaluate_one(r)
        assert not s.breached

    def test_review_sla(self):
        tracker = SlaTracker(SlaPolicy(max_days_in_review=14))
        r = _record(state=DetectionState.review, days_ago=20)
        s = tracker.evaluate_one(r)
        assert s.breached
        assert s.sla_limit_days == 14


class TestSlaTrackerEvaluate:
    def test_empty_returns_zeros(self):
        tracker = SlaTracker()
        summary = tracker.evaluate([])
        assert summary.total_tracked == 0
        assert summary.breached == 0
        assert summary.healthy == 0

    def test_mixed_status(self):
        policy = SlaPolicy(max_days_in_draft=5, max_days_in_review=3)
        tracker = SlaTracker(policy)
        records = [
            _record("d1", DetectionState.draft, days_ago=1, name="Healthy"),
            _record("d2", DetectionState.draft, days_ago=4.5, name="AtRisk"),
            _record("d3", DetectionState.draft, days_ago=10, name="Breached"),
            _record("d4", DetectionState.review, days_ago=5, name="ReviewBreached"),
        ]
        summary = tracker.evaluate(records)
        assert summary.total_tracked == 4
        assert summary.breached == 2
        assert summary.at_risk == 1
        assert summary.healthy == 1

    def test_breached_appear_first(self):
        policy = SlaPolicy(max_days_in_draft=5)
        tracker = SlaTracker(policy)
        records = [
            _record("d1", DetectionState.draft, days_ago=1, name="Healthy"),
            _record("d2", DetectionState.draft, days_ago=10, name="Breached"),
        ]
        summary = tracker.evaluate(records)
        # Breached should be first
        assert summary.statuses[0].breached is True
