"""Unit tests for LifecycleManager and lifecycle models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from odcp.lifecycle.manager import LifecycleError, LifecycleManager
from odcp.models.lifecycle import (
    VALID_TRANSITIONS,
    DetectionLifecycle,
    DetectionState,
    next_state,
    prev_state,
)


# ── State machine helpers ────────────────────────────────────────────────────


class TestStateMachineHelpers:
    def test_next_state_sequence(self):
        assert next_state(DetectionState.draft) == DetectionState.review
        assert next_state(DetectionState.review) == DetectionState.testing
        assert next_state(DetectionState.testing) == DetectionState.production
        assert next_state(DetectionState.production) == DetectionState.deprecated
        assert next_state(DetectionState.deprecated) is None

    def test_prev_state_sequence(self):
        assert prev_state(DetectionState.deprecated) == DetectionState.production
        assert prev_state(DetectionState.production) == DetectionState.testing
        assert prev_state(DetectionState.testing) == DetectionState.review
        assert prev_state(DetectionState.review) == DetectionState.draft
        assert prev_state(DetectionState.draft) is None

    def test_valid_transitions_coverage(self):
        # Every state should have an entry
        for state in DetectionState:
            assert state in VALID_TRANSITIONS

    def test_deprecated_is_terminal(self):
        assert len(VALID_TRANSITIONS[DetectionState.deprecated]) == 0

    def test_can_rollback_from_all_but_draft(self):
        # All states except draft and deprecated can go back
        rollbackable = [DetectionState.review, DetectionState.testing, DetectionState.production]
        for s in rollbackable:
            back = prev_state(s)
            assert back is not None
            assert back in VALID_TRANSITIONS[s]

    def test_state_display_has_required_keys(self):
        lc = DetectionLifecycle(detection_id="d1", detection_name="Test")
        d = lc.state_display()
        for key in ("state", "color", "icon", "can_promote", "can_rollback", "next_state", "prev_state"):
            assert key in d


# ── LifecycleManager basics ──────────────────────────────────────────────────


class TestLifecycleManagerBasics:
    def test_get_or_create_creates_draft(self):
        mgr = LifecycleManager()
        lc = mgr.get_or_create("det-001", "Login Brute Force")
        assert lc.current_state == DetectionState.draft
        assert lc.detection_id == "det-001"
        assert lc.detection_name == "Login Brute Force"

    def test_get_or_create_idempotent(self):
        mgr = LifecycleManager()
        lc1 = mgr.get_or_create("det-001", "Name1")
        lc2 = mgr.get_or_create("det-001", "Name2")  # second call with different name
        assert lc1 is lc2  # same object returned

    def test_initial_history_has_creation_event(self):
        mgr = LifecycleManager()
        lc = mgr.get_or_create("det-001", "Test")
        assert len(lc.history) == 1
        assert lc.history[0].to_state == DetectionState.draft
        assert lc.history[0].actor == "system"

    def test_get_returns_none_for_unknown(self):
        mgr = LifecycleManager()
        assert mgr.get("unknown-id") is None

    def test_get_all_empty(self):
        mgr = LifecycleManager()
        assert mgr.get_all() == []

    def test_get_all_with_filter(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "A")
        mgr.get_or_create("d2", "B")
        mgr.transition("d2", DetectionState.review, actor="alice")
        drafts = mgr.get_all(state_filter="draft")
        assert len(drafts) == 1
        assert drafts[0].detection_id == "d1"


# ── Transitions ──────────────────────────────────────────────────────────────


class TestTransitions:
    def test_promote_full_path(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        mgr.promote("d1", actor="alice")
        assert mgr.get("d1").current_state == DetectionState.review
        mgr.promote("d1", actor="bob")
        assert mgr.get("d1").current_state == DetectionState.testing
        mgr.promote("d1", actor="carol")
        assert mgr.get("d1").current_state == DetectionState.production
        mgr.promote("d1", actor="dave")
        assert mgr.get("d1").current_state == DetectionState.deprecated

    def test_promote_terminal_raises(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        for _ in range(4):
            mgr.promote("d1")
        with pytest.raises(LifecycleError, match="terminal"):
            mgr.promote("d1")

    def test_rollback_from_review(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        mgr.promote("d1")
        assert mgr.get("d1").current_state == DetectionState.review
        mgr.rollback("d1", actor="alice")
        assert mgr.get("d1").current_state == DetectionState.draft

    def test_rollback_initial_raises(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        with pytest.raises(LifecycleError, match="initial"):
            mgr.rollback("d1")

    def test_transition_to_deprecated_from_any_non_terminal(self):
        mgr = LifecycleManager()
        for did, _ in [("d1", None), ("d2", None), ("d3", None)]:
            mgr.get_or_create(did, did)
        # draft → deprecated
        mgr.transition("d1", DetectionState.deprecated, actor="admin")
        assert mgr.get("d1").current_state == DetectionState.deprecated
        # review → deprecated
        mgr.promote("d2")
        mgr.transition("d2", DetectionState.deprecated, actor="admin")
        assert mgr.get("d2").current_state == DetectionState.deprecated
        # testing → deprecated
        mgr.promote("d3")
        mgr.promote("d3")
        mgr.transition("d3", DetectionState.deprecated, actor="admin")
        assert mgr.get("d3").current_state == DetectionState.deprecated

    def test_invalid_transition_raises_lifecycle_error(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        with pytest.raises(LifecycleError, match="Cannot transition"):
            mgr.transition("d1", DetectionState.production)  # draft → production is invalid

    def test_unknown_detection_raises_key_error(self):
        mgr = LifecycleManager()
        with pytest.raises(KeyError):
            mgr.promote("nonexistent")
        with pytest.raises(KeyError):
            mgr.rollback("nonexistent")
        with pytest.raises(KeyError):
            mgr.transition("nonexistent", DetectionState.review)

    def test_transition_records_history(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Test")
        mgr.promote("d1", actor="alice", comment="LGTM")
        mgr.promote("d1", actor="bob", comment="Passes all tests")
        lc = mgr.get("d1")
        assert len(lc.history) == 3  # creation + 2 promotions
        assert lc.history[1].actor == "alice"
        assert lc.history[1].comment == "LGTM"
        assert lc.history[2].actor == "bob"
        assert lc.history[2].from_state == DetectionState.review
        assert lc.history[2].to_state == DetectionState.testing

    def test_updated_at_changes_on_transition(self):
        mgr = LifecycleManager()
        lc = mgr.get_or_create("d1", "Test")
        before = lc.updated_at
        import time; time.sleep(0.01)
        mgr.promote("d1")
        assert lc.updated_at > before


# ── Summary ──────────────────────────────────────────────────────────────────


class TestSummary:
    def test_summary_all_zeros_on_empty(self):
        mgr = LifecycleManager()
        s = mgr.summary()
        assert s.total == 0
        for state in DetectionState:
            assert s.by_state[state.value] == 0

    def test_summary_counts_by_state(self):
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "A")
        mgr.get_or_create("d2", "B")
        mgr.get_or_create("d3", "C")
        mgr.promote("d2")  # review
        mgr.promote("d3"); mgr.promote("d3")  # testing
        s = mgr.summary()
        assert s.total == 3
        assert s.by_state["draft"] == 1
        assert s.by_state["review"] == 1
        assert s.by_state["testing"] == 1

    def test_summary_recently_updated_capped_at_5(self):
        mgr = LifecycleManager()
        for i in range(8):
            mgr.get_or_create(f"d{i}", f"Det{i}")
        s = mgr.summary()
        assert len(s.recently_updated) <= 5


# ── Sync from report ─────────────────────────────────────────────────────────


class TestSyncFromReport:
    def test_sync_registers_new_detections(self):
        from odcp.models import Detection, ScanReport, Environment, Platform
        from odcp.models.report import ReadinessSummary

        report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
            detections=[
                Detection(id="d1", name="Det1", search_query="*"),
                Detection(id="d2", name="Det2", search_query="*"),
            ],
        )
        mgr = LifecycleManager()
        created = mgr.sync_from_report(report)
        assert created == 2
        assert mgr.get("d1") is not None
        assert mgr.get("d2") is not None

    def test_sync_skips_already_tracked(self):
        from odcp.models import Detection, ScanReport, Environment, Platform

        report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
            detections=[Detection(id="d1", name="Det1", search_query="*")],
        )
        mgr = LifecycleManager()
        mgr.get_or_create("d1", "Det1")
        created = mgr.sync_from_report(report)
        assert created == 0  # already tracked


# ── Persistence ──────────────────────────────────────────────────────────────


class TestPersistence:
    def test_save_and_load(self, tmp_path: Path):
        db = tmp_path / "lifecycle.json"
        mgr = LifecycleManager(persist_path=db)
        mgr.get_or_create("d1", "Test A")
        mgr.get_or_create("d2", "Test B")
        mgr.promote("d1", actor="alice")
        assert db.exists()

        # Load into fresh manager
        mgr2 = LifecycleManager(persist_path=db)
        assert mgr2.get("d1") is not None
        assert mgr2.get("d1").current_state == DetectionState.review
        assert mgr2.get("d2").current_state == DetectionState.draft

    def test_load_nonexistent_path_no_error(self, tmp_path: Path):
        db = tmp_path / "no_such_file.json"
        mgr = LifecycleManager(persist_path=db)
        assert mgr.get_all() == []

    def test_save_preserves_full_history(self, tmp_path: Path):
        db = tmp_path / "lifecycle.json"
        mgr = LifecycleManager(persist_path=db)
        mgr.get_or_create("d1", "Det1")
        mgr.promote("d1", actor="alice", comment="step1")
        mgr.promote("d1", actor="bob", comment="step2")

        mgr2 = LifecycleManager(persist_path=db)
        lc = mgr2.get("d1")
        assert len(lc.history) == 3  # creation + 2 promotions
        assert lc.history[1].comment == "step1"
        assert lc.history[2].comment == "step2"
