"""LifecycleManager — thread-safe store for detection lifecycle state.

Tracks per-detection state, validates transitions, records history, and
optionally persists the full state as a JSON file.

Usage::

    mgr = LifecycleManager()
    lc = mgr.get_or_create("det-001", "Login Brute Force")
    mgr.promote("det-001", actor="alice", comment="Reviewed, looks good")
    mgr.promote("det-001", actor="bob", comment="Passes lab tests")
    print(lc.current_state)  # production
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from odcp.models.lifecycle import (
    VALID_TRANSITIONS,
    DetectionLifecycle,
    DetectionState,
    LifecycleEvent,
    LifecycleSummary,
    next_state,
    prev_state,
)

logger = logging.getLogger(__name__)


class LifecycleError(ValueError):
    """Raised when an invalid state transition is attempted."""


class LifecycleManager:
    """Thread-safe detection lifecycle state manager.

    Parameters
    ----------
    persist_path:
        Optional path to a JSON file.  The full lifecycle store is written
        on every mutation and loaded on construction.
    """

    def __init__(self, persist_path: Optional[str | Path] = None) -> None:
        self._records: dict[str, DetectionLifecycle] = {}
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path and self._persist_path.exists():
            self._load()

    # ── Reads ───────────────────────────────────────────────────────────────

    def get(self, detection_id: str) -> Optional[DetectionLifecycle]:
        with self._lock:
            return self._records.get(detection_id)

    def get_all(
        self,
        state_filter: Optional[str] = None,
    ) -> list[DetectionLifecycle]:
        with self._lock:
            records = list(self._records.values())
        if state_filter:
            records = [r for r in records if r.current_state.value == state_filter]
        return sorted(records, key=lambda r: r.updated_at, reverse=True)

    def summary(self) -> LifecycleSummary:
        all_records = self.get_all()
        by_state: dict[str, int] = {s.value: 0 for s in DetectionState}
        for r in all_records:
            by_state[r.current_state.value] += 1
        recently = sorted(all_records, key=lambda r: r.updated_at, reverse=True)[:5]
        return LifecycleSummary(
            total=len(all_records),
            by_state=by_state,
            recently_updated=recently,
        )

    # ── Writes ──────────────────────────────────────────────────────────────

    def get_or_create(
        self,
        detection_id: str,
        detection_name: str,
    ) -> DetectionLifecycle:
        """Return existing lifecycle record or create a new draft."""
        with self._lock:
            if detection_id in self._records:
                return self._records[detection_id]
            record = DetectionLifecycle(
                detection_id=detection_id,
                detection_name=detection_name,
            )
            # Seed history with the initial creation event
            record.history.append(
                LifecycleEvent(
                    detection_id=detection_id,
                    from_state=None,
                    to_state=DetectionState.draft,
                    actor="system",
                    comment="Detection registered",
                )
            )
            self._records[detection_id] = record
        self._save()
        logger.info("Created lifecycle record for '%s' (%s)", detection_name, detection_id)
        return record

    def transition(
        self,
        detection_id: str,
        to_state: DetectionState,
        actor: str = "system",
        comment: Optional[str] = None,
    ) -> DetectionLifecycle:
        """Transition a detection to an explicit target state.

        Raises :class:`KeyError` if the detection is not tracked.
        Raises :class:`LifecycleError` if the transition is invalid.
        """
        with self._lock:
            record = self._records.get(detection_id)
            if record is None:
                raise KeyError(f"Detection '{detection_id}' is not tracked. Call get_or_create first.")
            if not record.can_transition_to(to_state):
                valid = [s.value for s in VALID_TRANSITIONS.get(record.current_state, set())]
                raise LifecycleError(
                    f"Cannot transition '{detection_id}' from "
                    f"'{record.current_state.value}' to '{to_state.value}'. "
                    f"Valid targets: {valid or ['none (terminal)']}"
                )
            event = LifecycleEvent(
                detection_id=detection_id,
                from_state=record.current_state,
                to_state=to_state,
                actor=actor,
                comment=comment,
            )
            record.history.append(event)
            record.current_state = to_state
            record.updated_at = datetime.now(timezone.utc)
        self._save()
        logger.info(
            "Detection '%s' transitioned %s → %s by %s",
            detection_id,
            event.from_state.value if event.from_state else "none",
            to_state.value,
            actor,
        )
        return record

    def promote(
        self,
        detection_id: str,
        actor: str = "system",
        comment: Optional[str] = None,
    ) -> DetectionLifecycle:
        """Advance the detection to the next state in the promotion path.

        Raises :class:`LifecycleError` if already at a terminal state or if
        the natural next state is not a valid transition (shouldn't happen in
        practice, but guard for safety).
        """
        with self._lock:
            record = self._records.get(detection_id)
            if record is None:
                raise KeyError(f"Detection '{detection_id}' is not tracked.")
            target = next_state(record.current_state)
            if target is None:
                raise LifecycleError(
                    f"Detection '{detection_id}' is in terminal state "
                    f"'{record.current_state.value}' and cannot be promoted."
                )
        return self.transition(detection_id, target, actor=actor, comment=comment)

    def rollback(
        self,
        detection_id: str,
        actor: str = "system",
        comment: Optional[str] = None,
    ) -> DetectionLifecycle:
        """Move the detection back to the previous state in the promotion path.

        Raises :class:`LifecycleError` if already at the initial state or if
        the previous state is not a valid transition.
        """
        with self._lock:
            record = self._records.get(detection_id)
            if record is None:
                raise KeyError(f"Detection '{detection_id}' is not tracked.")
            target = prev_state(record.current_state)
            if target is None:
                raise LifecycleError(
                    f"Detection '{detection_id}' is in initial state "
                    f"'{record.current_state.value}' and cannot be rolled back."
                )
        return self.transition(detection_id, target, actor=actor, comment=comment)

    def sync_from_report(self, report: "ScanReport", actor: str = "system") -> int:  # type: ignore[name-defined]  # noqa: F821
        """Register any detections from a report that are not yet tracked.

        Returns the number of new records created.
        """
        created = 0
        for det in report.detections:
            with self._lock:
                already = detection_id = det.id
                exists = already in self._records
            if not exists:
                self.get_or_create(det.id, det.name)
                created += 1
        return created

    # ── Persistence ─────────────────────────────────────────────────────────

    def _save(self) -> None:
        if not self._persist_path:
            return
        try:
            with self._lock:
                data = {k: v.model_dump(mode="json") for k, v in self._records.items()}
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._persist_path.write_text(
                json.dumps(data, default=str, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed to persist lifecycle store: %s", exc)

    def _load(self) -> None:
        try:
            raw = json.loads(self._persist_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
            with self._lock:
                for k, v in raw.items():
                    self._records[k] = DetectionLifecycle.model_validate(v)
            logger.info("Loaded %d lifecycle records from %s", len(self._records), self._persist_path)
        except Exception as exc:
            logger.error("Failed to load lifecycle store: %s", exc)
