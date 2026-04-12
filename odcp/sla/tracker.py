"""SLA tracker for detection lifecycle states.

Monitors how long detections spend in each state and flags breaches.

Usage::

    policy = SlaPolicy(max_days_in_draft=30, max_days_in_review=14,
                       max_days_in_testing=21, max_days_in_blocked=7)
    tracker = SlaTracker(policy)
    status_list = tracker.evaluate(lifecycle_manager.get_all())
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from odcp.models.lifecycle import DetectionLifecycle, DetectionState


class SlaPolicy(BaseModel):
    """Maximum allowed days in each mutable lifecycle state."""

    max_days_in_draft: int = 30
    max_days_in_review: int = 14
    max_days_in_testing: int = 21
    max_days_in_production: int = 0   # 0 = no limit
    max_days_blocked: int = 7         # time since last transition with no forward movement


class SlaStatus(BaseModel):
    """SLA status for a single detection."""

    detection_id: str
    detection_name: str
    current_state: str
    days_in_current_state: float
    sla_limit_days: int               # 0 = no limit
    at_risk: bool = False             # within 20% of the limit
    breached: bool = False
    last_transition: Optional[datetime] = None
    message: str = ""


class SlaSummary(BaseModel):
    """Fleet-level SLA summary."""

    total_tracked: int = 0
    breached: int = 0
    at_risk: int = 0
    healthy: int = 0
    statuses: list[SlaStatus] = Field(default_factory=list)


_STATE_LIMIT_ATTR: dict[str, str] = {
    "draft":      "max_days_in_draft",
    "review":     "max_days_in_review",
    "testing":    "max_days_in_testing",
    "production": "max_days_in_production",
}


class SlaTracker:
    """Evaluates SLA compliance for a list of lifecycle records."""

    def __init__(self, policy: Optional[SlaPolicy] = None) -> None:
        self.policy = policy or SlaPolicy()

    def evaluate_one(self, record: DetectionLifecycle) -> SlaStatus:
        """Return SLA status for a single lifecycle record."""
        now = datetime.now(timezone.utc)

        # Find when the detection entered its current state
        last_trans = record.updated_at
        for ev in reversed(record.history):
            if ev.to_state == record.current_state:
                last_trans = ev.timestamp
                break

        days_in = (now - last_trans).total_seconds() / 86400

        state = record.current_state.value
        attr = _STATE_LIMIT_ATTR.get(state, "")
        limit = getattr(self.policy, attr, 0) if attr else 0

        breached = limit > 0 and days_in > limit
        at_risk = limit > 0 and not breached and days_in > limit * 0.8

        msg = ""
        if breached:
            msg = f"SLA breached: {days_in:.1f} days in '{state}' (limit {limit}d)"
        elif at_risk:
            msg = f"SLA at risk: {days_in:.1f} days in '{state}' (limit {limit}d)"

        return SlaStatus(
            detection_id=record.detection_id,
            detection_name=record.detection_name,
            current_state=state,
            days_in_current_state=round(days_in, 2),
            sla_limit_days=limit,
            at_risk=at_risk,
            breached=breached,
            last_transition=last_trans,
            message=msg,
        )

    def evaluate(self, records: list[DetectionLifecycle]) -> SlaSummary:
        """Evaluate SLA for all records and return a summary."""
        statuses = [self.evaluate_one(r) for r in records]
        # Sort: breached first, then at-risk, then healthy
        statuses.sort(key=lambda s: (not s.breached, not s.at_risk, s.detection_name))

        return SlaSummary(
            total_tracked=len(statuses),
            breached=sum(1 for s in statuses if s.breached),
            at_risk=sum(1 for s in statuses if s.at_risk),
            healthy=sum(1 for s in statuses if not s.breached and not s.at_risk),
            statuses=statuses,
        )
