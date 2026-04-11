"""Detection lifecycle state machine models.

States and valid transitions:

    draft ──► review ──► testing ──► production ──► deprecated
      │         │           │
      └──────────┴───────────┴──► deprecated (abort at any stage)
                │           │
              draft ◄──── review   (reject / fail — roll back)
                          testing ◄── production  (rollback for re-testing)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class DetectionState(str, Enum):
    draft = "draft"
    review = "review"
    testing = "testing"
    production = "production"
    deprecated = "deprecated"


# Forward-only promotion path (ordered)
_PROMOTION_ORDER: list[DetectionState] = [
    DetectionState.draft,
    DetectionState.review,
    DetectionState.testing,
    DetectionState.production,
    DetectionState.deprecated,
]

# All valid transitions (including rollback and abort paths)
VALID_TRANSITIONS: dict[DetectionState, set[DetectionState]] = {
    DetectionState.draft:       {DetectionState.review, DetectionState.deprecated},
    DetectionState.review:      {DetectionState.testing, DetectionState.draft, DetectionState.deprecated},
    DetectionState.testing:     {DetectionState.production, DetectionState.review, DetectionState.deprecated},
    DetectionState.production:  {DetectionState.testing, DetectionState.deprecated},
    DetectionState.deprecated:  set(),  # terminal
}


def next_state(current: DetectionState) -> Optional[DetectionState]:
    """Return the next forward state in the promotion path, or None if terminal."""
    try:
        idx = _PROMOTION_ORDER.index(current)
        return _PROMOTION_ORDER[idx + 1] if idx + 1 < len(_PROMOTION_ORDER) else None
    except ValueError:
        return None


def prev_state(current: DetectionState) -> Optional[DetectionState]:
    """Return the previous state in the promotion path, or None if at start."""
    try:
        idx = _PROMOTION_ORDER.index(current)
        return _PROMOTION_ORDER[idx - 1] if idx > 0 else None
    except ValueError:
        return None


class LifecycleEvent(BaseModel):
    """A single state-transition event recorded in the history."""

    event_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_id: str
    from_state: Optional[DetectionState] = None
    to_state: DetectionState
    actor: str = "system"
    comment: Optional[str] = None


class DetectionLifecycle(BaseModel):
    """Full lifecycle record for a single detection."""

    detection_id: str
    detection_name: str
    current_state: DetectionState = DetectionState.draft
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    history: list[LifecycleEvent] = Field(default_factory=list)

    def can_transition_to(self, target: DetectionState) -> bool:
        return target in VALID_TRANSITIONS.get(self.current_state, set())

    def state_display(self) -> dict[str, Any]:
        """Return metadata useful for rendering the state badge."""
        colors = {
            "draft":       "secondary",
            "review":      "warning",
            "testing":     "info",
            "production":  "success",
            "deprecated":  "danger",
        }
        icons = {
            "draft":       "✏️",
            "review":      "🔍",
            "testing":     "🧪",
            "production":  "✅",
            "deprecated":  "🗄️",
        }
        s = self.current_state.value
        return {
            "state": s,
            "color": colors.get(s, "secondary"),
            "icon": icons.get(s, ""),
            "can_promote": next_state(self.current_state) is not None
            and self.can_transition_to(next_state(self.current_state)),  # type: ignore[arg-type]
            "can_rollback": prev_state(self.current_state) is not None
            and self.can_transition_to(prev_state(self.current_state)),  # type: ignore[arg-type]
            "next_state": (next_state(self.current_state) or DetectionState.deprecated).value,
            "prev_state": (prev_state(self.current_state) or DetectionState.draft).value,
        }


class LifecycleSummary(BaseModel):
    """Aggregate counts across all tracked detections."""

    total: int = 0
    by_state: dict[str, int] = Field(default_factory=dict)
    recently_updated: list[DetectionLifecycle] = Field(default_factory=list)
