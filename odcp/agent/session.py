"""Agent session state.

AgentSession holds all mutable context for a single agent conversation:
the currently-loaded scan report, an optional baseline for drift comparison,
and a short-term scratch dict for intermediate results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from odcp.models.report import ScanReport


class AgentSession:
    """Mutable context for one agent conversation.

    Attributes
    ----------
    report:
        The primary scan report loaded via ``load_report``.
    baseline:
        Optional older report used for drift comparison.
    scratch:
        Free-form key/value store for tools to cache intermediate data
        within a single session (e.g., computed catalogs).
    """

    def __init__(self) -> None:
        self.report: Optional[ScanReport] = None
        self.baseline: Optional[ScanReport] = None
        self.scratch: dict[str, Any] = {}

    # ── Report loading helpers ─────────────────────────────────────────────

    def load_report_from_path(self, path: str | Path) -> ScanReport:
        """Parse a JSON scan report file and store it in the session."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Report file not found: {path}")
        data = json.loads(p.read_text())
        report = ScanReport.model_validate(data)
        self.report = report
        return report

    def load_baseline_from_path(self, path: str | Path) -> ScanReport:
        """Parse a JSON scan report file and store it as the baseline."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Baseline file not found: {path}")
        data = json.loads(p.read_text())
        baseline = ScanReport.model_validate(data)
        self.baseline = baseline
        return baseline

    def require_report(self) -> ScanReport:
        """Return the current report or raise if none is loaded."""
        if self.report is None:
            raise RuntimeError(
                "No report loaded. Call load_report first, e.g.: "
                'load_report({"path": "report.json"})'
            )
        return self.report
