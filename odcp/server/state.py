"""Server state — report store and file watcher.

``ReportStore`` is the single source of truth for the web server.  It holds
the current ``ScanReport`` in memory, watches the source file for changes, and
notifies registered SSE subscribers when the report is refreshed.

Design:
- The report is loaded once at startup.
- A background ``asyncio`` task polls the file mtime every ``poll_interval``
  seconds; on change it re-parses the file and fires all subscriber queues.
- Subscribers are ``asyncio.Queue`` instances created by the SSE endpoint and
  removed when the client disconnects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from odcp.models.report import ScanReport

logger = logging.getLogger(__name__)


class ReportStore:
    """Holds the current ScanReport and manages background refresh.

    Parameters
    ----------
    report_path:
        Path to the JSON report file.  May be ``None`` if the server is
        started without a pre-loaded report (report can be loaded later via
        the ``/api/report/load`` endpoint).
    poll_interval:
        Seconds between file-mtime checks.  Set to 0 to disable polling.
    """

    def __init__(
        self,
        report_path: Optional[str | Path] = None,
        poll_interval: float = 5.0,
    ) -> None:
        self.report_path: Optional[Path] = Path(report_path) if report_path else None
        self.poll_interval = poll_interval
        self.report: Optional[ScanReport] = None
        self._last_mtime: float = 0.0
        self._subscribers: list[asyncio.Queue] = []
        self._watcher_task: Optional[asyncio.Task] = None

        if self.report_path:
            self._load_sync()

    # ── Sync load (called at startup, before event loop) ──────────────────

    def _load_sync(self) -> None:
        if self.report_path and self.report_path.exists():
            try:
                data = json.loads(self.report_path.read_text())
                self.report = ScanReport.model_validate(data)
                self._last_mtime = os.path.getmtime(self.report_path)
                logger.info("Loaded report: %s", self.report_path)
            except Exception as exc:
                logger.error("Failed to load report %s: %s", self.report_path, exc)

    # ── Async refresh ──────────────────────────────────────────────────────

    async def load_from_path(self, path: str | Path) -> ScanReport:
        """Load (or reload) a report file and notify all subscribers."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Report file not found: {path}")
        data = await asyncio.get_event_loop().run_in_executor(
            None, lambda: json.loads(p.read_text())
        )
        report = ScanReport.model_validate(data)
        self.report = report
        self.report_path = p
        self._last_mtime = os.path.getmtime(p)
        await self._notify("report_updated", {"path": str(p)})
        return report

    # ── SSE subscription ───────────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE subscriber and return its queue."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber queue (called when SSE client disconnects)."""
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def _notify(self, event: str, data: dict[str, Any]) -> None:
        payload = json.dumps({"event": event, **data})
        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    # ── Background file watcher ────────────────────────────────────────────

    async def start_watcher(self) -> None:
        """Start the background file-watch task (call from app lifespan)."""
        if self.poll_interval > 0:
            self._watcher_task = asyncio.create_task(self._watch_loop())

    async def stop_watcher(self) -> None:
        """Cancel the background task (call from app lifespan shutdown)."""
        if self._watcher_task:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except asyncio.CancelledError:
                pass

    async def _watch_loop(self) -> None:
        while True:
            await asyncio.sleep(self.poll_interval)
            if self.report_path is None or not self.report_path.exists():
                continue
            try:
                mtime = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: os.path.getmtime(self.report_path)  # type: ignore[arg-type]
                )
                if mtime > self._last_mtime:
                    logger.info("Report file changed, reloading…")
                    await self.load_from_path(self.report_path)
            except Exception as exc:
                logger.warning("File watch error: %s", exc)

    # ── Convenience getters ────────────────────────────────────────────────

    @property
    def loaded(self) -> bool:
        return self.report is not None

    def posture_dict(self) -> dict:
        """Return a compact posture summary dict for API/template consumption."""
        if self.report is None:
            return {}
        rs = self.report.readiness_summary
        ds = self.report.dependency_stats
        sev_counts: dict[str, int] = {}
        for f in self.report.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        return {
            "environment": self.report.environment.name,
            "platform": self.report.environment.platforms[0].adapter_type
            if self.report.environment.platforms
            else "unknown",
            "scan_timestamp": self.report.scan_timestamp.isoformat(),
            "total": rs.total_detections,
            "runnable": rs.runnable,
            "partially_runnable": rs.partially_runnable,
            "blocked": rs.blocked,
            "unknown": rs.unknown,
            "overall_score": round(rs.overall_score * 100),
            "blocked_pct": round(rs.blocked / rs.total_detections * 100)
            if rs.total_detections
            else 0,
            "total_findings": len(self.report.findings),
            "findings_by_severity": sev_counts,
            "total_deps": ds.total,
            "deps_by_status": ds.by_status,
        }
