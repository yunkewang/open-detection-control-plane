"""Collector agent — scheduled scanning and push to central server.

``CollectionAgent`` runs in a blocking loop:

1. Register with the central ODCP server on startup.
2. Run an immediate scan, then push the result.
3. Sleep for ``scan_interval_seconds``.
4. Send a heartbeat at ``heartbeat_interval_seconds`` (default 60 s).
5. Repeat until interrupted (SIGINT/SIGTERM).

The agent is deliberately synchronous so it can run in a plain Python
process without an event loop requirement.  For async contexts, use
``asyncio.run_in_executor`` or deploy as a separate process.
"""

from __future__ import annotations

import logging
import platform
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from odcp.models.collector import (
    AgentConfig,
    AgentHeartbeat,
    AgentRegistration,
    AgentStatus,
)
from odcp.models.report import ScanReport
from odcp.collector.push_client import PushClient

logger = logging.getLogger(__name__)


class CollectionAgent:
    """Scheduled collector agent.

    Parameters
    ----------
    config:
        Full agent configuration.
    heartbeat_interval_seconds:
        How often to send liveness signals between scans.
    dry_run:
        When True, run scans and log results but do not push to the server.
    """

    def __init__(
        self,
        config: AgentConfig,
        heartbeat_interval_seconds: int = 60,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        self.heartbeat_interval = heartbeat_interval_seconds
        self.dry_run = dry_run

        self.client = PushClient(
            central_url=config.central_url,
            agent_id=config.agent_id,
            api_token=config.api_token,
        )

        self._running = False
        self._last_report: Optional[ScanReport] = None
        self._last_scan_at: Optional[datetime] = None
        self._last_heartbeat_at: Optional[datetime] = None
        self._scan_errors: int = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the agent loop (blocks until stopped)."""
        self._setup_signal_handlers()
        self._running = True

        logger.info(
            "Starting collector agent '%s' (platform=%s, interval=%ds)",
            self.config.agent_id,
            self.config.platform,
            self.config.scan_interval_seconds,
        )

        # Register
        if not self.dry_run:
            self._register()

        # Immediate first scan
        self._run_scan_cycle()

        # Main loop
        last_loop_at = time.monotonic()
        while self._running:
            now = time.monotonic()
            elapsed = now - last_loop_at

            if elapsed >= self.config.scan_interval_seconds:
                self._run_scan_cycle()
                last_loop_at = time.monotonic()
            elif self._heartbeat_due():
                self._send_heartbeat(AgentStatus.active)

            time.sleep(min(5, self.config.scan_interval_seconds))

        # Deregister on clean exit
        if not self.dry_run:
            self.client.deregister()
        logger.info("Agent '%s' stopped.", self.config.agent_id)

    def stop(self) -> None:
        """Signal the agent to stop after the current scan completes."""
        self._running = False

    # ── Core operations ────────────────────────────────────────────────────

    def _run_scan_cycle(self) -> None:
        """Run one scan and push the result."""
        logger.info(
            "[%s] Running %s scan on %s",
            self.config.agent_id,
            self.config.platform,
            self.config.scan_path,
        )
        try:
            report = self.run_scan()
            self._last_report = report
            self._last_scan_at = datetime.now(timezone.utc)
            self._scan_errors = 0

            if not self.dry_run:
                pushed = self.client.push_report(report)
                if pushed:
                    logger.info(
                        "[%s] Pushed report: %d detections, score=%.0f%%",
                        self.config.agent_id,
                        report.readiness_summary.total_detections,
                        report.readiness_summary.overall_score * 100,
                    )
                else:
                    logger.warning("[%s] Failed to push report.", self.config.agent_id)
                    self._send_heartbeat(AgentStatus.degraded)
            else:
                logger.info(
                    "[dry-run] %s: %d detections, score=%.0f%%",
                    self.config.agent_id,
                    report.readiness_summary.total_detections,
                    report.readiness_summary.overall_score * 100,
                )

        except Exception as exc:
            self._scan_errors += 1
            logger.error("[%s] Scan failed: %s", self.config.agent_id, exc, exc_info=True)
            if not self.dry_run:
                self._send_heartbeat(AgentStatus.degraded, error=str(exc))

        self._last_heartbeat_at = datetime.now(timezone.utc)

    def run_scan(self) -> ScanReport:
        """Execute the platform scan and return a ScanReport.

        Dispatches to the appropriate ODCP adapter based on
        ``self.config.platform``.
        """
        adapter = self._build_adapter()
        from odcp.core.engine import ScanEngine

        engine = ScanEngine(adapter)
        report = engine.scan(Path(self.config.scan_path))
        return report

    def _build_adapter(self):
        """Return the correct adapter for the configured platform."""
        p = self.config.platform.lower()
        if p == "splunk":
            from odcp.adapters.splunk import SplunkAdapter
            return SplunkAdapter()
        if p == "sigma":
            from odcp.adapters.sigma import SigmaAdapter
            return SigmaAdapter()
        if p == "elastic":
            from odcp.adapters.elastic import ElasticAdapter
            return ElasticAdapter()
        if p == "sentinel":
            from odcp.adapters.sentinel import SentinelAdapter
            return SentinelAdapter()
        if p == "chronicle":
            from odcp.adapters.chronicle import ChronicleAdapter
            return ChronicleAdapter()
        raise ValueError(
            f"Unknown platform '{self.config.platform}'. "
            "Expected: splunk, sigma, elastic, sentinel, chronicle."
        )

    # ── Registration & heartbeat ───────────────────────────────────────────

    def _register(self) -> None:
        reg = AgentRegistration(
            config=self.config,
            odcp_version=self._odcp_version(),
            python_version=sys.version.split()[0],
        )
        ok = self.client.register(reg)
        if ok:
            logger.info("[%s] Registered with central server.", self.config.agent_id)
        else:
            logger.warning(
                "[%s] Registration failed — continuing in offline mode.", self.config.agent_id
            )

    def _heartbeat_due(self) -> bool:
        if self._last_heartbeat_at is None:
            return True
        elapsed = (datetime.now(timezone.utc) - self._last_heartbeat_at).total_seconds()
        return elapsed >= self.heartbeat_interval

    def _send_heartbeat(
        self,
        status: AgentStatus = AgentStatus.active,
        error: Optional[str] = None,
    ) -> None:
        hb = AgentHeartbeat(
            agent_id=self.config.agent_id,
            status=status,
            last_scan_timestamp=self._last_scan_at,
            last_scan_total_detections=self._last_report.readiness_summary.total_detections
            if self._last_report
            else 0,
            last_scan_readiness_score=self._last_report.readiness_summary.overall_score
            if self._last_report
            else 0.0,
            error_message=error,
        )
        self.client.send_heartbeat(hb)
        self._last_heartbeat_at = datetime.now(timezone.utc)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _setup_signal_handlers(self) -> None:
        def _handle(signum, frame):
            logger.info("Signal %d received — stopping agent…", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)

    @staticmethod
    def _odcp_version() -> str:
        try:
            from odcp import __version__
            return __version__
        except Exception:
            return "0.1.0"

    @staticmethod
    def hostname() -> str:
        try:
            return platform.node()
        except Exception:
            return "unknown"

    # ── Class-level factory ────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path, **kwargs) -> "CollectionAgent":
        """Load an ``AgentConfig`` from a YAML file and create an agent."""
        import yaml  # type: ignore[import]

        data = yaml.safe_load(Path(path).read_text())
        config = AgentConfig.model_validate(data)
        # Fill hostname if not set
        if not config.hostname:
            config.hostname = cls.hostname()
        return cls(config, **kwargs)

    @classmethod
    def from_args(
        cls,
        *,
        agent_id: str,
        environment_name: str,
        platform: str,
        scan_path: str,
        central_url: str,
        scan_interval_seconds: int = 300,
        api_token: Optional[str] = None,
        tags: Optional[list[str]] = None,
        **kwargs,
    ) -> "CollectionAgent":
        """Create an agent from explicit keyword arguments."""
        config = AgentConfig(
            agent_id=agent_id,
            environment_name=environment_name,
            platform=platform,
            scan_path=scan_path,
            central_url=central_url,
            scan_interval_seconds=scan_interval_seconds,
            api_token=api_token,
            tags=tags or [],
            hostname=cls.hostname(),
        )
        return cls(config, **kwargs)
