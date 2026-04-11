"""HTTP push client — sends scan results to the central ODCP server.

Uses only the Python standard library (``urllib``) so the collector agent
can be deployed with zero extra runtime dependencies.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any, Optional

from odcp.models.collector import AgentHeartbeat, AgentRegistration, AgentStatus
from odcp.models.report import ScanReport

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30  # seconds


class PushClient:
    """Thin HTTP client for communicating with the central ODCP server.

    Parameters
    ----------
    central_url:
        Base URL of the central ODCP server (e.g. ``http://odcp:8080``).
    agent_id:
        The ID of this agent, used to construct per-agent endpoints.
    api_token:
        Optional bearer token for server authentication.
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        central_url: str,
        agent_id: str,
        api_token: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.base = central_url.rstrip("/")
        self.agent_id = agent_id
        self.api_token = api_token
        self.timeout = timeout

    # ── Public methods ─────────────────────────────────────────────────────

    def register(self, registration: AgentRegistration) -> bool:
        """Register this agent with the central server.

        Returns True on success; logs and returns False on failure.
        """
        return self._post(
            "/api/fleet/agents/register",
            registration.model_dump(mode="json"),
        )

    def push_report(self, report: ScanReport) -> bool:
        """Push a completed scan report to the central server."""
        return self._post(
            f"/api/fleet/agents/{self.agent_id}/report",
            json.loads(report.model_dump_json()),
        )

    def send_heartbeat(self, heartbeat: AgentHeartbeat) -> bool:
        """Send a liveness heartbeat to the central server."""
        return self._post(
            f"/api/fleet/agents/{self.agent_id}/heartbeat",
            heartbeat.model_dump(mode="json"),
        )

    def deregister(self) -> bool:
        """Notify the central server that this agent is shutting down."""
        return self._delete(f"/api/fleet/agents/{self.agent_id}")

    def get_fleet_summary(self) -> Optional[dict[str, Any]]:
        """Fetch the fleet summary from the central server."""
        return self._get("/api/fleet/summary")

    def get_agent_list(self) -> Optional[list[dict[str, Any]]]:
        """Fetch the list of all registered agents."""
        result = self._get("/api/fleet/agents")
        if result and isinstance(result, dict):
            return result.get("agents", [])
        return None

    def check_health(self) -> bool:
        """Ping the central server; return True if reachable."""
        result = self._get("/api/fleet/health")
        return result is not None

    # ── Internal HTTP helpers ──────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_token:
            h["Authorization"] = f"Bearer {self.api_token}"
        return h

    def _post(self, path: str, payload: Any) -> bool:
        url = self.base + path
        data = json.dumps(payload, default=str).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ok = 200 <= resp.status < 300
                if not ok:
                    logger.warning("POST %s → HTTP %d", path, resp.status)
                return ok
        except urllib.error.HTTPError as exc:
            logger.error("POST %s → HTTP %d: %s", path, exc.code, exc.reason)
            return False
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            logger.error("POST %s → network error: %s", path, exc)
            return False

    def _delete(self, path: str) -> bool:
        url = self.base + path
        req = urllib.request.Request(url, headers=self._headers(), method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:
            logger.warning("DELETE %s failed: %s", path, exc)
            return False

    def _get(self, path: str) -> Optional[Any]:
        url = self.base + path
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode()
                return json.loads(body)
        except Exception as exc:
            logger.warning("GET %s failed: %s", path, exc)
            return None
