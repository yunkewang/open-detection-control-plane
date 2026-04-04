"""Splunk REST API client for collecting runtime health signals."""

from __future__ import annotations

import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from json import JSONDecodeError, loads
from typing import Any, Optional

from odcp.models.runtime import (
    DataModelHealth,
    IndexHealth,
    LookupHealth,
    SavedSearchHealth,
)

logger = logging.getLogger(__name__)

# Splunk REST API returns Atom/XML by default; request JSON.
_JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


class SplunkAPIError(Exception):
    """Raised when a Splunk REST API call fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SplunkAPIClient:
    """Minimal Splunk REST API client using only the standard library.

    Supports token-based auth (Bearer) and basic username/password auth.
    SSL verification can be disabled for self-signed certs (common in Splunk
    deployments) via *verify_ssl*.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.username = username
        self.password = password
        self.timeout = timeout

        self._ssl_ctx: ssl.SSLContext | None = None
        if not verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request against the Splunk REST API and return JSON."""
        url = f"{self.base_url}{endpoint}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url, method=method)
        for k, v in _JSON_HEADERS.items():
            req.add_header(k, v)

        # Auth
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        elif self.username and self.password:
            import base64

            cred = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {cred}")

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx)
            body = resp.read().decode("utf-8")
            return loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            msg = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            raise SplunkAPIError(msg, status_code=exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SplunkAPIError(f"Connection failed: {exc}") from exc
        except JSONDecodeError as exc:
            raise SplunkAPIError(f"Invalid JSON response: {exc}") from exc

    def _get(self, endpoint: str, **params: str) -> dict[str, Any]:
        return self._request("GET", endpoint, params=params if params else None)

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    def test_connection(self) -> dict[str, Any]:
        """Test connectivity and return server info."""
        data = self._get("/services/server/info", output_mode="json")
        entries = data.get("entry", [])
        if entries:
            return entries[0].get("content", {})
        return data

    # ------------------------------------------------------------------
    # Saved search execution status
    # ------------------------------------------------------------------

    def get_saved_search_health(self, name: str) -> SavedSearchHealth:
        """Retrieve runtime health for a saved search by name."""
        encoded = urllib.parse.quote(name, safe="")
        try:
            data = self._get(
                f"/servicesNS/-/-/saved/searches/{encoded}",
                output_mode="json",
            )
        except SplunkAPIError as exc:
            logger.warning("Could not fetch saved search '%s': %s", name, exc)
            return SavedSearchHealth(name=name)

        entries = data.get("entry", [])
        if not entries:
            return SavedSearchHealth(name=name)

        content = entries[0].get("content", {})
        return SavedSearchHealth(
            name=name,
            last_run_time=_parse_splunk_time(content.get("triggered_alert_count_time")),
            next_scheduled_time=_parse_splunk_time(content.get("next_scheduled_time")),
            last_run_status=content.get("dispatch.status", None),
            is_scheduled=content.get("is_scheduled", "0") == "1",
            dispatch_ttl=content.get("dispatch.ttl"),
            metadata={
                k: v
                for k, v in content.items()
                if k.startswith("dispatch.") or k.startswith("alert.")
            },
        )

    def get_saved_search_history(self, name: str, count: int = 5) -> list[dict[str, Any]]:
        """Retrieve recent dispatch history for a saved search."""
        encoded = urllib.parse.quote(name, safe="")
        try:
            data = self._get(
                f"/servicesNS/-/-/saved/searches/{encoded}/history",
                output_mode="json",
                count=str(count),
            )
        except SplunkAPIError as exc:
            logger.warning("Could not fetch history for '%s': %s", name, exc)
            return []

        results = []
        for entry in data.get("entry", []):
            content = entry.get("content", {})
            results.append(
                {
                    "sid": content.get("sid", entry.get("name", "")),
                    "run_time": content.get("runDuration"),
                    "event_count": content.get("eventCount"),
                    "result_count": content.get("resultCount"),
                    "is_done": content.get("isDone"),
                    "is_failed": content.get("isFailed"),
                    "dispatch_state": content.get("dispatchState"),
                }
            )
        return results

    # ------------------------------------------------------------------
    # Lookup / KV store health
    # ------------------------------------------------------------------

    def get_lookup_health(self, name: str) -> LookupHealth:
        """Retrieve runtime health for a lookup definition."""
        encoded = urllib.parse.quote(name, safe="")
        try:
            data = self._get(
                f"/servicesNS/-/-/data/transforms/lookups/{encoded}",
                output_mode="json",
            )
        except SplunkAPIError as exc:
            logger.warning("Could not fetch lookup '%s': %s", name, exc)
            return LookupHealth(name=name, exists=False)

        entries = data.get("entry", [])
        if not entries:
            return LookupHealth(name=name, exists=False)

        content = entries[0].get("content", {})
        lookup_type = "csv"
        if content.get("external_type"):
            lookup_type = "kvstore"
        elif content.get("type") == "external":
            lookup_type = "external"

        return LookupHealth(
            name=name,
            exists=True,
            lookup_type=lookup_type,
            metadata={k: v for k, v in content.items() if k != "eai:data"},
        )

    # ------------------------------------------------------------------
    # Data model acceleration status
    # ------------------------------------------------------------------

    def get_data_model_health(self, name: str) -> DataModelHealth:
        """Retrieve runtime health for a data model."""
        encoded = urllib.parse.quote(name, safe="")
        try:
            data = self._get(
                f"/servicesNS/-/-/datamodel/model/{encoded}",
                output_mode="json",
            )
        except SplunkAPIError as exc:
            logger.warning("Could not fetch data model '%s': %s", name, exc)
            return DataModelHealth(name=name, exists=False)

        entries = data.get("entry", [])
        if not entries:
            return DataModelHealth(name=name, exists=False)

        content = entries[0].get("content", {})
        accel = content.get("acceleration", {})
        if isinstance(accel, str):
            accel = {}

        return DataModelHealth(
            name=name,
            exists=True,
            acceleration_enabled=content.get("acceleration.enabled", "0") == "1",
            acceleration_complete=accel.get("is_done", False) if isinstance(accel, dict) else False,
            acceleration_percent=(
                float(accel.get("completion", 0.0)) if isinstance(accel, dict) else 0.0
            ),
            earliest_time=content.get("acceleration.earliest_time"),
            metadata={k: v for k, v in content.items() if "acceleration" in k.lower()},
        )

    # ------------------------------------------------------------------
    # Index / sourcetype data flow health
    # ------------------------------------------------------------------

    def get_index_health(self, name: str) -> IndexHealth:
        """Retrieve runtime health for a Splunk index."""
        encoded = urllib.parse.quote(name, safe="")
        try:
            data = self._get(
                f"/services/data/indexes/{encoded}",
                output_mode="json",
            )
        except SplunkAPIError as exc:
            logger.warning("Could not fetch index '%s': %s", name, exc)
            return IndexHealth(name=name, exists=False)

        entries = data.get("entry", [])
        if not entries:
            return IndexHealth(name=name, exists=False)

        content = entries[0].get("content", {})
        total_count = int(content.get("totalEventCount", 0))
        current_size = int(content.get("currentDBSizeMB", 0)) * 1024 * 1024

        return IndexHealth(
            name=name,
            exists=True,
            total_event_count=total_count,
            current_size_bytes=current_size,
            is_receiving_data=total_count > 0,
            metadata={
                "homePath": content.get("homePath"),
                "maxTotalDataSizeMB": content.get("maxTotalDataSizeMB"),
                "frozenTimePeriodInSecs": content.get("frozenTimePeriodInSecs"),
            },
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _parse_splunk_time(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parse of Splunk time strings."""
    if not value or value in ("", "0", "N/A"):
        return None
    # Splunk often returns ISO-like or epoch strings
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        pass
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    return None
