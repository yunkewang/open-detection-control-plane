"""Unified source inventory builder.

Extracts data source capabilities from any platform's scan report and
builds a vendor-neutral SourceCatalog with fields, ATT&CK relevance,
and health status.
"""

from __future__ import annotations

import logging
import re
from typing import Sequence

from odcp.models.dependency import Dependency, DependencyKind, DependencyStatus
from odcp.models.detection import Detection
from odcp.models.report import ScanReport
from odcp.models.source_catalog import (
    SourceCatalog,
    SourceField,
    SourceHealth,
    SourceHealthStatus,
    UnifiedSource,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ATT&CK data source mapping (data source name -> typical source_types)
# ---------------------------------------------------------------------------

_ATTACK_DATA_SOURCE_MAP: dict[str, list[str]] = {
    "Process Creation": [
        "process_creation", "sysmon", "XmlWinEventLog", "wineventlog",
        "endpoint.processes", "DeviceProcessEvents",
    ],
    "Network Traffic": [
        "network_connection", "firewall", "zeek", "suricata", "netflow",
        "NetworkCommunicationEvents", "udm.network",
    ],
    "File Creation": [
        "file_event", "sysmon", "file_access", "DeviceFileEvents",
    ],
    "Command Execution": [
        "powershell", "bash", "cmd", "script_execution",
        "Microsoft-Windows-PowerShell", "DeviceEvents",
    ],
    "Authentication Logs": [
        "linux_secure", "auth", "WinSecurity", "SigninLogs",
        "SecurityEvent", "AADSignInEventsBeta",
    ],
    "DNS Logs": [
        "dns", "stream:dns", "DnsEvents", "dns_query",
    ],
    "Windows Registry": [
        "registry_event", "sysmon", "DeviceRegistryEvents",
        "registry_set", "registry_add",
    ],
    "Cloud API Logs": [
        "aws:cloudtrail", "azure:activity", "gcp:audit", "CloudAppEvents",
        "AzureActivity", "AWSCloudTrail",
    ],
    "Email Logs": [
        "email", "o365:management:activity", "EmailEvents", "OfficeActivity",
    ],
    "Web Proxy": [
        "proxy", "web", "squid", "bluecoat", "UrlClickEvents",
    ],
}

# Reverse map: source name fragment -> ATT&CK data sources
_SOURCE_TO_ATTACK: dict[str, list[str]] = {}
for ds_name, fragments in _ATTACK_DATA_SOURCE_MAP.items():
    for frag in fragments:
        _SOURCE_TO_ATTACK.setdefault(frag.lower(), []).append(ds_name)

# ---------------------------------------------------------------------------
# Field inference (common fields per source type)
# ---------------------------------------------------------------------------

_COMMON_FIELDS: dict[str, list[SourceField]] = {
    "process_creation": [
        SourceField(name="process.name", field_type="string", description="Process executable name"),
        SourceField(name="process.command_line", field_type="string", description="Full command line"),
        SourceField(name="process.pid", field_type="integer", description="Process ID"),
        SourceField(name="process.parent.name", field_type="string", description="Parent process name"),
        SourceField(name="user.name", field_type="string", description="User who started the process"),
    ],
    "network_connection": [
        SourceField(name="src.ip", field_type="ip", description="Source IP address"),
        SourceField(name="dst.ip", field_type="ip", description="Destination IP address"),
        SourceField(name="dst.port", field_type="integer", description="Destination port"),
        SourceField(name="network.protocol", field_type="string", description="Network protocol"),
    ],
    "file_event": [
        SourceField(name="file.path", field_type="string", description="Full file path"),
        SourceField(name="file.name", field_type="string", description="File name"),
        SourceField(name="file.hash", field_type="string", description="File hash"),
    ],
    "dns_query": [
        SourceField(name="dns.question.name", field_type="string", description="DNS query name"),
        SourceField(name="dns.answer.data", field_type="string", description="DNS answer"),
        SourceField(name="dns.question.type", field_type="string", description="DNS query type"),
    ],
    "authentication": [
        SourceField(name="user.name", field_type="string", description="Authenticating user"),
        SourceField(name="src.ip", field_type="ip", description="Source IP"),
        SourceField(name="event.outcome", field_type="string", description="Success or failure"),
    ],
}


class SourceInventoryBuilder:
    """Build a unified SourceCatalog from one or more scan reports."""

    def build_catalog(self, reports: Sequence[ScanReport]) -> SourceCatalog:
        """Build a catalog from multiple platform scan reports."""
        all_sources: list[UnifiedSource] = []
        for report in reports:
            all_sources.extend(self._extract_sources(report))

        # Deduplicate by (platform, source_type, name)
        seen: dict[str, UnifiedSource] = {}
        for src in all_sources:
            key = f"{src.platform}:{src.source_type}:{src.name}"
            if key in seen:
                existing = seen[key]
                existing.detection_count += src.detection_count
                existing.observed = existing.observed or src.observed
                # Merge fields
                existing_field_names = {f.name for f in existing.fields}
                for field in src.fields:
                    if field.name not in existing_field_names:
                        existing.fields.append(field)
                        existing_field_names.add(field.name)
            else:
                seen[key] = src

        sources = list(seen.values())

        # Build aggregate stats
        platforms = sorted({s.platform for s in sources})
        healthy = sum(1 for s in sources if s.health.status == SourceHealthStatus.healthy)
        degraded = sum(1 for s in sources if s.health.status == SourceHealthStatus.degraded)
        unavailable = sum(1 for s in sources if s.health.status == SourceHealthStatus.unavailable)

        # ATT&CK data source coverage
        attack_coverage: dict[str, int] = {}
        for src in sources:
            for ads in src.attack_data_sources:
                attack_coverage[ads] = attack_coverage.get(ads, 0) + 1

        # Field coverage
        field_coverage: dict[str, int] = {}
        for src in sources:
            for f in src.fields:
                field_coverage[f.name] = field_coverage.get(f.name, 0) + 1

        return SourceCatalog(
            sources=sources,
            total_sources=len(sources),
            healthy_sources=healthy,
            degraded_sources=degraded,
            unavailable_sources=unavailable,
            platforms_represented=platforms,
            attack_data_source_coverage=attack_coverage,
            field_coverage=field_coverage,
        )

    def build_from_single(self, report: ScanReport) -> SourceCatalog:
        """Convenience: build catalog from a single report."""
        return self.build_catalog([report])

    # ------------------------------------------------------------------
    # Internal extraction
    # ------------------------------------------------------------------

    def _extract_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract unified sources from a scan report, dispatching by platform."""
        platform = self._get_platform(report)
        sources: list[UnifiedSource] = []

        # Try coverage-enriched inventory first
        inv = report.metadata.get("data_source_inventory", {})
        inv_sources = inv.get("sources", [])
        if inv_sources:
            for entry in inv_sources:
                src = self._from_inventory_entry(entry, platform)
                sources.append(src)

        # Extract from dependencies (all platforms)
        dep_sources = self._from_dependencies(report.dependencies, report.detections, platform)
        sources.extend(dep_sources)

        # Platform-specific extraction from detection metadata
        if platform == "splunk":
            sources.extend(self._extract_splunk_sources(report))
        elif platform == "sigma":
            sources.extend(self._extract_sigma_sources(report))
        elif platform == "elastic":
            sources.extend(self._extract_elastic_sources(report))
        elif platform == "sentinel":
            sources.extend(self._extract_sentinel_sources(report))
        elif platform == "chronicle":
            sources.extend(self._extract_chronicle_sources(report))

        # Enrich with ATT&CK mapping and fields
        for src in sources:
            self._enrich_attack_mapping(src)
            self._enrich_fields(src)
            self._infer_health(src, report)

        return sources

    def _from_inventory_entry(self, entry: dict, platform: str) -> UnifiedSource:
        """Convert a data_source_inventory entry to a UnifiedSource."""
        return UnifiedSource(
            name=entry.get("name", "unknown"),
            platform=platform,
            source_type=entry.get("source_type", "unknown"),
            observed=entry.get("observed", False),
            detection_count=entry.get("detection_count", 0),
        )

    def _from_dependencies(
        self,
        dependencies: list[Dependency],
        detections: list[Detection],
        platform: str,
    ) -> list[UnifiedSource]:
        """Extract sources from dependency objects."""
        # Count detections per dependency
        dep_det_count: dict[str, int] = {}
        for det in detections:
            for ref in det.references:
                dep_det_count[ref] = dep_det_count.get(ref, 0) + 1

        sources: list[UnifiedSource] = []
        seen: set[str] = set()
        source_kinds = {
            DependencyKind.data_model, DependencyKind.lookup,
            DependencyKind.field,
        }
        for dep in dependencies:
            if dep.kind not in source_kinds:
                continue
            key = f"{dep.kind.value}:{dep.name}"
            if key in seen:
                continue
            seen.add(key)

            source_type = self._dep_kind_to_source_type(dep.kind, dep.name, platform)
            sources.append(UnifiedSource(
                name=dep.name,
                platform=platform,
                source_type=source_type,
                observed=dep.status == DependencyStatus.resolved,
                detection_count=dep_det_count.get(dep.id, 0),
            ))
        return sources

    def _extract_splunk_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract Splunk-specific sources from detection queries."""
        from odcp.analyzers.coverage.data_sources import (
            extract_datamodel_references,
            extract_index_references,
            extract_sourcetype_references,
        )
        sources: list[UnifiedSource] = []
        seen: set[str] = set()

        for det in report.detections:
            for idx in extract_index_references(det.search_query):
                key = f"index:{idx}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=idx, platform="splunk", source_type="index",
                        provides=[f"Raw events from index '{idx}'"],
                    ))
            for st in extract_sourcetype_references(det.search_query):
                key = f"sourcetype:{st}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=st, platform="splunk", source_type="sourcetype",
                        provides=[f"Normalized events from sourcetype '{st}'"],
                    ))
            for dm in extract_datamodel_references(det.search_query):
                key = f"data_model:{dm}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=dm, platform="splunk", source_type="data_model",
                        provides=[f"Accelerated CIM data model '{dm}'"],
                    ))
        return sources

    def _extract_sigma_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract Sigma logsource info from detection metadata."""
        sources: list[UnifiedSource] = []
        seen: set[str] = set()

        for det in report.detections:
            ls = det.metadata.get("logsource", {})
            category = ls.get("category", "")
            product = ls.get("product", "")
            service = ls.get("service", "")

            if category:
                key = f"logsource:{category}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=category, platform="sigma", source_type="logsource_category",
                        provides=[f"Sigma logsource category '{category}'"],
                    ))
            if product:
                key = f"product:{product}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=product, platform="sigma", source_type="logsource_product",
                        provides=[f"Vendor/OS product '{product}'"],
                    ))
            if service:
                key = f"service:{service}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=service, platform="sigma", source_type="logsource_service",
                        provides=[f"Service-level source '{service}'"],
                    ))
        return sources

    def _extract_elastic_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract Elastic index patterns from detection metadata."""
        sources: list[UnifiedSource] = []
        seen: set[str] = set()

        for det in report.detections:
            for pattern in det.metadata.get("index_patterns", []):
                if pattern not in seen:
                    seen.add(pattern)
                    sources.append(UnifiedSource(
                        name=pattern, platform="elastic", source_type="index_pattern",
                        provides=[f"Elastic index pattern '{pattern}'"],
                    ))
        return sources

    def _extract_sentinel_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract Sentinel tables and connectors from detection metadata."""
        sources: list[UnifiedSource] = []
        seen: set[str] = set()

        for det in report.detections:
            for conn in det.metadata.get("data_connectors", []):
                if conn not in seen:
                    seen.add(conn)
                    sources.append(UnifiedSource(
                        name=conn, platform="sentinel", source_type="connector",
                        provides=[f"Sentinel data connector '{conn}'"],
                    ))
        return sources

    def _extract_chronicle_sources(self, report: ScanReport) -> list[UnifiedSource]:
        """Extract Chronicle UDM entities and reference lists from metadata."""
        sources: list[UnifiedSource] = []
        seen: set[str] = set()

        for det in report.detections:
            for entity in det.metadata.get("udm_entities", []):
                key = f"udm:{entity}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=entity, platform="chronicle", source_type="udm_entity",
                        provides=[f"UDM entity type '{entity}'"],
                    ))
            for rl in det.metadata.get("reference_lists", []):
                key = f"reflist:{rl}"
                if key not in seen:
                    seen.add(key)
                    sources.append(UnifiedSource(
                        name=rl, platform="chronicle", source_type="reference_list",
                        provides=[f"Chronicle reference list '{rl}'"],
                    ))
        return sources

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _enrich_attack_mapping(self, source: UnifiedSource) -> None:
        """Map a source to ATT&CK data sources based on name heuristics."""
        name_lower = source.name.lower()
        matched: set[str] = set()
        for fragment, ds_names in _SOURCE_TO_ATTACK.items():
            if fragment in name_lower:
                matched.update(ds_names)
        source.attack_data_sources = sorted(matched)

    def _enrich_fields(self, source: UnifiedSource) -> None:
        """Add common fields based on the source type / category."""
        if source.fields:
            return  # already populated

        name_lower = source.name.lower()
        for category, fields in _COMMON_FIELDS.items():
            if category in name_lower:
                source.fields = list(fields)
                return

    def _infer_health(self, source: UnifiedSource, report: ScanReport) -> None:
        """Infer health status from runtime metadata if available."""
        runtime = report.metadata.get("runtime_summary", {})
        if not runtime:
            return

        # Check if we have specific index/lookup/data_model health data
        combined = report.metadata.get("combined_scores", [])
        if not combined:
            return

        # If runtime is available and source is observed, mark healthy
        if source.observed:
            source.health.status = SourceHealthStatus.healthy
        elif source.observed is False and source.source_type in ("index", "sourcetype", "data_model"):
            source.health.status = SourceHealthStatus.unavailable

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _get_platform(report: ScanReport) -> str:
        if report.environment.platforms:
            return report.environment.platforms[0].name
        return "unknown"

    @staticmethod
    def _dep_kind_to_source_type(kind: DependencyKind, name: str, platform: str) -> str:
        if kind == DependencyKind.data_model:
            return "data_model"
        if kind == DependencyKind.lookup:
            return "lookup" if platform != "chronicle" else "reference_list"
        if kind == DependencyKind.field:
            if platform == "elastic":
                return "required_field"
            if platform == "sentinel":
                if name.startswith("connector:"):
                    return "connector"
                return "table"
            if platform == "chronicle":
                if name.startswith("udm_entity:"):
                    return "udm_entity"
                return "udm_field"
            if platform == "sigma":
                if name.startswith("logsource:"):
                    return "logsource_category"
                if name.startswith("product:"):
                    return "logsource_product"
                return "logsource_service"
        return "unknown"
