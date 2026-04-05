"""OCSF taxonomy mapper — normalizes vendor data sources to OCSF event classes.

Provides a curated mapping table and a mapper that converts vendor-specific
dependency references into OCSF (Open Cybersecurity Schema Framework) event
class identifiers, enabling cross-platform normalization.
"""

from __future__ import annotations

import logging
from typing import Optional

from odcp.models.detection import Detection
from odcp.models.dependency import Dependency
from odcp.models.ocsf import OcsfEventClass, OcsfMapping, OcsfNormalizationResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OCSF v1.1 event class catalog (curated subset)
# ---------------------------------------------------------------------------

OCSF_CATALOG: list[OcsfEventClass] = [
    OcsfEventClass(
        class_id=1001,
        class_name="File Activity",
        category="System Activity",
        description="File creation, modification, deletion, or access events.",
    ),
    OcsfEventClass(
        class_id=1007,
        class_name="Process Activity",
        category="System Activity",
        description="Process creation, termination, or injection events.",
    ),
    OcsfEventClass(
        class_id=1006,
        class_name="Module Activity",
        category="System Activity",
        description="Module/library load events (DLL, SO).",
    ),
    OcsfEventClass(
        class_id=1013,
        class_name="Registry Key Activity",
        category="System Activity",
        description="Windows registry key creation or modification events.",
    ),
    OcsfEventClass(
        class_id=4001,
        class_name="Network Activity",
        category="Network Activity",
        description="Network connection events.",
    ),
    OcsfEventClass(
        class_id=4003,
        class_name="DNS Activity",
        category="Network Activity",
        description="DNS query and response events.",
    ),
    OcsfEventClass(
        class_id=4002,
        class_name="HTTP Activity",
        category="Network Activity",
        description="HTTP request and response events.",
    ),
    OcsfEventClass(
        class_id=3001,
        class_name="Authentication",
        category="Identity & Access Management",
        description="Authentication attempt events (success/failure).",
    ),
    OcsfEventClass(
        class_id=3003,
        class_name="Account Change",
        category="Identity & Access Management",
        description="User/service account creation, modification, or deletion.",
    ),
    OcsfEventClass(
        class_id=6001,
        class_name="Email Activity",
        category="Application Activity",
        description="Email send, receive, and forwarding events.",
    ),
    OcsfEventClass(
        class_id=2001,
        class_name="Security Finding",
        category="Findings",
        description="Security findings from detection tools.",
    ),
    OcsfEventClass(
        class_id=4004,
        class_name="Firewall Activity",
        category="Network Activity",
        description="Firewall allow/block events.",
    ),
    OcsfEventClass(
        class_id=6003,
        class_name="Web Resource Access Activity",
        category="Application Activity",
        description="Web/proxy access events.",
    ),
]

OCSF_INDEX: dict[int, OcsfEventClass] = {c.class_id: c for c in OCSF_CATALOG}

# ---------------------------------------------------------------------------
# Vendor-to-OCSF mapping rules
# ---------------------------------------------------------------------------

# Maps (vendor_platform, source_key_pattern) → ocsf_class_id
_MAPPING_TABLE: list[tuple[Optional[str], str, int, float]] = [
    # Sigma logsource categories
    (None, "logsource:process_creation", 1007, 0.95),
    (None, "logsource:file_event", 1001, 0.95),
    (None, "logsource:network_connection", 4001, 0.90),
    (None, "logsource:dns_query", 4003, 0.95),
    (None, "logsource:image_load", 1006, 0.90),
    (None, "logsource:registry_event", 1013, 0.90),
    (None, "logsource:firewall", 4004, 0.90),
    (None, "logsource:proxy", 6003, 0.85),
    (None, "logsource:webserver", 4002, 0.85),
    (None, "logsource:antivirus", 2001, 0.80),
    # Sigma products
    (None, "product:windows", 1007, 0.50),
    (None, "product:linux", 1007, 0.50),
    # Splunk sourcetypes
    ("splunk", "WinEventLog", 1007, 0.70),
    ("splunk", "sysmon", 1007, 0.85),
    ("splunk", "xmlwineventlog", 1007, 0.70),
    ("splunk", "stream:dns", 4003, 0.90),
    ("splunk", "stream:http", 4002, 0.90),
    # Elastic index patterns
    ("elastic", "winlogbeat-*", 1007, 0.75),
    ("elastic", "filebeat-*", 1001, 0.70),
    ("elastic", "packetbeat-*", 4001, 0.75),
    ("elastic", "auditbeat-*", 3001, 0.75),
    # Sentinel tables
    ("sentinel", "SecurityEvent", 3001, 0.85),
    ("sentinel", "Syslog", 1007, 0.65),
    ("sentinel", "SigninLogs", 3001, 0.90),
    ("sentinel", "AzureActivity", 3003, 0.75),
    ("sentinel", "EmailEvents", 6001, 0.90),
    ("sentinel", "DnsEvents", 4003, 0.90),
]


class OcsfMapper:
    """Maps vendor dependencies to OCSF event classes."""

    def normalize(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
        platform: str = "unknown",
    ) -> OcsfNormalizationResult:
        """Normalize detection dependencies to OCSF taxonomy."""
        # Build dependency lookup
        dep_by_id: dict[str, Dependency] = {d.id: d for d in dependencies}

        mappings: list[OcsfMapping] = []
        mapped_detection_ids: set[str] = set()
        category_counts: dict[str, int] = {}

        for det in detections:
            det_mapped = False
            for ref_id in det.references:
                dep = dep_by_id.get(ref_id)
                if not dep:
                    continue

                vendor_source = dep.name
                mapping = self._find_mapping(vendor_source, platform)
                if mapping:
                    ocsf_class = OCSF_INDEX.get(mapping[0])
                    if ocsf_class:
                        mappings.append(
                            OcsfMapping(
                                vendor_source=vendor_source,
                                vendor_platform=platform,
                                ocsf_class_id=ocsf_class.class_id,
                                ocsf_class_name=ocsf_class.class_name,
                                ocsf_category=ocsf_class.category,
                                confidence=mapping[1],
                                metadata={
                                    "detection_id": det.id,
                                    "detection_name": det.name,
                                },
                            )
                        )
                        category_counts[ocsf_class.category] = (
                            category_counts.get(ocsf_class.category, 0) + 1
                        )
                        det_mapped = True

            if det_mapped:
                mapped_detection_ids.add(det.id)

        total = len(detections)
        mapped = len(mapped_detection_ids)

        return OcsfNormalizationResult(
            total_detections=total,
            mapped_detections=mapped,
            unmapped_detections=total - mapped,
            mappings=mappings,
            coverage_by_category=category_counts,
        )

    @staticmethod
    def _find_mapping(
        vendor_source: str,
        platform: str,
    ) -> Optional[tuple[int, float]]:
        """Find the best OCSF mapping for a vendor source string."""
        best: Optional[tuple[int, float]] = None

        for rule_platform, pattern, class_id, confidence in _MAPPING_TABLE:
            # Platform must match (None matches all)
            if rule_platform and rule_platform != platform:
                continue

            if pattern.lower() in vendor_source.lower():
                if best is None or confidence > best[1]:
                    best = (class_id, confidence)

        return best
