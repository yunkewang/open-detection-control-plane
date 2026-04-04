"""Sigma adapter — translates Sigma YAML rules into the ODCP model."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from odcp.adapters import BaseAdapter
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    DetectionSeverity,
    Environment,
    KnowledgeObject,
    Platform,
)

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, DetectionSeverity] = {
    "informational": DetectionSeverity.informational,
    "low": DetectionSeverity.low,
    "medium": DetectionSeverity.medium,
    "high": DetectionSeverity.high,
    "critical": DetectionSeverity.critical,
}

# Common Sigma log source categories that map to data source dependencies
_LOGSOURCE_CATEGORIES: dict[str, DependencyKind] = {
    "process_creation": DependencyKind.field,
    "network_connection": DependencyKind.field,
    "file_event": DependencyKind.field,
    "registry_event": DependencyKind.field,
    "dns_query": DependencyKind.field,
    "image_load": DependencyKind.field,
    "firewall": DependencyKind.field,
    "proxy": DependencyKind.field,
    "webserver": DependencyKind.field,
    "antivirus": DependencyKind.field,
}


class SigmaAdapter(BaseAdapter):
    """Adapter for parsing Sigma YAML detection rules."""

    def parse_environment(self, path: Path) -> Environment:
        rule_count = len(self._find_rule_files(path))
        platform = Platform(
            name="sigma",
            vendor="Sigma",
            adapter_type="sigma",
        )
        return Environment(
            name=path.name,
            description=f"Sigma rule set: {path.name} ({rule_count} rules)",
            platforms=[platform],
            metadata={"source_path": str(path)},
        )

    def parse_detections(self, path: Path) -> list[Detection]:
        detections: list[Detection] = []
        for rule_file in self._find_rule_files(path):
            for rule in self._load_yaml_docs(rule_file):
                det = self._parse_rule(rule, rule_file)
                if det:
                    detections.append(det)
        logger.info("Parsed %d Sigma detections from %s", len(detections), path)
        return detections

    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]:
        # Sigma doesn't have separate knowledge objects like Splunk;
        # dependencies are self-contained in each rule's logsource.
        return []

    def resolve_dependencies(
        self,
        detections: list[Detection],
        knowledge_objects: list[KnowledgeObject],
    ) -> list[Dependency]:
        all_deps: list[Dependency] = []

        for det in detections:
            logsource = det.metadata.get("logsource", {})
            deps = self._extract_logsource_deps(logsource)

            for dep in deps:
                all_deps.append(dep)
                det.references.append(dep.id)

        return all_deps

    # --- Private helpers ---

    def _parse_rule(self, rule: dict, source_file: Path) -> Detection | None:
        if not isinstance(rule, dict):
            return None

        title = rule.get("title")
        if not title:
            return None

        severity = _SEVERITY_MAP.get(
            str(rule.get("level", "medium")).lower(),
            DetectionSeverity.medium,
        )

        # Build a pseudo search query from the detection block
        detection = rule.get("detection", {})
        search_query = self._detection_to_query(detection)

        tags = []
        for tag in rule.get("tags", []):
            tags.append(str(tag))

        # Extract MITRE ATT&CK IDs from tags
        mitre_tags = [
            t.replace("attack.", "").upper()
            for t in tags
            if t.startswith("attack.t")
        ]

        return Detection(
            name=title,
            description=rule.get("description"),
            search_query=search_query,
            severity=severity,
            enabled=rule.get("status", "test") != "deprecated",
            source_file=str(source_file.name),
            source_app=rule.get("author"),
            tags=tags + mitre_tags,
            metadata={
                "logsource": rule.get("logsource", {}),
                "sigma_id": rule.get("id", ""),
                "status": rule.get("status", ""),
                "falsepositives": rule.get("falsepositives", []),
                "references": rule.get("references", []),
                "date": rule.get("date", ""),
                "modified": rule.get("modified", ""),
            },
        )

    @staticmethod
    def _detection_to_query(detection: dict) -> str:
        """Convert Sigma detection block to a pseudo-query string."""
        parts: list[str] = []
        condition = detection.get("condition", "")
        if condition:
            parts.append(f"condition: {condition}")
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                fields = " AND ".join(
                    f"{k}={v}" for k, v in value.items()
                )
                parts.append(f"{key}: ({fields})")
            elif isinstance(value, list):
                items = " OR ".join(str(v) for v in value)
                parts.append(f"{key}: ({items})")
        return " | ".join(parts)

    @staticmethod
    def _extract_logsource_deps(
        logsource: dict,
    ) -> list[Dependency]:
        """Extract dependencies from a Sigma logsource block."""
        deps: list[Dependency] = []

        category = logsource.get("category", "")
        product = logsource.get("product", "")
        service = logsource.get("service", "")

        if category:
            deps.append(
                Dependency(
                    kind=DependencyKind.field,
                    name=f"logsource:{category}",
                    status=DependencyStatus.unknown,
                    metadata={"logsource_type": "category", "value": category},
                )
            )

        if product:
            deps.append(
                Dependency(
                    kind=DependencyKind.field,
                    name=f"product:{product}",
                    status=DependencyStatus.unknown,
                    metadata={"logsource_type": "product", "value": product},
                )
            )

        if service:
            deps.append(
                Dependency(
                    kind=DependencyKind.field,
                    name=f"service:{service}",
                    status=DependencyStatus.unknown,
                    metadata={"logsource_type": "service", "value": service},
                )
            )

        return deps

    @staticmethod
    def _find_rule_files(path: Path) -> list[Path]:
        """Find all YAML rule files in a directory."""
        if path.is_file():
            return [path] if path.suffix in (".yml", ".yaml") else []
        files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))
        return sorted(files)

    @staticmethod
    def _load_yaml_docs(path: Path) -> list[dict]:
        """Load one or more YAML documents from a file."""
        try:
            text = path.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(text))
            return [d for d in docs if isinstance(d, dict)]
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to parse %s: %s", path, exc)
            return []
