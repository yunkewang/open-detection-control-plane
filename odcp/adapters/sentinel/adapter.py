"""Sentinel adapter — translates Microsoft Sentinel analytics rules into ODCP."""

from __future__ import annotations

import json
import logging
import re
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


class SentinelAdapter(BaseAdapter):
    """Adapter for parsing Microsoft Sentinel analytics rules.

    Supports YAML rule files (as used by the Azure Sentinel GitHub repo)
    and JSON ARM template exports.
    """

    def parse_environment(self, path: Path) -> Environment:
        rule_count = len(self._find_rule_files(path))
        platform = Platform(
            name="sentinel",
            vendor="Microsoft",
            adapter_type="sentinel",
        )
        return Environment(
            name=path.name,
            description=(
                f"Sentinel analytics: {path.name} ({rule_count} rules)"
            ),
            platforms=[platform],
            metadata={"source_path": str(path)},
        )

    def parse_detections(self, path: Path) -> list[Detection]:
        detections: list[Detection] = []
        for rule_file in self._find_rule_files(path):
            rule = self._load_rule(rule_file)
            if not rule:
                continue
            det = self._parse_rule(rule, rule_file)
            if det:
                detections.append(det)
        logger.info(
            "Parsed %d Sentinel detections from %s",
            len(detections), path,
        )
        return detections

    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]:
        return []

    def resolve_dependencies(
        self,
        detections: list[Detection],
        knowledge_objects: list[KnowledgeObject],
    ) -> list[Dependency]:
        all_deps: list[Dependency] = []

        for det in detections:
            # Data connectors / tables
            for table in det.metadata.get("required_tables", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"table:{table}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "table", "value": table},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

            # Data connectors
            for conn in det.metadata.get("data_connectors", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"connector:{conn}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "connector", "value": conn},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

        return all_deps

    # --- Private helpers ---

    def _parse_rule(
        self, rule: dict, source_file: Path
    ) -> Detection | None:
        name = rule.get("name")
        if not name:
            return None

        severity = _SEVERITY_MAP.get(
            str(rule.get("severity", "medium")).lower(),
            DetectionSeverity.medium,
        )

        query = rule.get("query", "")

        # Extract MITRE tags
        tags: list[str] = list(rule.get("tags", []))
        tactics = rule.get("relevantTechniques", [])
        for t in tactics:
            if t not in tags:
                tags.append(t)

        # Extract table references from KQL
        tables = self._extract_kql_tables(query)

        # Data connectors
        connectors: list[str] = []
        for dc in rule.get("requiredDataConnectors", []):
            cname = dc.get("connectorId", "")
            if cname:
                connectors.append(cname)

        enabled = rule.get("enabled", True)
        if rule.get("status") == "Available":
            enabled = True

        return Detection(
            name=name,
            description=rule.get("description"),
            search_query=query,
            severity=severity,
            enabled=enabled,
            source_file=str(source_file.name),
            source_app=rule.get("author"),
            tags=tags,
            metadata={
                "rule_id": rule.get("id", ""),
                "kind": rule.get("kind", "Scheduled"),
                "query_frequency": rule.get("queryFrequency", ""),
                "query_period": rule.get("queryPeriod", ""),
                "trigger_operator": rule.get("triggerOperator", ""),
                "trigger_threshold": rule.get("triggerThreshold", 0),
                "required_tables": tables,
                "data_connectors": connectors,
                "tactics": rule.get("tactics", []),
                "relevant_techniques": tactics,
            },
        )

    @staticmethod
    def _extract_kql_tables(query: str) -> list[str]:
        """Extract table references from a KQL query."""
        if not query:
            return []
        # KQL tables typically appear at the start of a statement
        # or after union/join operators
        pattern = (
            r"(?:^|\bunion\b|\bjoin\b\s+(?:kind\s*=\s*\w+\s+)?)"
            r"\s*([A-Z][A-Za-z_]+)"
        )
        matches = re.findall(pattern, query, re.MULTILINE)
        # Filter out KQL keywords
        kql_keywords = {
            "where", "project", "extend", "summarize", "sort",
            "order", "take", "limit", "count", "distinct", "top",
            "render", "let", "print", "evaluate", "invoke",
            "parse", "make", "mv", "serialize",
        }
        tables = []
        seen: set[str] = set()
        for m in matches:
            lower = m.lower()
            if lower not in kql_keywords and m not in seen:
                seen.add(m)
                tables.append(m)
        return tables

    @staticmethod
    def _find_rule_files(path: Path) -> list[Path]:
        if path.is_file():
            return (
                [path]
                if path.suffix in (".yml", ".yaml", ".json")
                else []
            )
        files = (
            list(path.rglob("*.yml"))
            + list(path.rglob("*.yaml"))
            + list(path.rglob("*.json"))
        )
        return sorted(files)

    @staticmethod
    def _load_rule(path: Path) -> dict | None:
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                data = json.loads(text)
            else:
                data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except (yaml.YAMLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse %s: %s", path, exc)
            return None
