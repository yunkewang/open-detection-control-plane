"""Sigma adapter — translates Sigma YAML rules into the ODCP model.

Supports standard detection rules, correlation meta-rules (Sigma spec
v2.1.0: event_count, value_count, temporal), and filter/meta-filter
rules for environment-specific exclusions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

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
from odcp.models.correlation import CorrelationRule, CorrelationType, SigmaFilter

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
    """Adapter for parsing Sigma YAML detection rules.

    Also parses correlation meta-rules and filter rules into separate
    collections accessible via ``parse_correlations()`` and
    ``parse_filters()``.
    """

    def __init__(self) -> None:
        self._correlations: list[CorrelationRule] = []
        self._filters: list[SigmaFilter] = []

    # -- Public accessors for extended rule types --

    @property
    def correlations(self) -> list[CorrelationRule]:
        """Correlation meta-rules discovered during the last parse."""
        return list(self._correlations)

    @property
    def filters(self) -> list[SigmaFilter]:
        """Filter/meta-filter rules discovered during the last parse."""
        return list(self._filters)

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
        self._correlations = []
        self._filters = []

        for rule_file in self._find_rule_files(path):
            for rule in self._load_yaml_docs(rule_file):
                rule_type = str(rule.get("type", "")).lower() if isinstance(rule, dict) else ""

                if rule_type == "correlation":
                    corr = self._parse_correlation(rule, rule_file)
                    if corr:
                        self._correlations.append(corr)
                    continue

                if rule_type in ("filter", "meta_filter"):
                    filt = self._parse_filter(rule, rule_file)
                    if filt:
                        self._filters.append(filt)
                    continue

                det = self._parse_rule(rule, rule_file)
                if det:
                    detections.append(det)

        logger.info(
            "Parsed %d detections, %d correlations, %d filters from %s",
            len(detections),
            len(self._correlations),
            len(self._filters),
            path,
        )
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

    # --- Correlation & filter parsers ---

    @staticmethod
    def _parse_correlation(
        rule: dict, source_file: Path,
    ) -> Optional[CorrelationRule]:
        """Parse a Sigma v2.1.0 correlation meta-rule."""
        if not isinstance(rule, dict):
            return None

        name = rule.get("name") or rule.get("title", "")
        if not name:
            return None

        # Determine correlation type
        corr_block = rule.get("correlation", {})
        if not isinstance(corr_block, dict):
            return None

        type_str = str(corr_block.get("type", "event_count")).lower()
        try:
            corr_type = CorrelationType(type_str)
        except ValueError:
            corr_type = CorrelationType.event_count

        # Referenced rules
        rules_ref = corr_block.get("rules", [])
        if isinstance(rules_ref, str):
            rules_ref = [rules_ref]

        group_by = corr_block.get("group-by", [])
        if isinstance(group_by, str):
            group_by = [group_by]

        timespan = corr_block.get("timespan")
        condition_block = corr_block.get("condition", {})
        if isinstance(condition_block, dict):
            # e.g. {"gte": 5} → ">= 5"
            parts = []
            _OP_MAP = {"gte": ">=", "lte": "<=", "gt": ">", "lt": "<", "eq": "="}
            for op, val in condition_block.items():
                parts.append(f"{_OP_MAP.get(op, op)} {val}")
            condition_str = " AND ".join(parts) if parts else None
        elif isinstance(condition_block, str):
            condition_str = condition_block
        else:
            condition_str = None

        return CorrelationRule(
            name=name,
            correlation_type=corr_type,
            rule_references=rules_ref,
            group_by=group_by,
            timespan=str(timespan) if timespan else None,
            condition=condition_str,
            enabled=rule.get("status", "test") != "deprecated",
            source_file=str(source_file.name),
            metadata={
                "sigma_id": rule.get("id", ""),
                "status": rule.get("status", ""),
                "description": rule.get("description", ""),
            },
        )

    @staticmethod
    def _parse_filter(
        rule: dict, source_file: Path,
    ) -> Optional[SigmaFilter]:
        """Parse a Sigma filter or meta-filter rule."""
        if not isinstance(rule, dict):
            return None

        name = rule.get("name") or rule.get("title", "")
        if not name:
            return None

        # Target rules the filter applies to
        target_rules = rule.get("rules", [])
        if isinstance(target_rules, str):
            target_rules = [target_rules]

        # Logsource selector for meta-filters
        logsource_filter = rule.get("logsource")

        # Exclusion conditions (detection-block style)
        conditions = rule.get("detection", {})

        return SigmaFilter(
            name=name,
            target_rules=target_rules,
            conditions=conditions,
            logsource_filter=logsource_filter if isinstance(logsource_filter, dict) else None,
            enabled=rule.get("status", "test") != "deprecated",
            source_file=str(source_file.name),
            metadata={
                "sigma_id": rule.get("id", ""),
                "status": rule.get("status", ""),
                "description": rule.get("description", ""),
            },
        )

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
