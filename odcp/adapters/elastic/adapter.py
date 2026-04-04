"""Elastic adapter — translates Elastic detection rules into the ODCP model."""

from __future__ import annotations

import json
import logging
from pathlib import Path

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


class ElasticAdapter(BaseAdapter):
    """Adapter for parsing Elastic Security detection rules.

    Supports the JSON format used by Elastic's detection-rules repository
    and Kibana detection rule exports.
    """

    def parse_environment(self, path: Path) -> Environment:
        rule_count = len(self._find_rule_files(path))
        platform = Platform(
            name="elastic",
            vendor="Elastic",
            adapter_type="elastic",
        )
        return Environment(
            name=path.name,
            description=f"Elastic rule set: {path.name} ({rule_count} rules)",
            platforms=[platform],
            metadata={"source_path": str(path)},
        )

    def parse_detections(self, path: Path) -> list[Detection]:
        detections: list[Detection] = []
        for rule_file in self._find_rule_files(path):
            rule = self._load_json(rule_file)
            if not rule:
                continue
            det = self._parse_rule(rule, rule_file)
            if det:
                detections.append(det)
        logger.info(
            "Parsed %d Elastic detections from %s",
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
            # Index patterns
            for idx in det.metadata.get("index_patterns", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"index:{idx}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "index_pattern", "value": idx},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

            # Required fields
            for field in det.metadata.get("required_fields", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"field:{field}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "field", "value": field},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

        return all_deps

    # --- Private helpers ---

    def _parse_rule(
        self, rule: dict, source_file: Path
    ) -> Detection | None:
        name = rule.get("name") or rule.get("rule", {}).get("name")
        if not name:
            return None

        # Handle both flat and nested ("rule" key) formats
        r = rule.get("rule", rule)

        severity = _SEVERITY_MAP.get(
            str(r.get("severity", "medium")).lower(),
            DetectionSeverity.medium,
        )

        query = r.get("query", "")
        rule_type = r.get("type", "query")

        # Threat/MITRE tags
        tags: list[str] = list(r.get("tags", []))
        for threat in r.get("threat", []):
            technique = threat.get("technique", [])
            for tech in technique:
                tid = tech.get("id", "")
                if tid:
                    tags.append(tid)
                for sub in tech.get("subtechnique", []):
                    sid = sub.get("id", "")
                    if sid:
                        tags.append(sid)

        index_patterns = r.get("index", [])
        required_fields = r.get("required_fields", [])

        enabled = r.get("enabled", True)

        return Detection(
            name=name,
            description=r.get("description"),
            search_query=query,
            severity=severity,
            enabled=enabled,
            source_file=str(source_file.name),
            source_app=r.get("author", [None])[0]
            if isinstance(r.get("author"), list)
            else r.get("author"),
            tags=tags,
            metadata={
                "rule_id": r.get("rule_id", r.get("id", "")),
                "type": rule_type,
                "language": r.get("language", ""),
                "index_patterns": index_patterns,
                "required_fields": required_fields,
                "risk_score": r.get("risk_score", 0),
                "interval": r.get("interval", ""),
            },
        )

    @staticmethod
    def _find_rule_files(path: Path) -> list[Path]:
        if path.is_file():
            return [path] if path.suffix == ".json" else []
        return sorted(path.rglob("*.json"))

    @staticmethod
    def _load_json(path: Path) -> dict | None:
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse %s: %s", path, exc)
            return None
