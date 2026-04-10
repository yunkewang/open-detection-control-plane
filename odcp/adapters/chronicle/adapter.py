"""Chronicle adapter — translates Google Chronicle YARA-L rules into the ODCP model.

Parses YARA-L 2.0 detection rules used by Google Chronicle (now Google
Security Operations).  Supports standard detection rules with ``meta``,
``events``, ``match``, ``outcome``, and ``condition`` sections, as well as
reference list dependencies.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

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

# YARA-L section headers (order matters for parsing)
_SECTION_HEADERS = ("meta", "events", "match", "outcome", "condition")

# Regex patterns for YARA-L parsing
_RULE_NAME_RE = re.compile(r"^rule\s+(\w+)\s*\{", re.MULTILINE)
_META_KV_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_UDM_FIELD_RE = re.compile(
    r"\b(?:src|target|principal|intermediary|observer|about|network|security_result|metadata|extensions)"
    r"(?:\.\w+)+"
)
_REFERENCE_LIST_RE = re.compile(r"%(\w+)")
_MATCH_VAR_RE = re.compile(r"\$(\w+)")
_EVENT_VAR_RE = re.compile(r"\$(\w+)\.\w+")
_FUNCTION_RE = re.compile(r"\b(re\.regex|net\.ip_in_range_cidr|strings\.concat|timestamp\.current_time|math\.\w+|hash\.\w+|arrays\.\w+)\b")


class ChronicleAdapter(BaseAdapter):
    """Adapter for parsing Google Chronicle YARA-L detection rules.

    Supports ``.yaral`` and ``.yar`` rule files containing YARA-L 2.0
    detection logic as used in Google Security Operations (Chronicle).
    """

    def parse_environment(self, path: Path) -> Environment:
        rule_count = len(self._find_rule_files(path))
        platform = Platform(
            name="chronicle",
            vendor="Google",
            adapter_type="chronicle",
        )
        return Environment(
            name=path.name,
            description=f"Chronicle rule set: {path.name} ({rule_count} rules)",
            platforms=[platform],
            metadata={"source_path": str(path)},
        )

    def parse_detections(self, path: Path) -> list[Detection]:
        detections: list[Detection] = []
        for rule_file in self._find_rule_files(path):
            text = self._read_file(rule_file)
            if not text:
                continue
            for rule_text in self._split_rules(text):
                det = self._parse_rule(rule_text, rule_file)
                if det:
                    detections.append(det)
        logger.info(
            "Parsed %d Chronicle detections from %s",
            len(detections), path,
        )
        return detections

    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]:
        # Chronicle reference lists could be knowledge objects, but they
        # live server-side and are not typically in the rule directory.
        return []

    def resolve_dependencies(
        self,
        detections: list[Detection],
        knowledge_objects: list[KnowledgeObject],
    ) -> list[Dependency]:
        all_deps: list[Dependency] = []

        for det in detections:
            # UDM entity / data source dependencies
            for entity in det.metadata.get("udm_entities", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"udm_entity:{entity}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "udm_entity", "value": entity},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

            # Reference list dependencies
            for ref_list in det.metadata.get("reference_lists", []):
                dep = Dependency(
                    kind=DependencyKind.lookup,
                    name=f"reference_list:{ref_list}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "reference_list", "value": ref_list},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

            # UDM field dependencies
            for field in det.metadata.get("udm_fields", []):
                dep = Dependency(
                    kind=DependencyKind.field,
                    name=f"udm_field:{field}",
                    status=DependencyStatus.unknown,
                    metadata={"dep_type": "udm_field", "value": field},
                )
                all_deps.append(dep)
                det.references.append(dep.id)

        return all_deps

    # --- Private helpers ---

    def _parse_rule(
        self, rule_text: str, source_file: Path,
    ) -> Optional[Detection]:
        """Parse a single YARA-L rule block into a Detection."""
        # Extract rule name
        name_match = _RULE_NAME_RE.search(rule_text)
        if not name_match:
            return None
        rule_name = name_match.group(1)

        # Parse sections
        sections = self._parse_sections(rule_text)
        meta = self._parse_meta(sections.get("meta", ""))

        # Severity from meta
        severity_str = meta.get("severity", "medium").lower()
        severity = _SEVERITY_MAP.get(severity_str, DetectionSeverity.medium)

        # Enabled/disabled from meta
        enabled = meta.get("status", "").lower() != "deprecated"

        # Build search query from events + condition
        events_section = sections.get("events", "")
        condition_section = sections.get("condition", "")
        search_query = self._build_search_query(events_section, condition_section)

        # Extract UDM entities (top-level entity types referenced)
        udm_entities = self._extract_udm_entities(events_section)

        # Extract reference lists
        reference_lists = self._extract_reference_lists(rule_text)

        # Extract UDM fields
        udm_fields = self._extract_udm_fields(events_section)

        # Extract MITRE ATT&CK tags from meta
        tags: list[str] = []
        mitre_attack = meta.get("mitre_attack_tactic", "")
        if mitre_attack:
            tags.append(f"attack.{mitre_attack.lower().replace(' ', '_')}")
        mitre_techniques = meta.get("mitre_attack_technique", "")
        if mitre_techniques:
            for tech in mitre_techniques.split(","):
                tech = tech.strip()
                if tech:
                    tags.append(tech)

        # Extract match variables
        match_section = sections.get("match", "")
        match_vars = _MATCH_VAR_RE.findall(match_section)

        # Extract outcome section
        outcome_section = sections.get("outcome", "")

        # Extract functions used
        functions_used = list(set(_FUNCTION_RE.findall(rule_text)))

        return Detection(
            name=rule_name,
            description=meta.get("description"),
            search_query=search_query,
            severity=severity,
            enabled=enabled,
            source_file=str(source_file.name),
            source_app=meta.get("author"),
            tags=tags,
            metadata={
                "rule_name": rule_name,
                "meta": meta,
                "udm_entities": udm_entities,
                "udm_fields": udm_fields,
                "reference_lists": reference_lists,
                "match_variables": match_vars,
                "has_outcome": bool(outcome_section.strip()),
                "functions_used": functions_used,
                "events_section": events_section.strip(),
                "condition_section": condition_section.strip(),
                "match_section": match_section.strip(),
                "outcome_section": outcome_section.strip(),
            },
        )

    @staticmethod
    def _parse_sections(rule_text: str) -> dict[str, str]:
        """Split a YARA-L rule into named sections."""
        sections: dict[str, str] = {}
        # Find the positions of each section header
        positions: list[tuple[str, int]] = []
        for header in _SECTION_HEADERS:
            # Match section header at the start of a line (with optional whitespace)
            pattern = re.compile(rf"^\s*{header}\s*:", re.MULTILINE)
            match = pattern.search(rule_text)
            if match:
                # Start of content is after the header line
                positions.append((header, match.end()))

        # Sort by position
        positions.sort(key=lambda x: x[1])

        # Extract content between sections
        for i, (header, start) in enumerate(positions):
            if i + 1 < len(positions):
                end = positions[i + 1][1] - len(positions[i + 1][0]) - 1
                # Find the actual start of the next section header
                next_header = positions[i + 1][0]
                next_pattern = re.compile(rf"^\s*{next_header}\s*:", re.MULTILINE)
                next_match = next_pattern.search(rule_text)
                if next_match:
                    end = next_match.start()
            else:
                # Last section: go until closing brace
                end = rule_text.rfind("}")
                if end == -1:
                    end = len(rule_text)
            sections[header] = rule_text[start:end]

        return sections

    @staticmethod
    def _parse_meta(meta_text: str) -> dict[str, str]:
        """Parse key-value pairs from a YARA-L meta section."""
        result: dict[str, str] = {}
        for match in _META_KV_RE.finditer(meta_text):
            result[match.group(1)] = match.group(2)
        return result

    @staticmethod
    def _build_search_query(events: str, condition: str) -> str:
        """Combine events and condition into a pseudo search query."""
        parts: list[str] = []
        events_stripped = events.strip()
        if events_stripped:
            parts.append(f"events: {events_stripped}")
        condition_stripped = condition.strip()
        if condition_stripped:
            parts.append(f"condition: {condition_stripped}")
        return " | ".join(parts)

    @staticmethod
    def _extract_udm_entities(events_text: str) -> list[str]:
        """Extract UDM entity types referenced in the events section."""
        entity_types = {
            "src", "target", "principal", "intermediary",
            "observer", "about", "network", "security_result",
            "metadata", "extensions",
        }
        found: list[str] = []
        seen: set[str] = set()
        for field_match in _UDM_FIELD_RE.finditer(events_text):
            entity = field_match.group(0).split(".")[0]
            if entity in entity_types and entity not in seen:
                seen.add(entity)
                found.append(entity)
        return found

    @staticmethod
    def _extract_udm_fields(events_text: str) -> list[str]:
        """Extract all UDM field paths from the events section."""
        fields: list[str] = []
        seen: set[str] = set()
        for match in _UDM_FIELD_RE.finditer(events_text):
            field = match.group(0)
            if field not in seen:
                seen.add(field)
                fields.append(field)
        return fields

    @staticmethod
    def _extract_reference_lists(rule_text: str) -> list[str]:
        """Extract reference list names (prefixed with %) from the rule."""
        lists: list[str] = []
        seen: set[str] = set()
        for match in _REFERENCE_LIST_RE.finditer(rule_text):
            name = match.group(1)
            if name not in seen:
                seen.add(name)
                lists.append(name)
        return lists

    @staticmethod
    def _split_rules(text: str) -> list[str]:
        """Split a file containing one or more YARA-L rules into individual rule blocks."""
        rules: list[str] = []
        depth = 0
        start = -1

        # Find "rule <name> {" patterns and extract balanced-brace blocks
        for match in re.finditer(r"^rule\s+\w+\s*\{", text, re.MULTILINE):
            if depth == 0:
                start = match.start()
            # We need to find the matching closing brace
            pos = match.end()
            depth = 1
            while pos < len(text) and depth > 0:
                if text[pos] == "{":
                    depth += 1
                elif text[pos] == "}":
                    depth -= 1
                pos += 1
            if depth == 0 and start >= 0:
                rules.append(text[start:pos])
                start = -1
                depth = 0

        return rules

    @staticmethod
    def _find_rule_files(path: Path) -> list[Path]:
        """Find all YARA-L rule files in a directory."""
        if path.is_file():
            return [path] if path.suffix in (".yaral", ".yar") else []
        files = list(path.rglob("*.yaral")) + list(path.rglob("*.yar"))
        return sorted(files)

    @staticmethod
    def _read_file(path: Path) -> Optional[str]:
        """Read a file and return its contents, or None on error."""
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to read %s: %s", path, exc)
            return None
