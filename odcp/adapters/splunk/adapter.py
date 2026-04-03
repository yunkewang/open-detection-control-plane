"""Splunk adapter — translates Splunk artifacts into the ODCP model."""

from __future__ import annotations

import logging
from pathlib import Path

from odcp.adapters import BaseAdapter
from odcp.adapters.splunk.parser import merge_stanzas, parse_conf_file
from odcp.adapters.splunk.spl_extractor import extract_all_references
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
    "1": DetectionSeverity.informational,
    "2": DetectionSeverity.low,
    "3": DetectionSeverity.medium,
    "4": DetectionSeverity.high,
    "5": DetectionSeverity.critical,
    "6": DetectionSeverity.critical,
}

_REF_KIND_MAP: dict[str, DependencyKind] = {
    "macro": DependencyKind.macro,
    "eventtype": DependencyKind.eventtype,
    "lookup": DependencyKind.lookup,
    "data_model": DependencyKind.data_model,
    "saved_search": DependencyKind.saved_search,
}


class SplunkAdapter(BaseAdapter):
    """Adapter for parsing Splunk app/TA bundles on disk."""

    def parse_environment(self, path: Path) -> Environment:
        app_name = self._detect_app_name(path) or path.name
        platform = Platform(
            name="splunk",
            vendor="Splunk",
            adapter_type="splunk",
        )
        return Environment(
            name=app_name,
            description=f"Splunk app: {app_name}",
            platforms=[platform],
            metadata={"source_path": str(path)},
        )

    def parse_detections(self, path: Path) -> list[Detection]:
        stanzas = self._load_conf(path, "savedsearches.conf")
        if not stanzas:
            logger.info("No savedsearches.conf found in %s", path)
            return []

        detections: list[Detection] = []
        for name, attrs in stanzas.items():
            search = attrs.get("search", "").strip()
            if not search:
                continue

            # Determine if this is a detection/alert vs a simple report
            is_detection = self._is_detection(attrs)

            severity = _SEVERITY_MAP.get(
                attrs.get("alert.severity", "3"),
                DetectionSeverity.medium,
            )
            enabled = attrs.get("disabled", "0") != "1"
            description = attrs.get("description", None)

            det = Detection(
                name=name,
                search_query=search,
                severity=severity,
                enabled=enabled,
                description=description,
                source_file="savedsearches.conf",
                source_app=self._detect_app_name(path),
                metadata={k: v for k, v in attrs.items() if k.startswith("action.")},
            )

            if is_detection:
                detections.append(det)

        # If no obvious detections found, include all saved searches with a search key
        if not detections:
            logger.info("No alert-type detections found; including all saved searches")
            for name, attrs in stanzas.items():
                search = attrs.get("search", "").strip()
                if search:
                    detections.append(
                        Detection(
                            name=name,
                            search_query=search,
                            source_file="savedsearches.conf",
                            source_app=self._detect_app_name(path),
                        )
                    )

        return detections

    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]:
        objects: list[KnowledgeObject] = []

        # Macros
        for name, attrs in self._load_conf(path, "macros.conf").items():
            objects.append(
                KnowledgeObject(
                    kind=DependencyKind.macro,
                    name=name,
                    definition=attrs.get("definition"),
                    source_file="macros.conf",
                )
            )

        # Eventtypes
        for name, attrs in self._load_conf(path, "eventtypes.conf").items():
            objects.append(
                KnowledgeObject(
                    kind=DependencyKind.eventtype,
                    name=name,
                    definition=attrs.get("search"),
                    source_file="eventtypes.conf",
                )
            )

        # Transforms (lookups, field extractions)
        for name, attrs in self._load_conf(path, "transforms.conf").items():
            obj = KnowledgeObject(
                kind=DependencyKind.transform,
                name=name,
                source_file="transforms.conf",
                metadata={},
            )
            if "filename" in attrs:
                obj.kind = DependencyKind.lookup
                obj.definition = attrs["filename"]
            elif "external_type" in attrs:
                obj.kind = DependencyKind.lookup
                obj.definition = attrs.get("external_cmd", attrs.get("external_type"))
            else:
                obj.definition = attrs.get("REGEX", attrs.get("REPORT", ""))
            objects.append(obj)

        return objects

    def resolve_dependencies(
        self,
        detections: list[Detection],
        knowledge_objects: list[KnowledgeObject],
    ) -> list[Dependency]:
        # Index knowledge objects by (kind, name)
        ko_index: dict[tuple[DependencyKind, str], KnowledgeObject] = {}
        for ko in knowledge_objects:
            ko_index[(ko.kind, ko.name)] = ko

        all_deps: list[Dependency] = []

        for det in detections:
            refs = extract_all_references(det.search_query)

            for ref_type, ref_names in refs.items():
                kind = _REF_KIND_MAP.get(ref_type, DependencyKind.unknown)

                for ref_name in ref_names:
                    # Check if resolved
                    ko = ko_index.get((kind, ref_name))
                    status = DependencyStatus.resolved if ko else DependencyStatus.missing

                    dep = Dependency(
                        kind=kind,
                        name=ref_name,
                        status=status,
                        source_detection=det.id,
                        definition=ko.definition if ko else None,
                    )
                    all_deps.append(dep)
                    det.references.append(dep.id)

        return all_deps

    # --- Private helpers ---

    @staticmethod
    def _is_detection(attrs: dict[str, str]) -> bool:
        """Heuristic: is this saved search a detection/alert?"""
        # Has alert actions configured
        if any(
            attrs.get(k, "0") not in ("0", "")
            for k in (
                "alert.severity",
                "alert.suppress",
                "action.email",
                "action.notable",
                "action.risk",
                "action.escu",
                "actions",
            )
        ):
            return True
        # Has scheduling configured (likely a correlation)
        if attrs.get("cron_schedule") and attrs.get("dispatch.earliest_time"):
            return True
        # Has alert threshold
        if attrs.get("alert_type") or attrs.get("alert.digest_mode"):
            return True
        return False

    @staticmethod
    def _detect_app_name(path: Path) -> str | None:
        """Try to detect the app name from app.conf."""
        for subdir in ("default", "local", "metadata"):
            app_conf = path / subdir / "app.conf"
            if app_conf.exists():
                stanzas = parse_conf_file(app_conf)
                label = stanzas.get("ui", {}).get("label")
                if label:
                    return label
                launcher_desc = stanzas.get("launcher", {}).get("description")
                if launcher_desc:
                    return launcher_desc
        return None

    @staticmethod
    def _load_conf(path: Path, filename: str) -> dict[str, dict[str, str]]:
        """Load and merge a conf file from default/ and local/."""
        default_path = path / "default" / filename
        local_path = path / "local" / filename

        default_stanzas = parse_conf_file(default_path) if default_path.exists() else {}
        local_stanzas = parse_conf_file(local_path) if local_path.exists() else {}

        if default_stanzas or local_stanzas:
            return merge_stanzas(default_stanzas, local_stanzas)
        return {}
