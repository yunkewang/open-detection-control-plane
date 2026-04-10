"""Detection-as-Code (DaC) validation analyzer.

Validates detection rule files for structural correctness, naming
conventions, lifecycle state consistency, and required metadata.
Designed for pre-commit hooks and PR checks.
"""

from __future__ import annotations

import logging
import os
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from odcp.models.detection import Detection
from odcp.models.report import ScanReport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ValidationSeverity(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"


class ValidationIssue(BaseModel):
    """A single validation issue found in a detection file."""

    file: str
    rule: str
    severity: ValidationSeverity
    message: str
    line: int | None = None
    detection_id: str | None = None


class LifecycleState(str, Enum):
    """Detection lifecycle states for DaC workflows."""

    draft = "draft"
    review = "review"
    testing = "testing"
    production = "production"
    deprecated = "deprecated"
    disabled = "disabled"


class ValidationResult(BaseModel):
    """Complete result of a DaC validation run."""

    valid: bool = True
    total_files: int = 0
    total_detections: int = 0
    issues: list[ValidationIssue] = Field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    lifecycle_summary: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Configurable validation policy
# ---------------------------------------------------------------------------


class DacPolicy(BaseModel):
    """Configurable policy for Detection-as-Code validation."""

    require_description: bool = True
    require_severity: bool = True
    require_mitre_tags: bool = False
    require_source_file: bool = False
    allowed_severities: list[str] = Field(
        default_factory=lambda: ["critical", "high", "medium", "low", "informational"]
    )
    naming_pattern: str | None = None  # regex pattern for detection names
    max_query_length: int = 0  # 0 = no limit
    require_enabled_state: bool = False
    allowed_lifecycle_states: list[str] = Field(default_factory=list)
    fail_on_warnings: bool = False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

_MITRE_TAG_RE = re.compile(r"(?:attack\.)?[tT]\d{4}(?:\.\d{3})?")


class DacValidator:
    """Validate detection rules against Detection-as-Code policies."""

    def __init__(self, policy: DacPolicy | None = None) -> None:
        self.policy = policy or DacPolicy()

    def validate_report(self, report: ScanReport) -> ValidationResult:
        """Validate all detections in a scan report."""
        issues: list[ValidationIssue] = []
        lifecycle_counts: dict[str, int] = {}

        for det in report.detections:
            det_issues = self._validate_detection(det)
            issues.extend(det_issues)

            # Track lifecycle state
            state = det.metadata.get("lifecycle_state", "unknown")
            lifecycle_counts[state] = lifecycle_counts.get(state, 0) + 1

        error_count = sum(1 for i in issues if i.severity == ValidationSeverity.error)
        warning_count = sum(1 for i in issues if i.severity == ValidationSeverity.warning)

        if self.policy.fail_on_warnings:
            valid = error_count == 0 and warning_count == 0
        else:
            valid = error_count == 0

        # Gather unique source files
        source_files: set[str] = set()
        for det in report.detections:
            if det.source_file:
                source_files.add(det.source_file)

        return ValidationResult(
            valid=valid,
            total_files=len(source_files),
            total_detections=len(report.detections),
            issues=issues,
            errors=error_count,
            warnings=warning_count,
            lifecycle_summary=lifecycle_counts,
        )

    def validate_files(self, path: Path, platform: str) -> ValidationResult:
        """Scan and validate detection files at the given path."""
        from odcp.core.engine import ScanEngine

        adapter = self._get_adapter(platform)
        if adapter is None:
            return ValidationResult(
                valid=False,
                issues=[ValidationIssue(
                    file=str(path),
                    rule="unsupported_platform",
                    severity=ValidationSeverity.error,
                    message=f"Unsupported platform: {platform}",
                )],
                errors=1,
            )

        engine = ScanEngine(adapter)
        report = engine.scan(path)

        result = self.validate_report(report)

        # Additional file-level checks
        file_issues = self._validate_file_structure(path, platform)
        result.issues.extend(file_issues)
        file_errors = sum(1 for i in file_issues if i.severity == ValidationSeverity.error)
        file_warnings = sum(1 for i in file_issues if i.severity == ValidationSeverity.warning)
        result.errors += file_errors
        result.warnings += file_warnings
        if file_errors > 0:
            result.valid = False

        return result

    def _validate_detection(self, det: Detection) -> list[ValidationIssue]:
        """Validate a single detection against the policy."""
        issues: list[ValidationIssue] = []
        source = det.source_file or "unknown"

        # Required description
        if self.policy.require_description and not det.description:
            issues.append(ValidationIssue(
                file=source,
                rule="require_description",
                severity=ValidationSeverity.error,
                message=f"Detection '{det.name}' is missing a description",
                detection_id=det.id,
            ))

        # Required severity
        if self.policy.require_severity and det.severity.value not in self.policy.allowed_severities:
            issues.append(ValidationIssue(
                file=source,
                rule="allowed_severities",
                severity=ValidationSeverity.error,
                message=(
                    f"Detection '{det.name}' has severity '{det.severity.value}' "
                    f"which is not in allowed list: {self.policy.allowed_severities}"
                ),
                detection_id=det.id,
            ))

        # MITRE tag requirement
        if self.policy.require_mitre_tags:
            has_mitre = any(_MITRE_TAG_RE.search(tag) for tag in det.tags)
            if not has_mitre:
                issues.append(ValidationIssue(
                    file=source,
                    rule="require_mitre_tags",
                    severity=ValidationSeverity.warning,
                    message=f"Detection '{det.name}' has no MITRE ATT&CK technique tags",
                    detection_id=det.id,
                ))

        # Naming convention
        if self.policy.naming_pattern:
            if not re.match(self.policy.naming_pattern, det.name):
                issues.append(ValidationIssue(
                    file=source,
                    rule="naming_pattern",
                    severity=ValidationSeverity.warning,
                    message=(
                        f"Detection name '{det.name}' does not match "
                        f"pattern '{self.policy.naming_pattern}'"
                    ),
                    detection_id=det.id,
                ))

        # Query length
        if self.policy.max_query_length > 0 and len(det.search_query) > self.policy.max_query_length:
            issues.append(ValidationIssue(
                file=source,
                rule="max_query_length",
                severity=ValidationSeverity.warning,
                message=(
                    f"Detection '{det.name}' query is {len(det.search_query)} chars, "
                    f"exceeding limit of {self.policy.max_query_length}"
                ),
                detection_id=det.id,
            ))

        # Empty query
        if not det.search_query.strip():
            issues.append(ValidationIssue(
                file=source,
                rule="empty_query",
                severity=ValidationSeverity.error,
                message=f"Detection '{det.name}' has an empty search query",
                detection_id=det.id,
            ))

        # Enabled state
        if self.policy.require_enabled_state and not det.enabled:
            issues.append(ValidationIssue(
                file=source,
                rule="require_enabled",
                severity=ValidationSeverity.warning,
                message=f"Detection '{det.name}' is disabled",
                detection_id=det.id,
            ))

        # Lifecycle state
        if self.policy.allowed_lifecycle_states:
            state = det.metadata.get("lifecycle_state", "unknown")
            if state not in self.policy.allowed_lifecycle_states:
                issues.append(ValidationIssue(
                    file=source,
                    rule="allowed_lifecycle_states",
                    severity=ValidationSeverity.error,
                    message=(
                        f"Detection '{det.name}' has lifecycle state '{state}' "
                        f"which is not allowed for this branch"
                    ),
                    detection_id=det.id,
                ))

        return issues

    def _validate_file_structure(self, path: Path, platform: str) -> list[ValidationIssue]:
        """Validate directory structure and file naming conventions."""
        issues: list[ValidationIssue] = []
        ext_map = {
            "sigma": {".yml", ".yaml"},
            "elastic": {".json"},
            "sentinel": {".yml", ".yaml", ".json"},
            "chronicle": {".yaral", ".yar"},
            "splunk": {".conf"},
        }
        expected_exts = ext_map.get(platform, set())
        if not expected_exts:
            return issues

        if path.is_file():
            files = [path]
        else:
            files = sorted(path.rglob("*"))

        for fp in files:
            if fp.is_dir():
                continue
            if fp.suffix not in expected_exts and not fp.name.startswith("."):
                # Skip common non-detection files
                if fp.name in ("README.md", "LICENSE", ".gitignore", "__init__.py"):
                    continue
                issues.append(ValidationIssue(
                    file=str(fp),
                    rule="file_extension",
                    severity=ValidationSeverity.info,
                    message=(
                        f"Unexpected file extension '{fp.suffix}' for "
                        f"{platform} rules (expected {expected_exts})"
                    ),
                ))

        return issues

    @staticmethod
    def _get_adapter(platform: str):
        """Dynamically load the adapter for the given platform."""
        try:
            if platform == "splunk":
                from odcp.adapters.splunk import SplunkAdapter
                return SplunkAdapter()
            elif platform == "sigma":
                from odcp.adapters.sigma import SigmaAdapter
                return SigmaAdapter()
            elif platform == "elastic":
                from odcp.adapters.elastic import ElasticAdapter
                return ElasticAdapter()
            elif platform == "sentinel":
                from odcp.adapters.sentinel import SentinelAdapter
                return SentinelAdapter()
            elif platform == "chronicle":
                from odcp.adapters.chronicle import ChronicleAdapter
                return ChronicleAdapter()
        except ImportError:
            pass
        return None
