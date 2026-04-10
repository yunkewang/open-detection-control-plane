"""Tests for Detection-as-Code validator."""

import pytest
from pathlib import Path

from odcp.analyzers.dac import (
    DacPolicy,
    DacValidator,
    LifecycleState,
    ValidationResult,
    ValidationSeverity,
)
from odcp.models import (
    Detection,
    DetectionSeverity,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(detections: list[Detection] | None = None) -> ScanReport:
    dets = detections or [
        Detection(
            id="det-1",
            name="Test Detection",
            description="A test detection rule.",
            search_query="index=test | stats count",
            severity=DetectionSeverity.medium,
            source_file="rules/test.yml",
            tags=["attack.T1059"],
        )
    ]
    return ScanReport(
        environment=Environment(
            name="Test",
            platforms=[Platform(name="sigma", vendor="sigma", adapter_type="sigma")],
        ),
        detections=dets,
        readiness_scores=[
            ReadinessScore(
                detection_id=d.id,
                detection_name=d.name,
                status=ReadinessStatus.runnable,
                score=1.0,
            )
            for d in dets
        ],
        readiness_summary=ReadinessSummary(
            total_detections=len(dets),
            runnable=len(dets),
            overall_score=1.0,
        ),
    )


# ---------------------------------------------------------------------------
# Basic validation
# ---------------------------------------------------------------------------

class TestBasicValidation:
    def test_valid_detection_passes(self) -> None:
        report = _make_report()
        result = DacValidator().validate_report(report)
        assert result.valid is True
        assert result.errors == 0

    def test_missing_description_fails(self) -> None:
        det = Detection(
            id="det-1", name="No Description", search_query="index=test",
            description=None,
        )
        report = _make_report([det])
        result = DacValidator().validate_report(report)
        assert result.valid is False
        assert result.errors >= 1
        assert any(i.rule == "require_description" for i in result.issues)

    def test_empty_description_fails(self) -> None:
        det = Detection(
            id="det-1", name="Empty Description", search_query="index=test",
            description="",
        )
        report = _make_report([det])
        result = DacValidator().validate_report(report)
        assert result.valid is False
        assert any(i.rule == "require_description" for i in result.issues)

    def test_description_not_required(self) -> None:
        det = Detection(
            id="det-1", name="No Description", search_query="index=test",
        )
        report = _make_report([det])
        policy = DacPolicy(require_description=False)
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "require_description" for i in result.issues)

    def test_empty_query_fails(self) -> None:
        det = Detection(
            id="det-1", name="Empty Query", description="desc",
            search_query="",
        )
        report = _make_report([det])
        result = DacValidator().validate_report(report)
        assert result.valid is False
        assert any(i.rule == "empty_query" for i in result.issues)

    def test_whitespace_only_query_fails(self) -> None:
        det = Detection(
            id="det-1", name="Whitespace Query", description="desc",
            search_query="   ",
        )
        report = _make_report([det])
        result = DacValidator().validate_report(report)
        assert any(i.rule == "empty_query" for i in result.issues)


# ---------------------------------------------------------------------------
# MITRE tag requirements
# ---------------------------------------------------------------------------

class TestMitreRequirement:
    def test_mitre_tags_required_and_present(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", tags=["attack.T1059.001"],
        )
        report = _make_report([det])
        policy = DacPolicy(require_mitre_tags=True)
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "require_mitre_tags" for i in result.issues)

    def test_mitre_tags_required_but_missing(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", tags=["windows", "powershell"],
        )
        report = _make_report([det])
        policy = DacPolicy(require_mitre_tags=True)
        result = DacValidator(policy).validate_report(report)
        assert any(i.rule == "require_mitre_tags" for i in result.issues)

    def test_mitre_tags_not_required(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", tags=[],
        )
        report = _make_report([det])
        policy = DacPolicy(require_mitre_tags=False)
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "require_mitre_tags" for i in result.issues)


# ---------------------------------------------------------------------------
# Naming pattern
# ---------------------------------------------------------------------------

class TestNamingPattern:
    def test_naming_pattern_matches(self) -> None:
        det = Detection(
            id="det-1", name="win_process_creation_suspicious_cmd",
            description="desc", search_query="index=test",
        )
        report = _make_report([det])
        policy = DacPolicy(naming_pattern=r"^[a-z][a-z0-9_]+$")
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "naming_pattern" for i in result.issues)

    def test_naming_pattern_violation(self) -> None:
        det = Detection(
            id="det-1", name="My Bad Name!",
            description="desc", search_query="index=test",
        )
        report = _make_report([det])
        policy = DacPolicy(naming_pattern=r"^[a-z][a-z0-9_]+$")
        result = DacValidator(policy).validate_report(report)
        assert any(i.rule == "naming_pattern" for i in result.issues)


# ---------------------------------------------------------------------------
# Query length
# ---------------------------------------------------------------------------

class TestQueryLength:
    def test_query_within_limit(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test | stats count",
        )
        report = _make_report([det])
        policy = DacPolicy(max_query_length=1000)
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "max_query_length" for i in result.issues)

    def test_query_exceeds_limit(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="x" * 200,
        )
        report = _make_report([det])
        policy = DacPolicy(max_query_length=100)
        result = DacValidator(policy).validate_report(report)
        assert any(i.rule == "max_query_length" for i in result.issues)

    def test_query_limit_zero_means_unlimited(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="x" * 50000,
        )
        report = _make_report([det])
        policy = DacPolicy(max_query_length=0)
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "max_query_length" for i in result.issues)


# ---------------------------------------------------------------------------
# Lifecycle states
# ---------------------------------------------------------------------------

class TestLifecycleStates:
    def test_allowed_lifecycle_passes(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test",
            metadata={"lifecycle_state": "production"},
        )
        report = _make_report([det])
        policy = DacPolicy(allowed_lifecycle_states=["production", "testing"])
        result = DacValidator(policy).validate_report(report)
        assert not any(i.rule == "allowed_lifecycle_states" for i in result.issues)

    def test_disallowed_lifecycle_fails(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test",
            metadata={"lifecycle_state": "draft"},
        )
        report = _make_report([det])
        policy = DacPolicy(allowed_lifecycle_states=["production", "testing"])
        result = DacValidator(policy).validate_report(report)
        assert any(i.rule == "allowed_lifecycle_states" for i in result.issues)
        assert result.valid is False

    def test_lifecycle_summary_tracked(self) -> None:
        dets = [
            Detection(
                id="det-1", name="Prod", description="d", search_query="q",
                metadata={"lifecycle_state": "production"},
            ),
            Detection(
                id="det-2", name="Draft", description="d", search_query="q",
                metadata={"lifecycle_state": "draft"},
            ),
            Detection(
                id="det-3", name="Draft2", description="d", search_query="q",
                metadata={"lifecycle_state": "draft"},
            ),
        ]
        report = _make_report(dets)
        result = DacValidator().validate_report(report)
        assert result.lifecycle_summary["production"] == 1
        assert result.lifecycle_summary["draft"] == 2


# ---------------------------------------------------------------------------
# Enabled state
# ---------------------------------------------------------------------------

class TestEnabledState:
    def test_disabled_detection_warning(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", enabled=False,
        )
        report = _make_report([det])
        policy = DacPolicy(require_enabled_state=True)
        result = DacValidator(policy).validate_report(report)
        assert any(i.rule == "require_enabled" for i in result.issues)


# ---------------------------------------------------------------------------
# Fail on warnings
# ---------------------------------------------------------------------------

class TestFailOnWarnings:
    def test_warnings_dont_fail_by_default(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", enabled=False,
        )
        report = _make_report([det])
        policy = DacPolicy(require_enabled_state=True, fail_on_warnings=False)
        result = DacValidator(policy).validate_report(report)
        assert result.valid is True  # warnings only

    def test_warnings_fail_when_policy_set(self) -> None:
        det = Detection(
            id="det-1", name="Test", description="desc",
            search_query="index=test", enabled=False,
        )
        report = _make_report([det])
        policy = DacPolicy(require_enabled_state=True, fail_on_warnings=True)
        result = DacValidator(policy).validate_report(report)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Multiple detections
# ---------------------------------------------------------------------------

class TestMultipleDetections:
    def test_counts_across_detections(self) -> None:
        dets = [
            Detection(id="d1", name="Good", description="desc", search_query="q"),
            Detection(id="d2", name="No desc", search_query="q"),
            Detection(id="d3", name="Empty q", description="desc", search_query=""),
        ]
        report = _make_report(dets)
        result = DacValidator().validate_report(report)
        assert result.total_detections == 3
        assert result.errors == 2  # missing desc + empty query
        assert result.valid is False


# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------

class TestFileValidation:
    def test_validate_sigma_files(self, tmp_path: Path) -> None:
        rule = tmp_path / "rule.yml"
        rule.write_text(
            "title: Test Rule\n"
            "status: test\n"
            "description: A test rule\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: 'suspicious'\n"
            "  condition: selection\n"
            "level: medium\n"
        )
        result = DacValidator().validate_files(tmp_path, "sigma")
        assert result.total_detections >= 1
        assert isinstance(result.valid, bool)

    def test_unsupported_platform(self, tmp_path: Path) -> None:
        result = DacValidator().validate_files(tmp_path, "unknown_platform")
        assert result.valid is False
        assert any(i.rule == "unsupported_platform" for i in result.issues)

    def test_file_structure_info_for_wrong_extension(self, tmp_path: Path) -> None:
        (tmp_path / "bad.txt").write_text("not a rule")
        (tmp_path / "good.yml").write_text(
            "title: Test\nstatus: test\ndescription: d\n"
            "logsource:\n  category: test\n  product: test\n"
            "detection:\n  selection:\n    field: value\n  condition: selection\n"
            "level: low\n"
        )
        result = DacValidator().validate_files(tmp_path, "sigma")
        file_ext_issues = [i for i in result.issues if i.rule == "file_extension"]
        assert len(file_ext_issues) >= 1
