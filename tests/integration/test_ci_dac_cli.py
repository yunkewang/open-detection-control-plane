"""Integration tests for CI/CD and Detection-as-Code CLI commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from odcp.cli.main import app
from odcp.models import (
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_report(path: Path, **overrides) -> Path:
    """Write a scan report JSON file for testing."""
    defaults = dict(
        environment=Environment(
            name="Test",
            platforms=[Platform(name="sigma", vendor="sigma", adapter_type="sigma")],
        ),
        detections=[
            Detection(
                id="det-1", name="Test Detection",
                description="A test rule.", search_query="index=test | stats count",
                tags=["attack.T1059"],
            ),
            Detection(
                id="det-2", name="Blocked Detection",
                description="A blocked rule.", search_query="index=missing",
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1", detection_name="Test Detection",
                status=ReadinessStatus.runnable, score=1.0,
            ),
            ReadinessScore(
                detection_id="det-2", detection_name="Blocked Detection",
                status=ReadinessStatus.blocked, score=0.0,
                total_dependencies=1, missing_dependencies=1,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=2, runnable=1, blocked=1,
            overall_score=0.5,
        ),
    )
    defaults.update(overrides)
    report = ScanReport(**defaults)
    out = path / "report.json"
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# odcp ci
# ---------------------------------------------------------------------------

class TestCiCommand:
    def test_ci_single_passes(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, ["ci", str(report_path)])
        assert result.exit_code == 0
        assert "CI/CD Gate" in result.output or "passed" in result.output.lower()

    def test_ci_single_fails_on_score(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, [
            "ci", str(report_path), "--min-score", "0.8",
        ])
        assert result.exit_code == 1

    def test_ci_single_fails_on_blocked_ratio(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, [
            "ci", str(report_path), "--max-blocked-ratio", "0.3",
        ])
        assert result.exit_code == 1

    def test_ci_baseline_comparison(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        base_dir.mkdir()
        baseline_path = _write_report(base_dir)

        curr_dir = tmp_path / "curr"
        curr_dir.mkdir()
        current_path = _write_report(
            curr_dir,
            readiness_summary=ReadinessSummary(
                total_detections=2, runnable=2, blocked=0, overall_score=1.0,
            ),
            readiness_scores=[
                ReadinessScore(
                    detection_id="det-1", detection_name="Test Detection",
                    status=ReadinessStatus.runnable, score=1.0,
                ),
                ReadinessScore(
                    detection_id="det-2", detection_name="Blocked Detection",
                    status=ReadinessStatus.runnable, score=1.0,
                ),
            ],
        )

        result = runner.invoke(app, [
            "ci", str(current_path),
            "--baseline", str(baseline_path),
            "--allow-regression",
            "--allow-new-blocked",
        ])
        assert result.exit_code == 0

    def test_ci_output_file(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        out = tmp_path / "ci-result.json"
        result = runner.invoke(app, [
            "ci", str(report_path), "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["verdict"] in ("passed", "failed", "warning")

    def test_ci_missing_file(self) -> None:
        result = runner.invoke(app, ["ci", "/nonexistent/report.json"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# odcp validate
# ---------------------------------------------------------------------------

class TestValidateCommand:
    def test_validate_sigma_rules(self, tmp_path: Path) -> None:
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
        result = runner.invoke(app, [
            "validate", str(tmp_path), "--platform", "sigma",
        ])
        assert result.exit_code == 0
        assert "Detection Validation" in result.output

    def test_validate_with_mitre_requirement(self, tmp_path: Path) -> None:
        rule = tmp_path / "rule.yml"
        rule.write_text(
            "title: No MITRE Tags\n"
            "status: test\n"
            "description: A rule without MITRE\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: 'test'\n"
            "  condition: selection\n"
            "level: low\n"
        )
        result = runner.invoke(app, [
            "validate", str(tmp_path),
            "--platform", "sigma",
            "--require-mitre",
            "--fail-on-warnings",
        ])
        # Should fail or warn since no MITRE tags
        assert "require_mitre_tags" in result.output or result.exit_code != 0

    def test_validate_output_file(self, tmp_path: Path) -> None:
        rule = tmp_path / "rule.yml"
        rule.write_text(
            "title: Test\nstatus: test\ndescription: d\n"
            "logsource:\n  category: test\n  product: test\n"
            "detection:\n  selection:\n    field: value\n  condition: selection\n"
            "level: low\n"
        )
        out = tmp_path / "validation.json"
        result = runner.invoke(app, [
            "validate", str(tmp_path),
            "--platform", "sigma",
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "valid" in data

    def test_validate_nonexistent_path(self) -> None:
        result = runner.invoke(app, [
            "validate", "/nonexistent/path",
            "--platform", "sigma",
        ])
        assert result.exit_code == 1

    def test_validate_chronicle_rules(self, tmp_path: Path) -> None:
        rule = tmp_path / "test.yaral"
        rule.write_text(
            'rule test_rule {\n'
            '  meta:\n'
            '    description = "A test YARA-L rule"\n'
            '    severity = "MEDIUM"\n'
            '  events:\n'
            '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
            '  condition:\n'
            '    $e\n'
            '}\n'
        )
        result = runner.invoke(app, [
            "validate", str(tmp_path), "--platform", "chronicle",
        ])
        assert "Detection Validation" in result.output
