"""Integration tests for AI SOC CLI commands."""

import json
from pathlib import Path

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


def _write_report(path: Path, **overrides) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    defaults = dict(
        environment=Environment(
            name="Test",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(
                id="det-1", name="Brute Force",
                description="Detect brute force.",
                search_query="index=auth sourcetype=linux_secure | stats count by user",
            ),
            Detection(
                id="det-2", name="Blocked Rule",
                description="A blocked rule.",
                search_query="index=missing | stats count",
                enabled=True,
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1", detection_name="Brute Force",
                status=ReadinessStatus.runnable, score=1.0,
            ),
            ReadinessScore(
                detection_id="det-2", detection_name="Blocked Rule",
                status=ReadinessStatus.blocked, score=0.0,
                total_dependencies=1, missing_dependencies=1,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=2, runnable=1, blocked=1, overall_score=0.5,
        ),
    )
    defaults.update(overrides)
    report = ScanReport(**defaults)
    out = path / "report.json"
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return out


class TestSocInventoryCmd:
    def test_inventory_prints_catalog(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, ["ai-soc", "inventory", str(report_path)])
        assert result.exit_code == 0
        assert "Source Catalog" in result.output

    def test_inventory_output_file(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        out = tmp_path / "catalog.json"
        result = runner.invoke(app, ["ai-soc", "inventory", str(report_path), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "sources" in data
        assert "total_sources" in data

    def test_inventory_missing_file(self) -> None:
        result = runner.invoke(app, ["ai-soc", "inventory", "/nonexistent.json"])
        assert result.exit_code == 1


class TestSocDriftCmd:
    def test_drift_prints_summary(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        curr_dir = tmp_path / "curr"
        base_path = _write_report(base_dir)
        curr_path = _write_report(
            curr_dir,
            detections=[
                Detection(id="det-1", name="Brute Force", description="d",
                          search_query="index=auth sourcetype=linux_secure | stats count by user"),
                Detection(id="det-2", name="Blocked Rule", description="d",
                          search_query="index=missing | stats count"),
                Detection(id="det-3", name="New Rule", description="d",
                          search_query="index=winsec | stats count"),
            ],
        )
        result = runner.invoke(app, ["ai-soc", "drift", str(base_path), str(curr_path)])
        assert result.exit_code == 0
        assert "Drift" in result.output

    def test_drift_output_file(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        curr_dir = tmp_path / "curr"
        base_path = _write_report(base_dir)
        curr_path = _write_report(curr_dir)
        out = tmp_path / "drift.json"
        result = runner.invoke(app, [
            "ai-soc", "drift", str(base_path), str(curr_path), "-o", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "total_drift_events" in data


class TestSocFeedbackCmd:
    def test_feedback_prints_summary(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, ["ai-soc", "feedback", str(report_path)])
        assert result.exit_code == 0
        assert "Feedback" in result.output

    def test_feedback_output_file(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        out = tmp_path / "feedback.json"
        result = runner.invoke(app, ["ai-soc", "feedback", str(report_path), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "proposals" in data


class TestSocCycleCmd:
    def test_cycle_prints_result(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        result = runner.invoke(app, ["ai-soc", "cycle", str(report_path)])
        assert result.exit_code == 0
        assert "AI SOC Cycle" in result.output
        assert "Priority Actions" in result.output

    def test_cycle_with_baseline(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        curr_dir = tmp_path / "curr"
        base_path = _write_report(base_dir)
        curr_path = _write_report(curr_dir)
        result = runner.invoke(app, [
            "ai-soc", "cycle", str(curr_path), "--baseline", str(base_path),
        ])
        assert result.exit_code == 0
        assert "Drift" in result.output

    def test_cycle_output_file(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path)
        out = tmp_path / "cycle.json"
        result = runner.invoke(app, [
            "ai-soc", "cycle", str(report_path), "-o", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "priority_actions" in data
        assert "readiness_score" in data

    def test_cycle_missing_file(self) -> None:
        result = runner.invoke(app, ["ai-soc", "cycle", "/nonexistent.json"])
        assert result.exit_code == 1
