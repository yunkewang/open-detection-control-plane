"""JSON report generation."""

from __future__ import annotations

from pathlib import Path

from odcp.models import ScanReport


def generate_json_report(report: ScanReport) -> str:
    """Serialize a scan report to JSON."""
    return report.model_dump_json(indent=2)


def write_json_report(report: ScanReport, path: Path) -> None:
    """Write a scan report as JSON to a file."""
    path.write_text(generate_json_report(report), encoding="utf-8")
