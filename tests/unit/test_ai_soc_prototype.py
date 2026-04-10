"""Tests for AI SOC prototype analyzer."""

from odcp.analyzers.ai_soc import AiSocPrototypeAnalyzer
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)


def test_ai_soc_analyzer_flags_data_gaps() -> None:
    detection = Detection(
        id="det-1",
        name="Suspicious PowerShell",
        search_query='index=winsec sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational | stats count',
    )
    readiness = ReadinessScore(
        detection_id="det-1",
        detection_name="Suspicious PowerShell",
        status=ReadinessStatus.blocked,
        score=0.0,
        total_dependencies=1,
        missing_dependencies=1,
    )
    report = ScanReport(
        environment=Environment(
            name="Lab",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=[detection],
        dependencies=[
            Dependency(
                kind=DependencyKind.data_model,
                name="Endpoint.Processes",
                status=DependencyStatus.missing,
            )
        ],
        readiness_scores=[readiness],
        metadata={
            "data_source_inventory": {
                "sources": [
                    {
                        "name": "winsec",
                        "source_type": "index",
                        "observed": True,
                        "detection_count": 1,
                    }
                ]
            }
        },
    )

    summary = AiSocPrototypeAnalyzer().analyze(report)

    assert summary.total_detections == 1
    assert summary.blocked_by_data == 1
    assert summary.detection_decisions[0].decision == "blocked_data_gap"
    assert "sourcetype:XmlWinEventLog:Microsoft-Windows-PowerShell" in (
        summary.detection_decisions[0].missing_data_sources
    )


def test_ai_soc_analyzer_detectable_when_sources_observed() -> None:
    detection = Detection(
        id="det-2",
        name="Brute Force",
        search_query="index=auth sourcetype=linux_secure | stats count by user",
    )
    readiness = ReadinessScore(
        detection_id="det-2",
        detection_name="Brute Force",
        status=ReadinessStatus.runnable,
        score=1.0,
    )
    report = ScanReport(
        environment=Environment(
            name="Prod",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=[detection],
        readiness_scores=[readiness],
        metadata={
            "data_source_inventory": {
                "sources": [
                    {"name": "auth", "source_type": "index", "observed": True},
                    {
                        "name": "linux_secure",
                        "source_type": "sourcetype",
                        "observed": True,
                    },
                ]
            }
        },
    )

    summary = AiSocPrototypeAnalyzer().analyze(report)

    assert summary.detectable_now == 1
    assert summary.blocked_by_data == 0
    assert summary.detection_decisions[0].decision == "detectable"
