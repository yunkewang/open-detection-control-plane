"""Tests for unified source inventory builder."""

from odcp.analyzers.ai_soc.source_inventory import SourceInventoryBuilder
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
from odcp.models.report import ReadinessSummary


def _splunk_report(**kwargs) -> ScanReport:
    defaults = dict(
        environment=Environment(
            name="Splunk Lab",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(
                id="det-1", name="Brute Force",
                search_query="index=auth sourcetype=linux_secure | stats count by user",
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1", detection_name="Brute Force",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=1, runnable=1, overall_score=1.0,
        ),
    )
    defaults.update(kwargs)
    return ScanReport(**defaults)


def _sigma_report() -> ScanReport:
    return ScanReport(
        environment=Environment(
            name="Sigma Rules",
            platforms=[Platform(name="sigma", vendor="sigma", adapter_type="sigma")],
        ),
        detections=[
            Detection(
                id="sig-1", name="Suspicious Process",
                search_query="CommandLine|contains: 'powershell'",
                metadata={"logsource": {"category": "process_creation", "product": "windows"}},
                tags=["attack.T1059"],
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="sig-1", detection_name="Suspicious Process",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=1, runnable=1, overall_score=1.0,
        ),
    )


def _chronicle_report() -> ScanReport:
    return ScanReport(
        environment=Environment(
            name="Chronicle Rules",
            platforms=[Platform(name="chronicle", vendor="google", adapter_type="chronicle")],
        ),
        detections=[
            Detection(
                id="chr-1", name="DNS Exfil",
                search_query='$e.network.dns.questions.name',
                metadata={
                    "udm_entities": ["network", "src"],
                    "reference_lists": ["known_bad_domains"],
                },
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="chr-1", detection_name="DNS Exfil",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=1, runnable=1, overall_score=1.0,
        ),
    )


class TestSourceInventoryBuilder:
    def test_splunk_extracts_index_and_sourcetype(self) -> None:
        report = _splunk_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "auth" in names
        assert "linux_secure" in names

    def test_splunk_source_types(self) -> None:
        report = _splunk_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        type_map = {s.name: s.source_type for s in catalog.sources}
        assert type_map.get("auth") == "index"
        assert type_map.get("linux_secure") == "sourcetype"

    def test_sigma_extracts_logsource(self) -> None:
        report = _sigma_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "process_creation" in names
        assert "windows" in names

    def test_chronicle_extracts_udm_and_reflist(self) -> None:
        report = _chronicle_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "network" in names
        assert "src" in names
        assert "known_bad_domains" in names

    def test_chronicle_reference_list_type(self) -> None:
        report = _chronicle_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        rl = next(s for s in catalog.sources if s.name == "known_bad_domains")
        assert rl.source_type == "reference_list"

    def test_attack_data_source_enrichment(self) -> None:
        report = _splunk_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        auth_src = next((s for s in catalog.sources if s.name == "auth"), None)
        # "auth" should match Authentication Logs
        assert auth_src is not None
        assert len(auth_src.attack_data_sources) > 0

    def test_field_enrichment(self) -> None:
        report = _sigma_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        proc_src = next((s for s in catalog.sources if s.name == "process_creation"), None)
        assert proc_src is not None
        field_names = {f.name for f in proc_src.fields}
        assert "process.name" in field_names
        assert "process.command_line" in field_names

    def test_multi_platform_catalog(self) -> None:
        reports = [_splunk_report(), _sigma_report(), _chronicle_report()]
        catalog = SourceInventoryBuilder().build_catalog(reports)
        assert len(catalog.platforms_represented) == 3
        assert "splunk" in catalog.platforms_represented
        assert "sigma" in catalog.platforms_represented
        assert "chronicle" in catalog.platforms_represented
        assert catalog.total_sources >= 5

    def test_dedup_same_sources(self) -> None:
        report = _splunk_report(
            detections=[
                Detection(id="d1", name="D1", search_query="index=auth | stats count"),
                Detection(id="d2", name="D2", search_query="index=auth | table user"),
            ],
        )
        catalog = SourceInventoryBuilder().build_from_single(report)
        auth_sources = [s for s in catalog.sources if s.name == "auth"]
        assert len(auth_sources) == 1

    def test_from_inventory_metadata(self) -> None:
        report = _splunk_report(
            metadata={
                "data_source_inventory": {
                    "sources": [
                        {"name": "winsec", "source_type": "index", "observed": True, "detection_count": 3},
                        {"name": "sysmon", "source_type": "sourcetype", "observed": False, "detection_count": 1},
                    ]
                }
            },
        )
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "winsec" in names
        assert "sysmon" in names

    def test_elastic_index_patterns(self) -> None:
        report = ScanReport(
            environment=Environment(
                name="Elastic",
                platforms=[Platform(name="elastic", vendor="elastic", adapter_type="elastic")],
            ),
            detections=[
                Detection(
                    id="el-1", name="Elastic Rule",
                    search_query="process.name: cmd.exe",
                    metadata={"index_patterns": ["logs-endpoint*", "winlogbeat-*"]},
                ),
            ],
            readiness_summary=ReadinessSummary(total_detections=1, runnable=1, overall_score=1.0),
        )
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "logs-endpoint*" in names
        assert "winlogbeat-*" in names

    def test_sentinel_connectors(self) -> None:
        report = ScanReport(
            environment=Environment(
                name="Sentinel",
                platforms=[Platform(name="sentinel", vendor="microsoft", adapter_type="sentinel")],
            ),
            detections=[
                Detection(
                    id="sen-1", name="Sentinel Rule",
                    search_query="SecurityEvent | where EventID == 4625",
                    metadata={"data_connectors": ["SecurityEvents", "AzureActiveDirectory"]},
                ),
            ],
            readiness_summary=ReadinessSummary(total_detections=1, runnable=1, overall_score=1.0),
        )
        catalog = SourceInventoryBuilder().build_from_single(report)
        names = {s.name for s in catalog.sources}
        assert "SecurityEvents" in names
        assert "AzureActiveDirectory" in names

    def test_catalog_aggregates(self) -> None:
        report = _splunk_report()
        catalog = SourceInventoryBuilder().build_from_single(report)
        assert catalog.total_sources > 0
        assert isinstance(catalog.attack_data_source_coverage, dict)
        assert isinstance(catalog.field_coverage, dict)
