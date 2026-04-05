"""Integration tests for extended Sigma features: correlations, filters, OCSF."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from odcp.adapters.sigma import SigmaAdapter
from odcp.analyzers.ocsf_mapper import OcsfMapper
from odcp.core.engine import ScanEngine


@pytest.fixture()
def sigma_rule_set(tmp_path):
    """Create a mixed rule set with detections, correlations, and filters."""
    # Detection 1
    (tmp_path / "proc_creation.yml").write_text(yaml.dump({
        "title": "Suspicious Process",
        "id": "det-001",
        "level": "high",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection",
        },
        "tags": ["attack.execution", "attack.t1059.001"],
    }))

    # Detection 2
    (tmp_path / "dns_exfil.yml").write_text(yaml.dump({
        "title": "DNS Exfiltration",
        "id": "det-002",
        "level": "high",
        "logsource": {"category": "dns_query"},
        "detection": {
            "selection": {"QueryName|contains": ".evil.com"},
            "condition": "selection",
        },
        "tags": ["attack.exfiltration", "attack.t1048"],
    }))

    # Correlation
    (tmp_path / "correlation.yml").write_text(yaml.dump({
        "title": "Multi-Stage Attack",
        "type": "correlation",
        "correlation": {
            "type": "temporal",
            "rules": ["det-001", "det-002"],
            "group-by": ["ComputerName"],
            "timespan": "30m",
        },
    }))

    # Filter
    (tmp_path / "filter.yml").write_text(yaml.dump({
        "title": "Exclude Test Machines",
        "type": "filter",
        "rules": ["*"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "filter": {"ComputerName|startswith": "TEST-"},
            "condition": "not filter",
        },
    }))

    return tmp_path


class TestSigmaExtendedScan:
    def test_full_scan_with_correlations(self, sigma_rule_set):
        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        report = engine.scan(sigma_rule_set)

        # Detections parsed
        assert len(report.detections) == 2

        # Correlations and filters captured
        assert len(adapter.correlations) == 1
        assert adapter.correlations[0].name == "Multi-Stage Attack"
        assert adapter.correlations[0].correlation_type.value == "temporal"
        assert len(adapter.correlations[0].rule_references) == 2

        assert len(adapter.filters) == 1
        assert adapter.filters[0].name == "Exclude Test Machines"

    def test_ocsf_normalization(self, sigma_rule_set):
        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        report = engine.scan(sigma_rule_set)

        mapper = OcsfMapper()
        result = mapper.normalize(report.detections, report.dependencies, "sigma")

        assert result.total_detections == 2
        assert result.mapped_detections >= 1  # process_creation should map
        assert len(result.mappings) >= 1

    def test_report_metadata_enrichment(self, sigma_rule_set):
        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        report = engine.scan(sigma_rule_set)

        meta = dict(report.metadata)
        meta["correlations"] = [c.model_dump() for c in adapter.correlations]
        meta["filters"] = [f.model_dump() for f in adapter.filters]

        assert len(meta["correlations"]) == 1
        assert len(meta["filters"]) == 1
        assert meta["correlations"][0]["correlation_type"] == "temporal"


class TestExampleRuleSet:
    def test_scan_example_sigma_rules(self):
        """Scan the example sigma_rules directory which now includes correlations and filters."""
        example_path = Path(__file__).parent.parent.parent / "examples" / "sigma_rules"
        if not example_path.exists():
            pytest.skip("Example sigma rules not found")

        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        report = engine.scan(example_path)

        # Should have the original detections plus the new example rules
        assert len(report.detections) >= 3  # At least the original 3 non-deprecated

        # Should have correlations from the new files
        assert len(adapter.correlations) >= 2

        # Should have at least one filter
        assert len(adapter.filters) >= 1
