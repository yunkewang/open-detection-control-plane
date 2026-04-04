"""Tests for data source extraction and inventory."""

from odcp.analyzers.coverage.data_sources import (
    build_data_source_inventory,
    extract_datamodel_references,
    extract_index_references,
    extract_sourcetype_references,
)
from odcp.models import Detection


class TestIndexExtraction:
    def test_simple_index(self):
        assert extract_index_references("index=main") == ["main"]

    def test_quoted_index(self):
        assert extract_index_references('index="security"') == ["security"]

    def test_multiple_indexes(self):
        spl = "index=main OR index=security"
        result = extract_index_references(spl)
        assert "main" in result
        assert "security" in result

    def test_wildcard_index(self):
        assert extract_index_references("index=os*") == ["os*"]

    def test_no_index(self):
        assert extract_index_references("| stats count by user") == []


class TestSourcetypeExtraction:
    def test_simple_sourcetype(self):
        refs = extract_sourcetype_references("sourcetype=access_combined")
        assert refs == ["access_combined"]

    def test_quoted_sourcetype(self):
        refs = extract_sourcetype_references('sourcetype="WinEventLog:Security"')
        assert refs == ["WinEventLog:Security"]

    def test_no_sourcetype(self):
        assert extract_sourcetype_references("index=main | stats count") == []


class TestDatamodelExtraction:
    def test_tstats_datamodel(self):
        spl = '| tstats count from datamodel=Network_Resolution where DNS.query_length > 50'
        refs = extract_datamodel_references(spl)
        assert "Network_Resolution" in refs

    def test_from_datamodel(self):
        spl = "| from datamodel:Endpoint.Processes"
        refs = extract_datamodel_references(spl)
        # The regex captures "Endpoint.Processes" as the full reference
        assert any("Endpoint" in r for r in refs)


class TestDataSourceInventory:
    def test_basic_inventory(self):
        dets = [
            Detection(
                name="Det1",
                search_query='index=main sourcetype=syslog | stats count',
            ),
            Detection(
                name="Det2",
                search_query='index=main sourcetype=access_combined | table _time',
            ),
        ]
        inv = build_data_source_inventory(dets)
        assert inv.total_expected > 0
        names = {s.name for s in inv.sources}
        assert "main" in names
        assert "syslog" in names

    def test_inventory_with_known_sources(self):
        dets = [
            Detection(
                name="Det1",
                search_query="index=main | stats count",
            ),
        ]
        inv = build_data_source_inventory(
            dets,
            known_indexes=["main"],
        )
        main_src = next(s for s in inv.sources if s.name == "main")
        assert main_src.observed is True
        assert main_src.expected is True
        assert inv.total_gaps == 0

    def test_inventory_with_gaps(self):
        dets = [
            Detection(
                name="Det1",
                search_query="index=security | stats count",
            ),
        ]
        inv = build_data_source_inventory(dets, known_indexes=["main"])
        # security is expected but not in known_indexes
        assert inv.total_gaps == 1

    def test_detection_count(self):
        dets = [
            Detection(name="Det1", search_query="index=main | head 10"),
            Detection(name="Det2", search_query="index=main | tail 10"),
            Detection(name="Det3", search_query="index=main | sort _time"),
        ]
        inv = build_data_source_inventory(dets)
        main_src = next(s for s in inv.sources if s.name == "main")
        assert main_src.detection_count == 3

    def test_empty_detections(self):
        inv = build_data_source_inventory([])
        assert inv.total_expected == 0
        assert inv.total_gaps == 0
