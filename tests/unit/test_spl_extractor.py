"""Tests for SPL dependency extraction."""

import pytest

from odcp.adapters.splunk.spl_extractor import (
    extract_all_references,
    extract_datamodel_references,
    extract_eventtype_references,
    extract_lookup_references,
    extract_macro_references,
    extract_savedsearch_references,
    extract_tag_references,
)


class TestMacroExtraction:
    def test_simple_macro(self):
        assert extract_macro_references("`my_macro`") == ["my_macro"]

    def test_macro_with_args(self):
        assert extract_macro_references('`my_macro(arg1, "arg2")`') == ["my_macro"]

    def test_multiple_macros(self):
        spl = '`auth_events` | where user!="system" | `normalize_fields`'
        result = extract_macro_references(spl)
        assert result == ["auth_events", "normalize_fields"]

    def test_duplicate_macros(self):
        spl = "`my_macro` | eval x=1 | `my_macro`"
        assert extract_macro_references(spl) == ["my_macro"]

    def test_no_macros(self):
        assert extract_macro_references("index=main | stats count by user") == []

    def test_macro_with_underscores_numbers(self):
        assert extract_macro_references("`cim_auth_2`") == ["cim_auth_2"]


class TestEventtypeExtraction:
    def test_simple_eventtype(self):
        assert extract_eventtype_references("eventtype=failed_login") == ["failed_login"]

    def test_quoted_eventtype(self):
        assert extract_eventtype_references('eventtype="success_login"') == ["success_login"]

    def test_multiple_eventtypes(self):
        spl = "eventtype=failed_login OR eventtype=success_login"
        result = extract_eventtype_references(spl)
        assert result == ["failed_login", "success_login"]

    def test_no_eventtypes(self):
        assert extract_eventtype_references("index=main sourcetype=syslog") == []


class TestLookupExtraction:
    def test_lookup(self):
        assert extract_lookup_references("| lookup my_lookup src_ip") == ["my_lookup"]

    def test_inputlookup(self):
        assert extract_lookup_references("| inputlookup my_table.csv") == ["my_table.csv"]

    def test_outputlookup(self):
        assert extract_lookup_references("| outputlookup results.csv") == ["results.csv"]

    def test_multiple_lookups(self):
        spl = "| lookup geo_lookup ip | lookup threat_intel domain"
        result = extract_lookup_references(spl)
        assert result == ["geo_lookup", "threat_intel"]

    def test_no_lookups(self):
        assert extract_lookup_references("index=main | stats count") == []


class TestDatamodelExtraction:
    def test_tstats_datamodel(self):
        spl = '| tstats count from datamodel=Network_Resolution by DNS.src'
        result = extract_datamodel_references(spl)
        assert "Network_Resolution" in result

    def test_from_datamodel(self):
        spl = "| from datamodel:Authentication"
        result = extract_datamodel_references(spl)
        assert "Authentication" in result

    def test_datamodel_command(self):
        spl = "| datamodel Network_Traffic search"
        result = extract_datamodel_references(spl)
        assert "Network_Traffic" in result

    def test_no_datamodels(self):
        assert extract_datamodel_references("index=main | stats count") == []


class TestSavedSearchExtraction:
    def test_savedsearch(self):
        assert extract_savedsearch_references("| savedsearch my_search") == ["my_search"]

    def test_no_savedsearch(self):
        assert extract_savedsearch_references("index=main") == []


class TestExtractAll:
    def test_complex_spl(self):
        spl = (
            '`sysmon_events` eventtype=process_create '
            '| lookup threat_intel hash '
            '| `normalize_fields` '
            '| tstats count from datamodel=Endpoint by host'
        )
        result = extract_all_references(spl)
        assert "sysmon_events" in result["macro"]
        assert "normalize_fields" in result["macro"]
        assert "process_create" in result["eventtype"]
        assert "threat_intel" in result["lookup"]
        assert "Endpoint" in result["data_model"]

    def test_empty_spl(self):
        result = extract_all_references("")
        for v in result.values():
            assert v == []


class TestTagExtraction:
    def test_simple_tag(self):
        assert extract_tag_references("index=main tag=malware") == ["malware"]

    def test_tag_field_syntax(self):
        assert extract_tag_references('tag::eventtype="failed_login"') == ["failed_login"]

    def test_multiple_tags_deduped(self):
        spl = 'tag=malware OR tag="malware" OR tag::host=suspicious'
        assert extract_tag_references(spl) == ["malware", "suspicious"]

    def test_extract_all_includes_tags(self):
        refs = extract_all_references("index=main tag=exfiltration")
        assert refs["tag"] == ["exfiltration"]
