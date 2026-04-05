"""Unit tests for ATT&CK STIX catalog refresh."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from odcp.analyzers.coverage.stix_refresh import (
    _extract_data_sources,
    _extract_primary_tactic,
    _extract_technique_id,
    load_stix_from_file,
    merge_catalogs,
    parse_stix_bundle,
    refresh_catalog,
)
from odcp.analyzers.coverage.mitre_catalog import TECHNIQUE_CATALOG
from odcp.models.coverage import MitreTechnique


@pytest.fixture()
def sample_stix_bundle() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Spearphishing Attachment",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566.001",
                        "url": "https://attack.mitre.org/techniques/T1566/001",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_data_sources": [
                    "Application Log: Application Log Content",
                    "Network Traffic: Network Traffic Content",
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "PowerShell",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_data_sources": [
                    "Process: Process Creation",
                    "Script: Script Execution",
                    "Command: Command Execution",
                ],
            },
            # Revoked technique — should be skipped
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Old Technique",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
            # Non-attack-pattern — should be skipped
            {
                "type": "malware",
                "id": "malware--1",
                "name": "Some Malware",
            },
            # Deprecated — should be skipped
            {
                "type": "attack-pattern",
                "id": "attack-pattern--4",
                "name": "Deprecated",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T8888"}
                ],
            },
        ],
    }


class TestParseStixBundle:
    def test_parses_valid_techniques(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        assert len(techniques) == 2
        ids = [t.technique_id for t in techniques]
        assert "T1566.001" in ids
        assert "T1059.001" in ids

    def test_skips_revoked(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        ids = [t.technique_id for t in techniques]
        assert "T9999" not in ids

    def test_skips_deprecated(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        ids = [t.technique_id for t in techniques]
        assert "T8888" not in ids

    def test_extracts_tactic(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        t1566 = [t for t in techniques if t.technique_id == "T1566.001"][0]
        assert t1566.tactic == "initial-access"

    def test_extracts_data_sources(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        t1059 = [t for t in techniques if t.technique_id == "T1059.001"][0]
        assert "Process" in t1059.data_sources
        assert "Script" in t1059.data_sources

    def test_extracts_url(self, sample_stix_bundle):
        techniques = parse_stix_bundle(sample_stix_bundle)
        t1566 = [t for t in techniques if t.technique_id == "T1566.001"][0]
        assert t1566.url is not None
        assert "T1566/001" in t1566.url

    def test_empty_bundle(self):
        assert parse_stix_bundle({}) == []
        assert parse_stix_bundle({"objects": []}) == []


class TestExtractHelpers:
    def test_extract_technique_id(self):
        obj = {
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1234.001"}
            ]
        }
        assert _extract_technique_id(obj) == "T1234.001"

    def test_extract_technique_id_invalid(self):
        obj = {
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0001"}
            ]
        }
        assert _extract_technique_id(obj) is None

    def test_extract_tactic(self):
        obj = {
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}
            ]
        }
        assert _extract_primary_tactic(obj) == "persistence"

    def test_extract_tactic_unknown(self):
        assert _extract_primary_tactic({}) == "unknown"

    def test_extract_data_sources(self):
        obj = {"x_mitre_data_sources": ["Process: Creation", "File: Modification"]}
        sources = _extract_data_sources(obj)
        assert sources == ["Process", "File"]

    def test_extract_data_sources_empty(self):
        assert _extract_data_sources({}) == []


class TestMergeCatalogs:
    def test_merge_replaces_existing(self):
        curated = [
            MitreTechnique(technique_id="T1059", name="Old Name", tactic="execution")
        ]
        refreshed = [
            MitreTechnique(technique_id="T1059", name="New Name", tactic="execution")
        ]
        merged = merge_catalogs(curated, refreshed)
        assert len(merged) == 1
        assert merged[0].name == "New Name"

    def test_merge_preserves_curated_only(self):
        curated = [
            MitreTechnique(technique_id="T1111", name="Custom", tactic="custom")
        ]
        refreshed = [
            MitreTechnique(technique_id="T1059", name="PowerShell", tactic="execution")
        ]
        merged = merge_catalogs(curated, refreshed)
        ids = [t.technique_id for t in merged]
        assert "T1111" in ids
        assert "T1059" in ids

    def test_merge_sorted(self):
        curated = [
            MitreTechnique(technique_id="T1200", name="A", tactic="x"),
            MitreTechnique(technique_id="T1100", name="B", tactic="x"),
        ]
        merged = merge_catalogs(curated, [])
        assert merged[0].technique_id == "T1100"
        assert merged[1].technique_id == "T1200"


class TestLoadStixFromFile:
    def test_load_from_json(self, tmp_path, sample_stix_bundle):
        p = tmp_path / "attack.json"
        p.write_text(json.dumps(sample_stix_bundle))
        techniques = load_stix_from_file(p)
        assert len(techniques) == 2

    def test_refresh_catalog_local_file(self, tmp_path, sample_stix_bundle):
        p = tmp_path / "attack.json"
        p.write_text(json.dumps(sample_stix_bundle))
        techniques = refresh_catalog(stix_source=p)
        assert len(techniques) == 2

    def test_refresh_catalog_nonexistent_file_tries_network_or_fallback(self):
        """When a nonexistent path is given, falls back to network or curated."""
        techniques = refresh_catalog(stix_source=Path("/nonexistent/file.json"))
        # Should return either the curated catalog (fallback) or a larger
        # STIX-fetched catalog if network is available
        assert len(techniques) >= len(TECHNIQUE_CATALOG)
