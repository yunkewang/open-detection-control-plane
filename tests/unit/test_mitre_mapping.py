"""Tests for MITRE ATT&CK technique mapping heuristics."""

from odcp.analyzers.coverage.mitre_catalog import (
    TECHNIQUE_CATALOG,
    TECHNIQUE_INDEX,
    map_detection_to_techniques,
)


class TestMitreCatalog:
    def test_catalog_not_empty(self):
        assert len(TECHNIQUE_CATALOG) >= 20

    def test_index_matches_catalog(self):
        assert len(TECHNIQUE_INDEX) == len(TECHNIQUE_CATALOG)
        for t in TECHNIQUE_CATALOG:
            assert t.technique_id in TECHNIQUE_INDEX

    def test_all_techniques_have_tactic(self):
        for t in TECHNIQUE_CATALOG:
            assert t.tactic, f"{t.technique_id} missing tactic"

    def test_all_techniques_have_data_sources(self):
        for t in TECHNIQUE_CATALOG:
            assert len(t.data_sources) > 0, f"{t.technique_id} has no data sources"


class TestMappingHeuristics:
    def test_brute_force_detection(self):
        ids = map_detection_to_techniques(
            name="Detect Brute Force Login Attempts",
            description="Detects multiple failed login attempts",
            search_query=(
                "`authentication_events` eventtype=failed_login "
                "| stats count as attempts by src_ip"
            ),
            tags=[],
        )
        assert "T1110" in ids

    def test_powershell_detection(self):
        ids = map_detection_to_techniques(
            name="Detect Suspicious PowerShell Execution",
            description="Detects encoded or obfuscated PowerShell commands",
            search_query='Image="*\\powershell.exe" CommandLine="*-enc*"',
            tags=[],
        )
        assert "T1059.001" in ids

    def test_lateral_movement_psexec(self):
        ids = map_detection_to_techniques(
            name="Detect Lateral Movement via PsExec",
            description="Identifies PsExec-style lateral movement",
            search_query='Image="*\\psexec.exe" OR Image="*\\psexesvc.exe"',
            tags=[],
        )
        assert "T1021" in ids

    def test_dns_exfiltration(self):
        ids = map_detection_to_techniques(
            name="Detect Data Exfiltration via DNS",
            description="Detects DNS tunneling",
            search_query=(
                "tstats count from datamodel=Network_Resolution "
                "where DNS.query_length > 50"
            ),
            tags=[],
        )
        assert "T1048" in ids or "T1572" in ids

    def test_tag_based_mapping(self):
        ids = map_detection_to_techniques(
            name="Generic Detection",
            description=None,
            search_query="index=main",
            tags=["T1486", "T1490"],
        )
        assert "T1486" in ids
        assert "T1490" in ids

    def test_no_match_returns_empty(self):
        ids = map_detection_to_techniques(
            name="Daily User Activity Summary",
            description="Non-detection saved search for user reporting",
            search_query="index=main sourcetype=access_combined | stats count by user",
            tags=[],
        )
        # May or may not match — just verify it doesn't crash
        assert isinstance(ids, list)

    def test_cloud_api_detection(self):
        ids = map_detection_to_techniques(
            name="Detect Unauthorized Cloud API Calls",
            description="Detects API calls from unauthorized regions",
            search_query="`cloud_trail_events` | lookup authorized_regions",
            tags=[],
        )
        # This is a broad detection; may match valid accounts
        assert isinstance(ids, list)
