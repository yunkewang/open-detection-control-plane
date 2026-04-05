"""Unit tests for Splunk Cloud CI readiness checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.analyzers.splunk_cloud import SplunkCloudChecker


@pytest.fixture()
def checker():
    return SplunkCloudChecker()


@pytest.fixture()
def clean_app(tmp_path):
    """An app bundle that passes all cloud checks."""
    default = tmp_path / "default"
    default.mkdir()
    (default / "app.conf").write_text(
        "[launcher]\nversion = 1.0.0\n\n[install]\nbuild = 1\n\n[id]\nname = test_app\n"
    )
    (default / "savedsearches.conf").write_text(
        "[My Search]\nsearch = index=main | stats count\n"
    )
    return tmp_path


@pytest.fixture()
def dirty_app(tmp_path):
    """An app bundle with cloud-readiness issues."""
    default = tmp_path / "default"
    default.mkdir()
    # app.conf missing [id] name
    (default / "app.conf").write_text("[launcher]\nversion = 1.0.0\n")
    # Disallowed file
    (tmp_path / "malware.exe").write_bytes(b"\x00")
    (tmp_path / "helper.ps1").write_text("Write-Host Hello")
    return tmp_path


class TestDisallowedFiles:
    def test_detects_exe(self, checker, dirty_app):
        findings = checker._check_disallowed_files(dirty_app)
        exe_findings = [f for f in findings if ".exe" in f.title]
        assert len(exe_findings) >= 1

    def test_detects_ps1(self, checker, dirty_app):
        findings = checker._check_disallowed_files(dirty_app)
        ps1_findings = [f for f in findings if ".ps1" in f.title]
        assert len(ps1_findings) >= 1

    def test_clean_app_no_findings(self, checker, clean_app):
        findings = checker._check_disallowed_files(clean_app)
        assert findings == []


class TestAppConf:
    def test_missing_app_conf(self, checker, tmp_path):
        findings = checker._check_app_conf(tmp_path)
        assert len(findings) == 1
        assert "Missing app.conf" in findings[0].title

    def test_complete_app_conf(self, checker, clean_app):
        findings = checker._check_app_conf(clean_app)
        assert findings == []

    def test_incomplete_app_conf(self, checker, dirty_app):
        findings = checker._check_app_conf(dirty_app)
        # Missing [install] build and [id] name
        assert len(findings) >= 1
        missing_fields = [f.title for f in findings]
        assert any("build" in t for t in missing_fields)


class TestAppManifest:
    def test_missing_manifest(self, checker, clean_app):
        findings = checker._check_app_manifest(clean_app)
        assert len(findings) == 1
        assert "manifest" in findings[0].title.lower()

    def test_present_manifest(self, checker, clean_app):
        (clean_app / "app.manifest").write_text("{}")
        findings = checker._check_app_manifest(clean_app)
        assert findings == []


class TestSplCommands:
    def test_restricted_script_command(self, checker):
        spl = [("Bad Search", "| script python my_script")]
        findings = checker._check_spl_commands(spl)
        assert len(findings) >= 1

    def test_restricted_rest_command(self, checker):
        spl = [("Rest Search", "| rest /services/search/jobs")]
        findings = checker._check_spl_commands(spl)
        assert len(findings) >= 1

    def test_clean_spl(self, checker):
        spl = [("Good Search", "index=main sourcetype=syslog | stats count by host")]
        findings = checker._check_spl_commands(spl)
        assert findings == []

    def test_internal_index_write(self, checker):
        spl = [("Collector", "index=main | collect index=_internal")]
        findings = checker._check_spl_commands(spl)
        assert len(findings) >= 1


class TestCustomCommands:
    def test_python_command(self, checker, clean_app):
        commands_conf = clean_app / "default" / "commands.conf"
        commands_conf.write_text(
            "[mycommand]\nfilename = my_script.py\nchunked = true\n"
        )
        findings = checker._check_custom_commands(clean_app)
        assert len(findings) == 1
        assert "Python" in findings[0].title

    def test_no_commands_conf(self, checker, clean_app):
        findings = checker._check_custom_commands(clean_app)
        assert findings == []


class TestFullCheck:
    def test_clean_app(self, checker, clean_app):
        findings = checker.check(clean_app)
        # Only the missing manifest is expected
        assert len(findings) <= 1

    def test_dirty_app(self, checker, dirty_app):
        findings = checker.check(dirty_app, detections_spl=[
            ("Bad Script", "| script python evil"),
        ])
        assert len(findings) >= 3  # exe + ps1 + missing fields + manifest + script
