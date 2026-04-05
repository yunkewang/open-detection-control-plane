"""Splunk Cloud CI integration checks (AppInspect / ACS-aligned).

Validates that a Splunk app bundle conforms to cloud-readiness requirements
such as those enforced by Splunk AppInspect and the Automated Private
App Vetting (ACS) pipeline.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from odcp.models.finding import Finding, FindingCategory, FindingSeverity, RemediationAction

logger = logging.getLogger(__name__)

# Files/patterns that are disallowed in Splunk Cloud
_DISALLOWED_PATTERNS: list[tuple[str, str]] = [
    ("*.exe", "Executable files are not allowed in Splunk Cloud apps"),
    ("*.dll", "DLL files are not allowed in Splunk Cloud apps"),
    ("*.so", "Shared object files are not allowed in Splunk Cloud apps"),
    ("*.bat", "Batch scripts are not allowed in Splunk Cloud apps"),
    ("*.cmd", "CMD scripts are not allowed in Splunk Cloud apps"),
    ("*.ps1", "PowerShell scripts are not allowed in Splunk Cloud apps"),
]

# Disallowed SPL commands in Splunk Cloud
_DISALLOWED_COMMANDS: list[tuple[str, str]] = [
    (r"\bscript\b", "The 'script' command is not permitted in Splunk Cloud"),
    (r"\brunscript\b", "The 'runscript' command is not permitted in Splunk Cloud"),
    (r"\brun\b", "Custom scripted inputs ('run') may be restricted in Splunk Cloud"),
    (r"\brest\s+/", "Direct REST calls may be restricted in Splunk Cloud"),
    (r"\bsystem\b", "System-level commands are not permitted in Splunk Cloud"),
    (r"\bcollect\s+index=_", "Writing to internal indexes is not allowed in Splunk Cloud"),
]

# Required metadata fields
_REQUIRED_APP_CONF_FIELDS: list[tuple[str, str, str]] = [
    ("launcher", "version", "app.conf [launcher] must define 'version'"),
    ("install", "build", "app.conf [install] must define 'build'"),
    ("id", "name", "app.conf [id] must define 'name'"),
]


class SplunkCloudChecker:
    """Checks a Splunk app bundle for Splunk Cloud readiness."""

    def check(
        self,
        path: Path,
        detections_spl: Optional[list[tuple[str, str]]] = None,
    ) -> list[Finding]:
        """Run all cloud-readiness checks against the app bundle.

        Args:
            path: Root path of the Splunk app bundle.
            detections_spl: Optional list of (detection_name, search_query)
                tuples to check for disallowed commands.

        Returns:
            List of findings for cloud-readiness issues.
        """
        findings: list[Finding] = []

        findings.extend(self._check_disallowed_files(path))
        findings.extend(self._check_app_conf(path))
        findings.extend(self._check_app_manifest(path))
        findings.extend(self._check_custom_commands(path))

        if detections_spl:
            findings.extend(self._check_spl_commands(detections_spl))

        logger.info(
            "Splunk Cloud readiness: %d issues found in %s",
            len(findings),
            path,
        )
        return findings

    def _check_disallowed_files(self, path: Path) -> list[Finding]:
        """Check for file types not permitted in Splunk Cloud."""
        findings: list[Finding] = []

        for pattern, reason in _DISALLOWED_PATTERNS:
            matches = list(path.rglob(pattern))
            for match in matches:
                findings.append(
                    Finding(
                        detection_id="__cloud_readiness__",
                        category=FindingCategory.configuration_issue,
                        severity=FindingSeverity.high,
                        title=f"Disallowed file: {match.name}",
                        description=f"{reason}: {match.relative_to(path)}",
                        remediation=RemediationAction(
                            title="Remove disallowed file",
                            description=(
                                f"Remove {match.relative_to(path)} or replace "
                                "with a cloud-compatible alternative."
                            ),
                            effort="medium",
                            steps=[
                                f"Delete or replace {match.relative_to(path)}",
                                "Use a Cloud-compatible approach if needed",
                            ],
                        ),
                    )
                )

        return findings

    def _check_app_conf(self, path: Path) -> list[Finding]:
        """Validate app.conf has required metadata for cloud submission."""
        findings: list[Finding] = []

        from odcp.adapters.splunk.parser import parse_conf_file

        app_conf = path / "default" / "app.conf"
        if not app_conf.exists():
            findings.append(
                Finding(
                    detection_id="__cloud_readiness__",
                    category=FindingCategory.configuration_issue,
                    severity=FindingSeverity.high,
                    title="Missing app.conf",
                    description="default/app.conf is required for Splunk Cloud app submission.",
                    remediation=RemediationAction(
                        title="Create app.conf",
                        description="Create a default/app.conf with required stanzas.",
                        effort="low",
                        steps=[
                            "Create default/app.conf",
                            "Add [launcher], [install], and [id] stanzas with required fields",
                        ],
                    ),
                )
            )
            return findings

        stanzas = parse_conf_file(app_conf)

        for stanza, key, msg in _REQUIRED_APP_CONF_FIELDS:
            section = stanzas.get(stanza, {})
            if not section.get(key):
                findings.append(
                    Finding(
                        detection_id="__cloud_readiness__",
                        category=FindingCategory.configuration_issue,
                        severity=FindingSeverity.medium,
                        title=f"Missing app.conf field: [{stanza}] {key}",
                        description=msg,
                        remediation=RemediationAction(
                            title=f"Add [{stanza}] {key} to app.conf",
                            description=f"Set [{stanza}] {key} in default/app.conf.",
                            effort="low",
                            steps=[f"Add '{key} = <value>' under [{stanza}] in default/app.conf"],
                        ),
                    )
                )

        return findings

    def _check_app_manifest(self, path: Path) -> list[Finding]:
        """Check for app.manifest (recommended for cloud vetting)."""
        findings: list[Finding] = []

        manifest = path / "app.manifest"
        if not manifest.exists():
            findings.append(
                Finding(
                    detection_id="__cloud_readiness__",
                    category=FindingCategory.configuration_issue,
                    severity=FindingSeverity.low,
                    title="Missing app.manifest",
                    description=(
                        "An app.manifest file is recommended for Splunk Cloud vetting. "
                        "It declares the app's packaging and compatibility info."
                    ),
                    remediation=RemediationAction(
                        title="Generate app.manifest",
                        description="Use 'slim generate-manifest' or create app.manifest manually.",
                        effort="low",
                        steps=[
                            "Install the Splunk Packaging Toolkit (slim)",
                            "Run: slim generate-manifest <app-directory>",
                        ],
                    ),
                )
            )

        return findings

    def _check_custom_commands(self, path: Path) -> list[Finding]:
        """Check for custom commands that may need special handling."""
        findings: list[Finding] = []

        commands_conf = path / "default" / "commands.conf"
        if commands_conf.exists():
            from odcp.adapters.splunk.parser import parse_conf_file

            stanzas = parse_conf_file(commands_conf)
            for cmd_name, attrs in stanzas.items():
                filename = attrs.get("filename", "")
                if filename.endswith(".py"):
                    # Check Python version compatibility
                    findings.append(
                        Finding(
                            detection_id="__cloud_readiness__",
                            category=FindingCategory.configuration_issue,
                            severity=FindingSeverity.info,
                            title=f"Custom command uses Python script: {cmd_name}",
                            description=(
                                f"Command '{cmd_name}' uses Python script '{filename}'. "
                                "Ensure it is compatible with Splunk Cloud's Python 3 runtime."
                            ),
                            remediation=RemediationAction(
                                title="Verify Python 3 compatibility",
                                description=f"Ensure {filename} is Python 3 compatible.",
                                effort="medium",
                                steps=[
                                    f"Review {filename} for Python 2-only syntax",
                                    "Ensure imports use Splunk Cloud-supported libraries",
                                    "Test with py_compile module for syntax check",
                                ],
                            ),
                        )
                    )

        return findings

    def _check_spl_commands(
        self,
        detections_spl: list[tuple[str, str]],
    ) -> list[Finding]:
        """Check saved search SPL for commands restricted in Splunk Cloud."""
        findings: list[Finding] = []

        for det_name, spl in detections_spl:
            for pattern, reason in _DISALLOWED_COMMANDS:
                if re.search(pattern, spl, re.IGNORECASE):
                    findings.append(
                        Finding(
                            detection_id="__cloud_readiness__",
                            category=FindingCategory.configuration_issue,
                            severity=FindingSeverity.high,
                            title=f"Restricted SPL command in: {det_name}",
                            description=f"{reason}. Found in detection '{det_name}'.",
                            remediation=RemediationAction(
                                title="Replace restricted command",
                                description=(
                                f"Rewrite the search for '{det_name}' "
                                "to avoid restricted commands."
                            ),
                                effort="high",
                                steps=[
                                    f"Review the SPL for '{det_name}'",
                                    "Replace with a cloud-compatible alternative",
                                    "Test the updated search on a Splunk Cloud instance",
                                ],
                            ),
                        )
                    )

        return findings
