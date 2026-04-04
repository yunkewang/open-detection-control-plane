"""MITRE ATT&CK technique catalog and detection mapping heuristics.

This module provides a curated catalog of commonly-detected MITRE ATT&CK
techniques and heuristics for mapping detections to techniques based on
their names, descriptions, tags, and SPL content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from odcp.models.coverage import MitreTechnique


@dataclass
class _MappingRule:
    """A heuristic rule for matching detections to techniques."""

    technique_id: str
    keywords: list[str] = field(default_factory=list)
    spl_patterns: list[str] = field(default_factory=list)


# -- Curated catalog of common ATT&CK techniques --

TECHNIQUE_CATALOG: list[MitreTechnique] = [
    # Initial Access
    MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="initial-access",
        data_sources=["Authentication", "Logon Session"],
    ),
    MitreTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="initial-access",
        data_sources=["Email", "Network Traffic"],
    ),
    # Execution
    MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="execution",
        data_sources=["Process", "Command"],
    ),
    MitreTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="execution",
        data_sources=["Process", "Script", "Command"],
    ),
    MitreTechnique(
        technique_id="T1204",
        name="User Execution",
        tactic="execution",
        data_sources=["Process", "File"],
    ),
    # Persistence
    MitreTechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="persistence",
        data_sources=["Scheduled Job", "Process", "Command"],
    ),
    MitreTechnique(
        technique_id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic="persistence",
        data_sources=["Windows Registry", "Process", "File"],
    ),
    MitreTechnique(
        technique_id="T1136",
        name="Create Account",
        tactic="persistence",
        data_sources=["User Account", "Process", "Command"],
    ),
    # Privilege Escalation
    MitreTechnique(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="privilege-escalation",
        data_sources=["Process", "Command", "Windows Registry"],
    ),
    # Defense Evasion
    MitreTechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="defense-evasion",
        data_sources=["Process", "File", "Command"],
    ),
    MitreTechnique(
        technique_id="T1070",
        name="Indicator Removal",
        tactic="defense-evasion",
        data_sources=["File", "Process", "Windows Registry"],
    ),
    # Credential Access
    MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="credential-access",
        data_sources=["Authentication", "Logon Session"],
    ),
    MitreTechnique(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactic="credential-access",
        data_sources=["Process", "Command", "Active Directory"],
    ),
    # Discovery
    MitreTechnique(
        technique_id="T1087",
        name="Account Discovery",
        tactic="discovery",
        data_sources=["Process", "Command"],
    ),
    MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="discovery",
        data_sources=["Network Traffic", "Process"],
    ),
    # Lateral Movement
    MitreTechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="lateral-movement",
        data_sources=["Network Traffic", "Logon Session", "Process"],
    ),
    MitreTechnique(
        technique_id="T1570",
        name="Lateral Tool Transfer",
        tactic="lateral-movement",
        data_sources=["Network Traffic", "File"],
    ),
    # Collection
    MitreTechnique(
        technique_id="T1114",
        name="Email Collection",
        tactic="collection",
        data_sources=["Email", "Logon Session", "File"],
    ),
    # Command and Control
    MitreTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="command-and-control",
        data_sources=["Network Traffic"],
    ),
    MitreTechnique(
        technique_id="T1572",
        name="Protocol Tunneling",
        tactic="command-and-control",
        data_sources=["Network Traffic"],
    ),
    # Exfiltration
    MitreTechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="exfiltration",
        data_sources=["Network Traffic", "Command"],
    ),
    MitreTechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="exfiltration",
        data_sources=["Network Traffic"],
    ),
    # Impact
    MitreTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="impact",
        data_sources=["File", "Process", "Command"],
    ),
    MitreTechnique(
        technique_id="T1490",
        name="Inhibit System Recovery",
        tactic="impact",
        data_sources=["Process", "Command", "Windows Registry"],
    ),
]

# Index for fast lookup
TECHNIQUE_INDEX: dict[str, MitreTechnique] = {
    t.technique_id: t for t in TECHNIQUE_CATALOG
}


# -- Heuristic mapping rules --

_MAPPING_RULES: list[_MappingRule] = [
    _MappingRule(
        "T1110",
        keywords=["brute force", "failed login", "login attempt", "password spray"],
        spl_patterns=[r"failed.?login", r"attempts\s*>\s*\d+"],
    ),
    _MappingRule(
        "T1078",
        keywords=["valid account", "unauthorized access", "credential"],
        spl_patterns=[r"authentication", r"logon"],
    ),
    _MappingRule(
        "T1059.001",
        keywords=["powershell", "encoded command", "obfuscated powershell"],
        spl_patterns=[r"powershell\.exe", r"-enc", r"encodedcommand"],
    ),
    _MappingRule(
        "T1059",
        keywords=[
            "command", "scripting", "cmd.exe", "wscript", "cscript", "bash",
        ],
        spl_patterns=[r"cmd\.exe", r"wscript", r"cscript"],
    ),
    _MappingRule(
        "T1021",
        keywords=[
            "lateral movement", "psexec", "remote service", "rdp",
            "wmi", "winrm", "ssh",
        ],
        spl_patterns=[r"psexec", r"psexesvc", r"wmic", r"winrm"],
    ),
    _MappingRule(
        "T1570",
        keywords=["lateral tool", "tool transfer"],
        spl_patterns=[r"psexec", r"smbcopy"],
    ),
    _MappingRule(
        "T1048",
        keywords=["exfiltration", "dns tunnel", "data exfil"],
        spl_patterns=[
            r"dns.*tunnel", r"query_length\s*>", r"exfiltration",
        ],
    ),
    _MappingRule(
        "T1572",
        keywords=["dns tunnel", "protocol tunnel", "tunneling"],
        spl_patterns=[r"dns.*tunnel", r"query_length\s*>"],
    ),
    _MappingRule(
        "T1071",
        keywords=["c2", "command and control", "beacon", "callback"],
        spl_patterns=[r"c2", r"beacon"],
    ),
    _MappingRule(
        "T1027",
        keywords=[
            "obfuscated", "encoded", "base64", "obfuscation",
        ],
        spl_patterns=[r"base64", r"-enc", r"obfuscat"],
    ),
    _MappingRule(
        "T1547",
        keywords=["autostart", "run key", "startup", "registry persistence"],
        spl_patterns=[
            r"currentversion\\\\run", r"startup",
        ],
    ),
    _MappingRule(
        "T1053",
        keywords=["scheduled task", "schtask", "cron", "at job"],
        spl_patterns=[r"schtask", r"scheduled"],
    ),
    _MappingRule(
        "T1003",
        keywords=[
            "credential dump", "mimikatz", "lsass", "hashdump",
            "credential theft",
        ],
        spl_patterns=[r"lsass", r"mimikatz", r"hashdump"],
    ),
    _MappingRule(
        "T1070",
        keywords=["indicator removal", "clear log", "log deletion"],
        spl_patterns=[r"wevtutil.*cl", r"clear-eventlog"],
    ),
    _MappingRule(
        "T1486",
        keywords=["ransomware", "encrypt", "ransom"],
        spl_patterns=[r"ransomware", r"encrypt"],
    ),
    _MappingRule(
        "T1136",
        keywords=["create account", "new user", "add user"],
        spl_patterns=[r"net\s+user.*\/add", r"new-localuser"],
    ),
    _MappingRule(
        "T1566",
        keywords=["phishing", "spearphishing", "malicious attachment"],
        spl_patterns=[r"phish", r"spearphish"],
    ),
    _MappingRule(
        "T1046",
        keywords=["port scan", "network scan", "service discovery"],
        spl_patterns=[r"port.?scan", r"nmap"],
    ),
    _MappingRule(
        "T1087",
        keywords=["account discovery", "account enumeration"],
        spl_patterns=[r"net\s+user", r"get-aduser"],
    ),
    _MappingRule(
        "T1548",
        keywords=["uac bypass", "privilege escalation", "elevation"],
        spl_patterns=[r"uac", r"privilege.?escalat"],
    ),
    _MappingRule(
        "T1204",
        keywords=["user execution", "click", "open attachment"],
        spl_patterns=[],
    ),
    _MappingRule(
        "T1114",
        keywords=["email collection", "email forwarding"],
        spl_patterns=[r"email.*forward", r"inbox.*rule"],
    ),
    _MappingRule(
        "T1041",
        keywords=["exfiltration over c2", "data staging"],
        spl_patterns=[],
    ),
    _MappingRule(
        "T1490",
        keywords=[
            "inhibit recovery", "shadow copy", "vssadmin",
            "bcdedit", "wbadmin",
        ],
        spl_patterns=[r"vssadmin", r"bcdedit", r"wbadmin"],
    ),
]


def map_detection_to_techniques(
    name: str,
    description: str | None,
    search_query: str,
    tags: list[str],
) -> list[str]:
    """Map a detection to MITRE ATT&CK technique IDs using heuristics.

    Checks detection name, description, tags, and SPL query against
    keyword and regex rules.
    """
    text = " ".join(
        filter(None, [name.lower(), (description or "").lower(), " ".join(tags).lower()])
    )
    spl_lower = search_query.lower()

    matched: list[str] = []
    for rule in _MAPPING_RULES:
        if _rule_matches(rule, text, spl_lower):
            matched.append(rule.technique_id)

    # Also check tags for explicit MITRE IDs (e.g. "T1059.001")
    for tag in tags:
        tag_upper = tag.strip().upper()
        if re.match(r"T\d{4}(\.\d{3})?$", tag_upper):
            if tag_upper not in matched:
                matched.append(tag_upper)

    return matched


def _rule_matches(rule: _MappingRule, text: str, spl: str) -> bool:
    """Check if a mapping rule matches against detection text and SPL."""
    for kw in rule.keywords:
        if kw in text:
            return True
    for pat in rule.spl_patterns:
        if re.search(pat, spl, re.IGNORECASE):
            return True
    return False
