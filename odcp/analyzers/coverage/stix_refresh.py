"""ATT&CK catalog auto-refresh from STIX/TAXII feeds.

Fetches the ATT&CK Enterprise STIX bundle from the official MITRE
repository and converts it into ODCP MitreTechnique objects, replacing
or augmenting the hand-curated catalog.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from odcp.models.coverage import MitreTechnique

logger = logging.getLogger(__name__)

# Official ATT&CK STIX bundle URL (Enterprise)
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Tactic mapping from STIX kill-chain phase names to ODCP tactic slugs
_TACTIC_SLUG: dict[str, str] = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource-development",
    "initial-access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "credential-access": "credential-access",
    "discovery": "discovery",
    "lateral-movement": "lateral-movement",
    "collection": "collection",
    "command-and-control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def parse_stix_bundle(bundle: dict) -> list[MitreTechnique]:
    """Parse a STIX 2.1 bundle into MitreTechnique objects.

    Extracts attack-pattern objects that have external references
    containing ATT&CK technique IDs (T####[.###]).
    """
    techniques: list[MitreTechnique] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked / deprecated
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _extract_technique_id(obj)
        if not technique_id:
            continue

        name = obj.get("name", "")
        tactic = _extract_primary_tactic(obj)
        data_sources = _extract_data_sources(obj)
        url = _extract_url(obj)

        techniques.append(
            MitreTechnique(
                technique_id=technique_id,
                name=name,
                tactic=tactic,
                url=url,
                data_sources=data_sources,
            )
        )

    logger.info(
        "Parsed %d techniques from STIX bundle (%d objects total)",
        len(techniques),
        len(bundle.get("objects", [])),
    )
    return techniques


def load_stix_from_file(path: Path) -> list[MitreTechnique]:
    """Load a STIX bundle from a local JSON file and parse techniques."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return parse_stix_bundle(data)


def refresh_catalog(
    stix_source: Optional[Path] = None,
) -> list[MitreTechnique]:
    """Refresh the technique catalog from a STIX source.

    If *stix_source* is a local file path, reads from disk.
    Otherwise, attempts to fetch from the official MITRE STIX URL.

    Falls back to the hand-curated catalog on any error.
    """
    if stix_source and stix_source.exists():
        logger.info("Refreshing catalog from local STIX file: %s", stix_source)
        return load_stix_from_file(stix_source)

    # Try network fetch
    try:
        import urllib.request

        logger.info("Fetching ATT&CK STIX bundle from %s", ATTACK_STIX_URL)
        req = urllib.request.Request(
            ATTACK_STIX_URL,
            headers={"User-Agent": "ODCP/0.1"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return parse_stix_bundle(data)
    except Exception as exc:
        logger.warning(
            "Failed to fetch STIX bundle, falling back to curated catalog: %s",
            exc,
        )
        from odcp.analyzers.coverage.mitre_catalog import TECHNIQUE_CATALOG

        return list(TECHNIQUE_CATALOG)


def merge_catalogs(
    curated: list[MitreTechnique],
    refreshed: list[MitreTechnique],
) -> list[MitreTechnique]:
    """Merge refreshed STIX techniques with the curated catalog.

    Techniques from the refreshed feed take priority.  Curated entries
    that don't exist in the feed are preserved to avoid losing coverage.
    """
    by_id: dict[str, MitreTechnique] = {t.technique_id: t for t in curated}
    for tech in refreshed:
        by_id[tech.technique_id] = tech
    return sorted(by_id.values(), key=lambda t: t.technique_id)


# -- Internal helpers --


def _extract_technique_id(obj: dict) -> Optional[str]:
    """Extract ATT&CK technique ID from STIX external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id", "")
            if re.match(r"T\d{4}(\.\d{3})?$", ext_id):
                return ext_id
    return None


def _extract_url(obj: dict) -> Optional[str]:
    """Extract ATT&CK page URL from STIX external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _extract_primary_tactic(obj: dict) -> str:
    """Extract the primary tactic from STIX kill-chain phases."""
    phases = obj.get("kill_chain_phases", [])
    for phase in phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            slug = phase.get("phase_name", "")
            if slug in _TACTIC_SLUG:
                return _TACTIC_SLUG[slug]
    return "unknown"


def _extract_data_sources(obj: dict) -> list[str]:
    """Extract data source names from x_mitre_data_sources."""
    raw = obj.get("x_mitre_data_sources", [])
    sources: list[str] = []
    for entry in raw:
        # Format: "Data Source: Component" → take just the source name
        name = entry.split(":")[0].strip()
        if name and name not in sources:
            sources.append(name)
    return sources
