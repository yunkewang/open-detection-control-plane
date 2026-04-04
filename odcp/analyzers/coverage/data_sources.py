"""Data source extraction from SPL queries.

Identifies indexes, sourcetypes, and data models referenced in search
queries to build a data source inventory.
"""

from __future__ import annotations

import re

from odcp.models import Detection
from odcp.models.coverage import DataSource, DataSourceInventory


def extract_index_references(spl: str) -> list[str]:
    """Extract index= references from SPL."""
    pattern = r'\bindex\s*=\s*"?([a-zA-Z_*][a-zA-Z0-9_*\-]*)"?'
    matches = re.findall(pattern, spl, re.IGNORECASE)
    return _dedupe(matches)


def extract_sourcetype_references(spl: str) -> list[str]:
    """Extract sourcetype= references from SPL."""
    pattern = r'\bsourcetype\s*=\s*"?([a-zA-Z_*][a-zA-Z0-9_:*\-]*)"?'
    matches = re.findall(pattern, spl, re.IGNORECASE)
    return _dedupe(matches)


def extract_datamodel_references(spl: str) -> list[str]:
    """Extract data model references from SPL."""
    patterns = [
        r"\|\s*datamodel\s+([a-zA-Z_][a-zA-Z0-9_.\-]*)",
        r"\|\s*from\s+datamodel\s*:\s*([a-zA-Z_][a-zA-Z0-9_.\-]*)",
        r"\bfrom\s+datamodel\s*=\s*\"?([a-zA-Z_][a-zA-Z0-9_.\-]*)\"?",
        r"\bdatamodel\s*=\s*\"?([a-zA-Z_][a-zA-Z0-9_.\-]*)\"?",
    ]
    matches: list[str] = []
    for p in patterns:
        matches.extend(re.findall(p, spl, re.IGNORECASE))
    return _dedupe(matches)


def build_data_source_inventory(
    detections: list[Detection],
    known_indexes: list[str] | None = None,
    known_sourcetypes: list[str] | None = None,
) -> DataSourceInventory:
    """Build a data source inventory from detections.

    Scans all detection SPL to discover referenced data sources, then
    compares against known/expected sources to identify gaps.
    """
    source_map: dict[str, DataSource] = {}

    for det in detections:
        spl = det.search_query

        for idx in extract_index_references(spl):
            key = f"index:{idx}"
            if key not in source_map:
                source_map[key] = DataSource(
                    name=idx, source_type="index", expected=True
                )
            source_map[key].detection_count += 1

        for st in extract_sourcetype_references(spl):
            key = f"sourcetype:{st}"
            if key not in source_map:
                source_map[key] = DataSource(
                    name=st, source_type="sourcetype", expected=True
                )
            source_map[key].detection_count += 1

        for dm in extract_datamodel_references(spl):
            key = f"data_model:{dm}"
            if key not in source_map:
                source_map[key] = DataSource(
                    name=dm, source_type="data_model", expected=True
                )
            source_map[key].detection_count += 1

    # Mark known sources as observed
    for idx in known_indexes or []:
        key = f"index:{idx}"
        if key in source_map:
            source_map[key].observed = True
        else:
            source_map[key] = DataSource(
                name=idx, source_type="index", observed=True
            )

    for st in known_sourcetypes or []:
        key = f"sourcetype:{st}"
        if key in source_map:
            source_map[key].observed = True
        else:
            source_map[key] = DataSource(
                name=st, source_type="sourcetype", observed=True
            )

    sources = list(source_map.values())
    observed = sum(1 for s in sources if s.observed)
    expected = sum(1 for s in sources if s.expected)
    gaps = sum(1 for s in sources if s.expected and not s.observed)

    return DataSourceInventory(
        sources=sources,
        total_observed=observed,
        total_expected=expected,
        total_gaps=gaps,
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
