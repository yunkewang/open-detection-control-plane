"""SPL dependency extraction — extracts references from Splunk search queries."""

from __future__ import annotations

import re


def extract_macro_references(spl: str) -> list[str]:
    """Extract macro references from SPL.

    Macros in SPL are wrapped in backticks: `macro_name` or `macro_name(arg1, arg2)`.
    """
    pattern = r"`\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*`"
    matches = re.findall(pattern, spl)
    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def extract_eventtype_references(spl: str) -> list[str]:
    """Extract eventtype= references from SPL."""
    pattern = r'\beventtype\s*=\s*"?([a-zA-Z_][a-zA-Z0-9_\-]*)"?'
    matches = re.findall(pattern, spl, re.IGNORECASE)
    return _dedupe(matches)


def extract_lookup_references(spl: str) -> list[str]:
    """Extract lookup references from SPL.

    Matches: | lookup <name>, | inputlookup <name>, | outputlookup <name>
    """
    pattern = r"\|\s*(?:lookup|inputlookup|outputlookup)\s+([a-zA-Z_][a-zA-Z0-9_.\-]*)"
    matches = re.findall(pattern, spl, re.IGNORECASE)
    return _dedupe(matches)


def extract_datamodel_references(spl: str) -> list[str]:
    """Extract data model references from SPL.

    Matches:
    - | datamodel <name>
    - | from datamodel:<dataset>
    - tstats ... from datamodel=<name>
    - datamodel:<name>
    """
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


def extract_savedsearch_references(spl: str) -> list[str]:
    """Extract saved search references from SPL.

    Matches: | savedsearch <name>
    """
    pattern = r"\|\s*savedsearch\s+\"?([a-zA-Z_][a-zA-Z0-9_ \-]*)\"?"
    matches = re.findall(pattern, spl, re.IGNORECASE)
    return _dedupe([m.strip() for m in matches])


def extract_all_references(spl: str) -> dict[str, list[str]]:
    """Extract all dependency references from an SPL query."""
    return {
        "macro": extract_macro_references(spl),
        "eventtype": extract_eventtype_references(spl),
        "lookup": extract_lookup_references(spl),
        "data_model": extract_datamodel_references(spl),
        "saved_search": extract_savedsearch_references(spl),
    }


def _dedupe(items: list[str]) -> list[str]:
    """Deduplicate a list while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
