"""Parser for Splunk .conf files."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

Stanzas = dict[str, dict[str, str]]


def parse_conf_file(path: Path) -> Stanzas:
    """Parse a Splunk .conf file into {stanza_name: {key: value}}.

    Handles:
    - [stanza] headers
    - key = value pairs
    - multi-line values (continuation lines starting with whitespace)
    - Comments (# and ;)
    - Empty lines
    """
    stanzas: Stanzas = {}
    current_stanza = "default"
    current_key: str | None = None
    stanzas[current_stanza] = {}

    if not path.exists():
        logger.debug("Conf file not found: %s", path)
        return {}

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return {}

    for line_num, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()

        # Skip empty lines and comments
        if not line or line.lstrip().startswith("#") or line.lstrip().startswith(";"):
            current_key = None
            continue

        # Continuation line (starts with whitespace and we have a current key)
        if line[0] in (" ", "\t") and current_key is not None:
            prev = stanzas[current_stanza].get(current_key, "")
            stanzas[current_stanza][current_key] = prev + "\n" + line.strip()
            continue

        # Stanza header
        if line.startswith("[") and "]" in line:
            stanza_name = line[1 : line.index("]")].strip()
            current_stanza = stanza_name
            if current_stanza not in stanzas:
                stanzas[current_stanza] = {}
            current_key = None
            continue

        # Key-value pair
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            stanzas[current_stanza][key] = value
            current_key = key
            continue

        # Unrecognized line — log and skip
        logger.debug("Skipping unrecognized line %d in %s: %s", line_num, path, line)
        current_key = None

    # Remove the default stanza if empty
    if not stanzas.get("default"):
        stanzas.pop("default", None)

    return stanzas


def merge_stanzas(default: Stanzas, local: Stanzas) -> Stanzas:
    """Merge local stanzas over default stanzas (Splunk precedence)."""
    merged: Stanzas = {}

    all_keys = set(default) | set(local)
    for stanza in all_keys:
        merged[stanza] = {}
        if stanza in default:
            merged[stanza].update(default[stanza])
        if stanza in local:
            merged[stanza].update(local[stanza])

    return merged
