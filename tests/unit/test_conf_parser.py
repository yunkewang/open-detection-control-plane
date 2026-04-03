"""Tests for Splunk .conf file parsing."""

import textwrap
from pathlib import Path

import pytest

from odcp.adapters.splunk.parser import merge_stanzas, parse_conf_file


@pytest.fixture
def tmp_conf(tmp_path):
    """Helper to write a conf file and return its path."""
    def _write(content: str) -> Path:
        p = tmp_path / "test.conf"
        p.write_text(textwrap.dedent(content))
        return p
    return _write


class TestParseConfFile:
    def test_basic_stanza(self, tmp_conf):
        p = tmp_conf("""\
        [my_search]
        search = index=main | stats count
        disabled = 0
        """)
        result = parse_conf_file(p)
        assert "my_search" in result
        assert result["my_search"]["search"] == "index=main | stats count"
        assert result["my_search"]["disabled"] == "0"

    def test_multiple_stanzas(self, tmp_conf):
        p = tmp_conf("""\
        [search_one]
        search = index=main

        [search_two]
        search = index=web
        """)
        result = parse_conf_file(p)
        assert "search_one" in result
        assert "search_two" in result

    def test_comments_ignored(self, tmp_conf):
        p = tmp_conf("""\
        # This is a comment
        [my_stanza]
        ; Another comment
        key = value
        """)
        result = parse_conf_file(p)
        assert result["my_stanza"]["key"] == "value"

    def test_multiline_value(self, tmp_conf):
        p = tmp_conf("""\
        [my_search]
        search = index=main \\
          | stats count by host \\
          | sort -count
        """)
        result = parse_conf_file(p)
        # Continuation lines should be joined
        assert "stats count by host" in result["my_search"]["search"]

    def test_empty_file(self, tmp_conf):
        p = tmp_conf("")
        result = parse_conf_file(p)
        assert result == {} or all(not v for v in result.values())

    def test_missing_file(self, tmp_path):
        result = parse_conf_file(tmp_path / "nonexistent.conf")
        assert result == {}


class TestMergeStanzas:
    def test_local_overrides_default(self):
        default = {"search1": {"search": "old_query", "disabled": "0"}}
        local = {"search1": {"search": "new_query"}}
        merged = merge_stanzas(default, local)
        assert merged["search1"]["search"] == "new_query"
        assert merged["search1"]["disabled"] == "0"  # preserved from default

    def test_local_adds_new_stanza(self):
        default = {"search1": {"search": "query1"}}
        local = {"search2": {"search": "query2"}}
        merged = merge_stanzas(default, local)
        assert "search1" in merged
        assert "search2" in merged

    def test_empty_merge(self):
        assert merge_stanzas({}, {}) == {}
