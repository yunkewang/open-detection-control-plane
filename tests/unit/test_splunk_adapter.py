"""Tests for Splunk adapter behavior beyond parsing basics."""

from pathlib import Path

from odcp.adapters.splunk import SplunkAdapter
from odcp.models import DependencyKind, Detection


def _write_conf(path: Path, filename: str, content: str) -> None:
    conf = path / "default" / filename
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(content)


def test_tags_conf_creates_tag_knowledge_objects(tmp_path: Path):
    adapter = SplunkAdapter()
    _write_conf(
        tmp_path,
        "tags.conf",
        """
[eventtype=authentication]
critical = enabled
noise = 0

[source::WinEventLog:Security]
identity = 1
""".strip(),
    )

    objects = adapter.parse_knowledge_objects(tmp_path)
    tag_names = {o.name for o in objects if o.kind == DependencyKind.tag}

    assert "critical" in tag_names
    assert "identity" in tag_names
    assert "noise" not in tag_names


def test_lookup_dependency_marked_degraded_when_backing_csv_missing(tmp_path: Path):
    adapter = SplunkAdapter()
    _write_conf(
        tmp_path,
        "transforms.conf",
        """
[threat_lookup]
filename = threat_lookup.csv
""".strip(),
    )

    detections = [
        Detection(name="Lookup Rule", search_query="index=main | lookup threat_lookup ip")
    ]
    dependencies = adapter.resolve_dependencies(
        detections,
        adapter.parse_knowledge_objects(tmp_path),
    )

    lookup_dep = next(d for d in dependencies if d.kind == DependencyKind.lookup)
    assert lookup_dep.name == "threat_lookup"
    assert lookup_dep.status.value == "degraded"


def test_lookup_dependency_resolved_when_backing_csv_exists(tmp_path: Path):
    adapter = SplunkAdapter()
    _write_conf(
        tmp_path,
        "transforms.conf",
        """
[asset_lookup]
filename = assets.csv
""".strip(),
    )
    (tmp_path / "lookups").mkdir(parents=True, exist_ok=True)
    (tmp_path / "lookups" / "assets.csv").write_text("host,criticality\n")

    detections = [Detection(name="Asset Rule", search_query="| lookup asset_lookup host")]
    dependencies = adapter.resolve_dependencies(
        detections,
        adapter.parse_knowledge_objects(tmp_path),
    )

    lookup_dep = next(d for d in dependencies if d.kind == DependencyKind.lookup)
    assert lookup_dep.status.value == "resolved"
