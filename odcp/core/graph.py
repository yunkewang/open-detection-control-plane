"""Dependency graph engine using NetworkX."""

from __future__ import annotations

import networkx as nx

from odcp.models import Dependency, Detection


class DependencyGraph:
    """Directed graph linking detections to their dependencies."""

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    # --- Construction ---

    def add_detection(self, detection: Detection) -> None:
        self._g.add_node(detection.id, type="detection", name=detection.name)

    def add_dependency(self, dependency: Dependency) -> None:
        self._g.add_node(
            dependency.id,
            type="dependency",
            name=dependency.name,
            kind=dependency.kind.value,
            status=dependency.status.value,
        )

    def add_edge(self, detection_id: str, dependency_id: str) -> None:
        self._g.add_edge(detection_id, dependency_id)

    def build_from_scan(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
    ) -> None:
        """Build the graph from scan results."""
        dep_index: dict[str, Dependency] = {d.id: d for d in dependencies}

        for det in detections:
            self.add_detection(det)

        for dep in dependencies:
            self.add_dependency(dep)

        for det in detections:
            for ref_id in det.references:
                if ref_id in dep_index:
                    self.add_edge(det.id, ref_id)

    # --- Queries ---

    def get_detection_dependencies(self, detection_id: str) -> list[str]:
        """Return dependency IDs for a detection."""
        if detection_id not in self._g:
            return []
        return list(self._g.successors(detection_id))

    def get_dependency_dependents(self, dependency_id: str) -> list[str]:
        """Return detection IDs that depend on this dependency."""
        if dependency_id not in self._g:
            return []
        return list(self._g.predecessors(dependency_id))

    def get_orphaned_dependencies(self) -> list[str]:
        """Return dependency IDs that no detection references."""
        orphaned = []
        for node, data in self._g.nodes(data=True):
            if data.get("type") == "dependency" and self._g.in_degree(node) == 0:
                orphaned.append(node)
        return orphaned

    def get_most_depended_on(self, top_n: int = 10) -> list[tuple[str, str, int]]:
        """Return (id, name, count) of most-referenced dependencies."""
        deps = []
        for node, data in self._g.nodes(data=True):
            if data.get("type") == "dependency":
                count = self._g.in_degree(node)
                deps.append((node, data.get("name", ""), count))
        deps.sort(key=lambda x: x[2], reverse=True)
        return deps[:top_n]

    def to_dict(self) -> dict:
        """Serialize graph summary to dict."""
        return {
            "node_count": self._g.number_of_nodes(),
            "edge_count": self._g.number_of_edges(),
            "detections": sum(
                1 for _, d in self._g.nodes(data=True) if d.get("type") == "detection"
            ),
            "dependencies": sum(
                1 for _, d in self._g.nodes(data=True) if d.get("type") == "dependency"
            ),
        }

    @property
    def node_count(self) -> int:
        return self._g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._g.number_of_edges()
