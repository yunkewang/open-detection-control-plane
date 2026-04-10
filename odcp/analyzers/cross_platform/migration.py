"""Detection migration analyzer.

Evaluates the feasibility and complexity of migrating detections from
one SIEM/platform to another, identifying blockers, estimating effort,
and mapping feature equivalents.
"""

from __future__ import annotations

import logging
import re

from odcp.models import Detection, ScanReport
from odcp.models.cross_platform import (
    DetectionMigrationResult,
    MigrationBlocker,
    MigrationComplexity,
    MigrationSummary,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature / query-language capability maps
# ---------------------------------------------------------------------------

_PLATFORM_CAPABILITIES: dict[str, set[str]] = {
    "splunk": {
        "spl", "regex", "stats", "eval", "lookup", "macro",
        "subsearch", "join", "transaction", "tstats", "datamodel",
        "outputlookup", "inputlookup", "eventtype", "tag",
        "alert_action", "cron_schedule",
    },
    "sigma": {
        "logsource_abstraction", "field_modifiers", "condition_logic",
        "correlation", "filter", "yaml_format", "vendor_agnostic",
    },
    "elastic": {
        "eql", "kql", "lucene", "esql", "threshold_rule",
        "machine_learning", "indicator_match", "new_terms",
        "index_pattern", "runtime_field", "exception_list",
    },
    "sentinel": {
        "kql", "analytics_rule", "fusion", "nrt_rule",
        "entity_mapping", "alert_grouping", "playbook_trigger",
        "watchlist", "threat_intelligence", "data_connector",
    },
    "chronicle": {
        "yaral", "udm", "reference_list", "outcome_variable",
        "match_section", "event_variable", "regex",
        "multi_event_correlation", "function_calls",
    },
}

# Pairwise feature mappings: (source_platform, target_platform) -> {src_feature: target_feature | None}
_FEATURE_MAPPINGS: dict[tuple[str, str], dict[str, str | None]] = {
    ("splunk", "chronicle"): {
        "spl": "yaral",
        "regex": "regex",
        "stats": "outcome_variable",
        "lookup": "reference_list",
        "macro": None,
        "subsearch": None,
        "join": "multi_event_correlation",
        "transaction": "multi_event_correlation",
        "datamodel": "udm",
        "eventtype": None,
        "tag": None,
    },
    ("splunk", "elastic"): {
        "spl": "kql",
        "regex": "lucene",
        "stats": "threshold_rule",
        "lookup": "indicator_match",
        "macro": None,
        "subsearch": None,
        "join": "eql",
        "datamodel": "index_pattern",
    },
    ("splunk", "sentinel"): {
        "spl": "kql",
        "regex": "kql",
        "stats": "analytics_rule",
        "lookup": "watchlist",
        "macro": None,
        "subsearch": None,
        "join": "kql",
        "datamodel": "data_connector",
    },
    ("sigma", "chronicle"): {
        "logsource_abstraction": "udm",
        "field_modifiers": "regex",
        "condition_logic": "yaral",
        "correlation": "multi_event_correlation",
        "vendor_agnostic": "yaral",
    },
    ("sigma", "elastic"): {
        "logsource_abstraction": "index_pattern",
        "field_modifiers": "kql",
        "condition_logic": "kql",
        "correlation": "threshold_rule",
        "vendor_agnostic": "kql",
    },
    ("sigma", "sentinel"): {
        "logsource_abstraction": "data_connector",
        "field_modifiers": "kql",
        "condition_logic": "kql",
        "correlation": "analytics_rule",
        "vendor_agnostic": "kql",
    },
    ("elastic", "chronicle"): {
        "kql": "yaral",
        "eql": "yaral",
        "threshold_rule": "outcome_variable",
        "indicator_match": "reference_list",
        "machine_learning": None,
        "index_pattern": "udm",
        "exception_list": None,
    },
    ("elastic", "sentinel"): {
        "kql": "kql",
        "eql": "kql",
        "threshold_rule": "analytics_rule",
        "indicator_match": "threat_intelligence",
        "machine_learning": "fusion",
        "index_pattern": "data_connector",
    },
    ("sentinel", "chronicle"): {
        "kql": "yaral",
        "analytics_rule": "yaral",
        "fusion": None,
        "nrt_rule": "yaral",
        "watchlist": "reference_list",
        "entity_mapping": "udm",
        "data_connector": "udm",
        "playbook_trigger": None,
    },
    ("chronicle", "splunk"): {
        "yaral": "spl",
        "udm": "datamodel",
        "reference_list": "lookup",
        "outcome_variable": "stats",
        "match_section": "transaction",
        "multi_event_correlation": "join",
        "regex": "regex",
    },
    ("chronicle", "elastic"): {
        "yaral": "eql",
        "udm": "index_pattern",
        "reference_list": "indicator_match",
        "outcome_variable": "threshold_rule",
        "multi_event_correlation": "eql",
        "regex": "lucene",
    },
    ("chronicle", "sentinel"): {
        "yaral": "kql",
        "udm": "data_connector",
        "reference_list": "watchlist",
        "outcome_variable": "analytics_rule",
        "multi_event_correlation": "kql",
        "regex": "kql",
    },
}

# Effort estimates by complexity (hours per detection)
_EFFORT_MAP: dict[MigrationComplexity, float] = {
    MigrationComplexity.trivial: 0.5,
    MigrationComplexity.low: 2.0,
    MigrationComplexity.medium: 6.0,
    MigrationComplexity.high: 16.0,
    MigrationComplexity.infeasible: 0.0,
}

# Patterns that indicate higher complexity
_COMPLEX_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "splunk": [
        re.compile(r"\bjoin\b", re.IGNORECASE),
        re.compile(r"\btransaction\b", re.IGNORECASE),
        re.compile(r"\bsubsearch\b", re.IGNORECASE),
        re.compile(r"`\w+`"),  # macro invocation
    ],
    "elastic": [
        re.compile(r'"type"\s*:\s*"machine_learning"'),
        re.compile(r'"type"\s*:\s*"new_terms"'),
    ],
    "sentinel": [
        re.compile(r"\bunion\b", re.IGNORECASE),
        re.compile(r"\bjoin\b", re.IGNORECASE),
    ],
    "chronicle": [
        re.compile(r"match\s*:.*over", re.IGNORECASE | re.DOTALL),
        re.compile(r"%\w+"),  # reference list usage
    ],
}


class MigrationAnalyzer:
    """Analyze feasibility and effort of migrating detections between platforms."""

    def analyze(
        self,
        source_report: ScanReport,
        target_platform: str,
    ) -> MigrationSummary:
        """Analyze migration of all detections from a source report to a target platform."""
        source_platform = self._get_platform_name(source_report)
        results: list[DetectionMigrationResult] = []

        for det in source_report.detections:
            result = self._analyze_detection(det, source_platform, target_platform)
            results.append(result)

        # Summarize
        total = len(results)
        trivial = sum(1 for r in results if r.complexity == MigrationComplexity.trivial)
        low = sum(1 for r in results if r.complexity == MigrationComplexity.low)
        medium = sum(1 for r in results if r.complexity == MigrationComplexity.medium)
        high = sum(1 for r in results if r.complexity == MigrationComplexity.high)
        infeasible = sum(1 for r in results if r.complexity == MigrationComplexity.infeasible)

        feasible_results = [r for r in results if r.complexity != MigrationComplexity.infeasible]
        overall_feasibility = (
            sum(r.feasibility_score for r in feasible_results) / len(feasible_results)
            if feasible_results
            else 0.0
        )

        total_hours = sum(r.effort_hours or 0 for r in results)

        # Common blockers
        blocker_counts: dict[str, int] = {}
        all_blockers: dict[str, MigrationBlocker] = {}
        for r in results:
            for b in r.blockers:
                key = f"{b.category}:{b.description}"
                blocker_counts[key] = blocker_counts.get(key, 0) + 1
                all_blockers[key] = b
        common_blockers = [
            all_blockers[key]
            for key, count in sorted(blocker_counts.items(), key=lambda x: -x[1])
            if count >= 2
        ][:10]

        return MigrationSummary(
            source_platform=source_platform,
            target_platform=target_platform,
            total_detections=total,
            trivial=trivial,
            low_complexity=low,
            medium_complexity=medium,
            high_complexity=high,
            infeasible=infeasible,
            overall_feasibility=round(overall_feasibility, 3),
            estimated_total_hours=round(total_hours, 1),
            common_blockers=common_blockers,
            detection_results=results,
        )

    def _analyze_detection(
        self,
        detection: Detection,
        source_platform: str,
        target_platform: str,
    ) -> DetectionMigrationResult:
        """Analyze migration feasibility for a single detection."""
        # Determine feature mapping
        mapping = _FEATURE_MAPPINGS.get((source_platform, target_platform), {})

        # Detect features used in this detection
        used_features = self._detect_used_features(detection, source_platform)

        mapped: list[str] = []
        unmapped: list[str] = []
        blockers: list[MigrationBlocker] = []

        for feature in used_features:
            target_equiv = mapping.get(feature)
            if target_equiv is not None:
                mapped.append(f"{feature} -> {target_equiv}")
            else:
                unmapped.append(feature)
                blockers.append(MigrationBlocker(
                    category="platform_feature",
                    description=f"No direct equivalent for '{feature}' on {target_platform}",
                    severity="medium",
                ))

        # Check query complexity
        complexity_hits = self._check_query_complexity(detection, source_platform)
        for hit in complexity_hits:
            blockers.append(MigrationBlocker(
                category="query_language",
                description=f"Complex query pattern detected: {hit}",
                severity="medium",
            ))

        # Check data source compatibility
        ds_blockers = self._check_data_source_compatibility(
            detection, source_platform, target_platform
        )
        blockers.extend(ds_blockers)

        # Calculate complexity and feasibility
        complexity = self._calculate_complexity(
            len(mapped), len(unmapped), len(blockers), complexity_hits
        )
        feasibility = self._calculate_feasibility(
            len(mapped), len(unmapped), len(blockers)
        )
        effort = _EFFORT_MAP.get(complexity, 6.0)

        return DetectionMigrationResult(
            detection_id=detection.id,
            detection_name=detection.name,
            source_platform=source_platform,
            target_platform=target_platform,
            complexity=complexity,
            feasibility_score=round(feasibility, 3),
            blockers=blockers,
            mapped_features=mapped,
            unmapped_features=unmapped,
            effort_hours=effort,
        )

    @staticmethod
    def _get_platform_name(report: ScanReport) -> str:
        """Extract the platform name from a scan report."""
        if report.environment.platforms:
            return report.environment.platforms[0].name
        return "unknown"

    @staticmethod
    def _detect_used_features(detection: Detection, platform: str) -> list[str]:
        """Detect which platform features a detection uses."""
        capabilities = _PLATFORM_CAPABILITIES.get(platform, set())
        used: list[str] = []
        query = detection.search_query.lower()
        meta = detection.metadata

        if platform == "splunk":
            if "`" in query:
                used.append("macro")
            if "lookup" in query or "inputlookup" in query:
                used.append("lookup")
            if "join" in query:
                used.append("join")
            if "transaction" in query:
                used.append("transaction")
            if "tstats" in query or "datamodel" in query:
                used.append("datamodel")
            if "stats" in query or "eval" in query:
                used.append("stats")
            if "regex" in query or "rex " in query:
                used.append("regex")
            if not used:
                used.append("spl")

        elif platform == "sigma":
            if meta.get("logsource"):
                used.append("logsource_abstraction")
            if "condition" in query:
                used.append("condition_logic")
            if any(mod in query for mod in ("|contains", "|endswith", "|startswith")):
                used.append("field_modifiers")

        elif platform == "elastic":
            rule_type = meta.get("type", "query")
            lang = meta.get("language", "")
            if lang == "eql" or rule_type == "eql":
                used.append("eql")
            elif lang == "kuery" or rule_type == "query":
                used.append("kql")
            if rule_type == "threshold":
                used.append("threshold_rule")
            if rule_type == "machine_learning":
                used.append("machine_learning")
            if rule_type == "indicator_match" or rule_type == "threat_match":
                used.append("indicator_match")
            if meta.get("index_patterns"):
                used.append("index_pattern")

        elif platform == "sentinel":
            used.append("kql")
            if meta.get("kind") == "NRT":
                used.append("nrt_rule")
            elif meta.get("kind") == "Fusion":
                used.append("fusion")
            else:
                used.append("analytics_rule")
            if meta.get("data_connectors"):
                used.append("data_connector")
            if "join" in query:
                used.append("kql")  # complex KQL
            if meta.get("tactics"):
                used.append("entity_mapping")

        elif platform == "chronicle":
            used.append("yaral")
            if meta.get("udm_entities"):
                used.append("udm")
            if meta.get("reference_lists"):
                used.append("reference_list")
            if meta.get("has_outcome"):
                used.append("outcome_variable")
            if meta.get("match_section"):
                used.append("match_section")
            if meta.get("functions_used"):
                used.append("function_calls")

        # Deduplicate while preserving order
        seen: set[str] = set()
        result: list[str] = []
        for f in used:
            if f not in seen and f in capabilities:
                seen.add(f)
                result.append(f)
        return result

    @staticmethod
    def _check_query_complexity(
        detection: Detection, source_platform: str,
    ) -> list[str]:
        """Check for complex query patterns that increase migration difficulty."""
        patterns = _COMPLEX_PATTERNS.get(source_platform, [])
        query = detection.search_query
        hits: list[str] = []
        for pattern in patterns:
            if pattern.search(query):
                hits.append(pattern.pattern)
        return hits

    @staticmethod
    def _check_data_source_compatibility(
        detection: Detection,
        source_platform: str,
        target_platform: str,
    ) -> list[MigrationBlocker]:
        """Check if the detection's data sources are available on the target."""
        blockers: list[MigrationBlocker] = []
        meta = detection.metadata

        # Platform-specific data source checks
        if source_platform == "splunk":
            if meta.get("data_model"):
                blockers.append(MigrationBlocker(
                    category="data_source",
                    description="Splunk data model requires mapping to target data schema",
                    severity="medium",
                ))
        elif source_platform == "sentinel":
            for conn in meta.get("data_connectors", []):
                if target_platform != "sentinel":
                    blockers.append(MigrationBlocker(
                        category="data_source",
                        description=f"Sentinel data connector '{conn}' needs equivalent on {target_platform}",
                        severity="low",
                    ))
        elif source_platform == "chronicle":
            if meta.get("reference_lists"):
                if target_platform not in ("chronicle",):
                    blockers.append(MigrationBlocker(
                        category="data_source",
                        description="Chronicle reference lists need equivalent lookup mechanism",
                        severity="low",
                    ))

        return blockers

    @staticmethod
    def _calculate_complexity(
        mapped_count: int,
        unmapped_count: int,
        blocker_count: int,
        complexity_hits: list[str],
    ) -> MigrationComplexity:
        """Calculate migration complexity based on feature analysis."""
        total_features = mapped_count + unmapped_count
        if total_features == 0:
            return MigrationComplexity.trivial

        unmapped_ratio = unmapped_count / total_features if total_features > 0 else 0

        if unmapped_ratio > 0.5 and unmapped_count >= 3:
            return MigrationComplexity.infeasible
        if unmapped_ratio > 0.3 or blocker_count >= 4:
            return MigrationComplexity.high
        if unmapped_count >= 1 or complexity_hits or blocker_count >= 2:
            return MigrationComplexity.medium
        if blocker_count >= 1:
            return MigrationComplexity.low
        return MigrationComplexity.trivial

    @staticmethod
    def _calculate_feasibility(
        mapped_count: int,
        unmapped_count: int,
        blocker_count: int,
    ) -> float:
        """Calculate a feasibility score between 0.0 and 1.0."""
        total = mapped_count + unmapped_count
        if total == 0:
            return 1.0

        # Base score from feature mapping coverage
        base = mapped_count / total

        # Penalty for blockers (diminishing returns)
        penalty = min(blocker_count * 0.1, 0.5)

        return max(0.0, min(1.0, base - penalty))
