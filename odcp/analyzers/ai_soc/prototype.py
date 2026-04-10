"""Environment-aware AI SOC prototype analyzer."""

from __future__ import annotations

from odcp.analyzers.coverage.data_sources import (
    extract_datamodel_references,
    extract_index_references,
    extract_sourcetype_references,
)
from odcp.models.ai_soc import (
    AiSocPrototypeSummary,
    AutomationActionItem,
    DataSourceCapability,
    DetectionDataDecision,
)
from odcp.models.dependency import DependencyStatus
from odcp.models.report import ScanReport
from odcp.models.scoring import ReadinessStatus


class AiSocPrototypeAnalyzer:
    """Builds a data-aware prototype plan for AI-assisted SOC operations."""

    def analyze(self, report: ScanReport) -> AiSocPrototypeSummary:
        capabilities = self._build_data_source_capabilities(report)
        observed_sources = {
            f"{s.source_type}:{s.name}"
            for s in capabilities
            if s.observed
        }

        decisions: list[DetectionDataDecision] = []
        score_map = {s.detection_id: s for s in report.readiness_scores}

        counts = {
            "detectable": 0,
            "blocked_data_gap": 0,
            "blocked_logic_gap": 0,
            "unknown": 0,
        }

        for det in report.detections:
            readiness = score_map.get(det.id)
            required = self._extract_required_sources(det.search_query)
            missing = [src for src in required if src not in observed_sources]
            data_supported = len(required) == 0 or len(missing) == 0

            if readiness is None or readiness.status == ReadinessStatus.unknown:
                decision = "unknown"
                confidence = 0.4
                rationale = "No readiness score available to determine feasibility."
            elif readiness.status == ReadinessStatus.blocked and missing:
                decision = "blocked_data_gap"
                confidence = 0.95
                rationale = "Detection is blocked and its required data sources are not observed."
            elif readiness.status == ReadinessStatus.blocked:
                decision = "blocked_logic_gap"
                confidence = 0.8
                rationale = (
                    "Detection is blocked despite data source coverage; "
                    "dependency or query logic remediation is required."
                )
            elif missing:
                decision = "blocked_data_gap"
                confidence = 0.75
                rationale = "Detection references unavailable data sources and may fail in runtime."
            else:
                decision = "detectable"
                confidence = 0.9
                rationale = "Detection has readiness support and required data sources are observed."

            counts[decision] += 1
            decisions.append(
                DetectionDataDecision(
                    detection_id=det.id,
                    detection_name=det.name,
                    decision=decision,
                    data_supported=data_supported,
                    confidence=confidence,
                    required_data_sources=required,
                    missing_data_sources=missing,
                    rationale=rationale,
                )
            )

        next_actions = self._build_next_actions(report, decisions)

        return AiSocPrototypeSummary(
            environment_name=report.environment.name,
            total_detections=len(report.detections),
            detectable_now=counts["detectable"],
            blocked_by_data=counts["blocked_data_gap"],
            blocked_by_logic=counts["blocked_logic_gap"],
            unknown=counts["unknown"],
            data_source_catalog=capabilities,
            detection_decisions=decisions,
            next_actions=next_actions,
        )

    def _build_data_source_capabilities(
        self, report: ScanReport
    ) -> list[DataSourceCapability]:
        inventory = report.metadata.get("data_source_inventory", {})
        from_inventory = inventory.get("sources", [])

        capabilities: list[DataSourceCapability] = []
        if from_inventory:
            for src in from_inventory:
                source_type = src.get("source_type", "unknown")
                name = src.get("name", "unknown")
                capabilities.append(
                    DataSourceCapability(
                        name=name,
                        source_type=source_type,
                        observed=src.get("observed", False),
                        detection_count=src.get("detection_count", 0),
                        provides=self._default_provides(source_type, name),
                    )
                )
            return capabilities

        # Fallback when coverage inventory wasn't enabled.
        observed_data_models = {
            d.name for d in report.dependencies
            if d.kind.value == "data_model" and d.status == DependencyStatus.resolved
        }

        for dep in report.dependencies:
            if dep.kind.value != "data_model":
                continue
            capabilities.append(
                DataSourceCapability(
                    name=dep.name,
                    source_type="data_model",
                    observed=dep.name in observed_data_models,
                    provides=self._default_provides("data_model", dep.name),
                )
            )
        return capabilities

    def _extract_required_sources(self, query: str) -> list[str]:
        required: list[str] = []
        required.extend(f"index:{i}" for i in extract_index_references(query))
        required.extend(f"sourcetype:{s}" for s in extract_sourcetype_references(query))
        required.extend(f"data_model:{d}" for d in extract_datamodel_references(query))
        return required

    def _build_next_actions(
        self,
        report: ScanReport,
        decisions: list[DetectionDataDecision],
    ) -> list[AutomationActionItem]:
        missing_sources = sorted(
            {src for d in decisions for src in d.missing_data_sources}
        )

        actions = [
            AutomationActionItem(
                phase="environment-awareness",
                priority="high",
                action="Continuously refresh data source inventory from SIEM APIs and log onboarding metadata.",
            ),
            AutomationActionItem(
                phase="threat-intel-ingestion",
                priority="high",
                action="Schedule ATT&CK/STIX intelligence refresh and map new TTPs to supported data sources.",
            ),
            AutomationActionItem(
                phase="detection-generation",
                priority="high",
                action="Gate detection creation/migration with data support checks before enabling in production.",
            ),
            AutomationActionItem(
                phase="detection-validation",
                priority="medium",
                action="Run automated post-deploy verification (execution status, false-positive drift, and alert volume health).",
            ),
        ]

        if missing_sources:
            actions.insert(
                1,
                AutomationActionItem(
                    phase="data-onboarding",
                    priority="high",
                    action=(
                        "Prioritize onboarding or fixing these missing sources: "
                        f"{', '.join(missing_sources[:8])}"
                    ),
                ),
            )

        if any(d.decision == "blocked_logic_gap" for d in decisions):
            actions.append(
                AutomationActionItem(
                    phase="content-engineering",
                    priority="medium",
                    action="Create backlog for blocked detections with adequate data support but unresolved logic/dependency issues.",
                )
            )

        if report.metadata.get("runtime_enabled"):
            actions.append(
                AutomationActionItem(
                    phase="runtime-assurance",
                    priority="high",
                    action="Keep runtime health scans in CI/CD to detect scheduling failures and data model degradation early.",
                )
            )

        return actions

    def _default_provides(self, source_type: str, name: str) -> list[str]:
        if source_type == "index":
            return [f"Raw events from index '{name}'", "Historical search context"]
        if source_type == "sourcetype":
            return [f"Normalized event stream '{name}'", "Field-level detection pivots"]
        if source_type == "data_model":
            return [f"Accelerated CIM/UDM-like model '{name}'", "Stats/tstats-compatible aggregations"]
        return [f"Telemetry feed '{name}'"]
