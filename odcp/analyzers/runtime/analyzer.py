"""Runtime health analyzer — scores detections based on live Splunk signals."""

from __future__ import annotations

import logging

from odcp.collectors.api import RuntimeData
from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    DependencyKind,
    Detection,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReadinessScore,
    RemediationAction,
)
from odcp.models.runtime import (
    CombinedReadinessScore,
    RuntimeHealthScore,
    RuntimeHealthStatus,
    RuntimeHealthSummary,
    RuntimeSignal,
)

logger = logging.getLogger(__name__)


class RuntimeHealthAnalyzer:
    """Analyzes runtime health signals and produces scores and findings.

    This analyzer uses live data collected from the Splunk REST API
    to determine whether detections are actually executing, whether
    their dependencies are healthy at runtime, and what the combined
    static + runtime readiness looks like.
    """

    def analyze(
        self,
        detections: list[Detection],
        dependencies: list[Dependency],
        runtime_data: RuntimeData,
        graph: DependencyGraph,
    ) -> tuple[list[RuntimeHealthScore], list[Finding]]:
        """Analyze runtime health for all detections.

        Returns runtime health scores and any runtime-specific findings.
        """
        dep_index: dict[str, Dependency] = {d.id: d for d in dependencies}
        scores: list[RuntimeHealthScore] = []
        findings: list[Finding] = []

        for det in detections:
            signals: list[RuntimeSignal] = []

            # 1. Check saved search execution status
            ss_signals, ss_findings = self._check_saved_search(det, runtime_data)
            signals.extend(ss_signals)
            findings.extend(ss_findings)

            # 2. Check dependency-level runtime health
            dep_ids = graph.get_detection_dependencies(det.id)
            det_deps = [dep_index[d] for d in dep_ids if d in dep_index]

            for dep in det_deps:
                dep_signals, dep_findings = self._check_dependency_health(
                    det, dep, runtime_data
                )
                signals.extend(dep_signals)
                findings.extend(dep_findings)

            # Compute runtime score from signals
            runtime_status, runtime_score = self._compute_runtime_score(signals)

            scores.append(
                RuntimeHealthScore(
                    detection_id=det.id,
                    detection_name=det.name,
                    runtime_status=runtime_status,
                    runtime_score=round(runtime_score, 3),
                    signals=signals,
                )
            )

        return scores, findings

    def compute_combined_scores(
        self,
        static_scores: list[ReadinessScore],
        runtime_scores: list[RuntimeHealthScore],
        static_weight: float = 0.5,
        runtime_weight: float = 0.5,
    ) -> list[CombinedReadinessScore]:
        """Merge static readiness scores with runtime health scores."""
        runtime_index = {s.detection_id: s for s in runtime_scores}
        combined: list[CombinedReadinessScore] = []

        for ss in static_scores:
            rs = runtime_index.get(ss.detection_id)
            r_score = rs.runtime_score if rs else 0.0
            r_status = rs.runtime_status.value if rs else "unknown"

            c_score = (ss.score * static_weight) + (r_score * runtime_weight)
            c_status = self._derive_combined_status(ss.status.value, r_status)

            combined.append(
                CombinedReadinessScore(
                    detection_id=ss.detection_id,
                    detection_name=ss.detection_name,
                    static_score=ss.score,
                    runtime_score=r_score,
                    combined_score=round(c_score, 3),
                    static_status=ss.status.value,
                    runtime_status=r_status,
                    combined_status=c_status,
                )
            )

        return combined

    def compute_runtime_summary(
        self, scores: list[RuntimeHealthScore]
    ) -> RuntimeHealthSummary:
        """Compute aggregate runtime health summary."""
        total = len(scores)
        if total == 0:
            return RuntimeHealthSummary()

        healthy = sum(1 for s in scores if s.runtime_status == RuntimeHealthStatus.healthy)
        degraded = sum(1 for s in scores if s.runtime_status == RuntimeHealthStatus.degraded)
        unhealthy = sum(1 for s in scores if s.runtime_status == RuntimeHealthStatus.unhealthy)
        unknown = sum(1 for s in scores if s.runtime_status == RuntimeHealthStatus.unknown)
        avg = sum(s.runtime_score for s in scores) / total

        # Count signal types checked
        all_signals = [sig for s in scores for sig in s.signals]
        ss_checked = len({s.detection_id for s in scores if any(
            sig.signal_type == "saved_search" for sig in s.signals
        )})
        lookup_names = {
            sig.title.split(": ")[-1] for sig in all_signals
            if sig.signal_type == "lookup"
        }
        dm_names = {
            sig.title.split(": ")[-1] for sig in all_signals
            if sig.signal_type == "data_model"
        }
        idx_names = {
            sig.title.split(": ")[-1] for sig in all_signals
            if sig.signal_type == "index"
        }

        return RuntimeHealthSummary(
            total_detections=total,
            healthy=healthy,
            degraded=degraded,
            unhealthy=unhealthy,
            unknown=unknown,
            overall_runtime_score=round(avg, 3),
            saved_searches_checked=ss_checked,
            lookups_checked=len(lookup_names),
            data_models_checked=len(dm_names),
            indexes_checked=len(idx_names),
        )

    # ------------------------------------------------------------------
    # Private: saved search checks
    # ------------------------------------------------------------------

    def _check_saved_search(
        self, det: Detection, runtime_data: RuntimeData
    ) -> tuple[list[RuntimeSignal], list[Finding]]:
        signals: list[RuntimeSignal] = []
        findings: list[Finding] = []

        health = runtime_data.saved_search_health.get(det.name)
        if not health:
            signals.append(
                RuntimeSignal(
                    detection_id=det.id,
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.unknown,
                    title=f"Saved search not found: {det.name}",
                    detail="Could not retrieve execution status from Splunk API.",
                )
            )
            return signals, findings

        # Check scheduling
        if not health.is_scheduled and det.enabled:
            signals.append(
                RuntimeSignal(
                    detection_id=det.id,
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.degraded,
                    title=f"Not scheduled: {det.name}",
                    detail="Detection is enabled but not scheduled to run.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    category=FindingCategory.runtime_health,
                    severity=FindingSeverity.high,
                    title=f"Detection not scheduled: {det.name}",
                    description=(
                        f"Detection '{det.name}' is enabled but not scheduled "
                        f"in Splunk. It will not execute automatically."
                    ),
                    remediation=RemediationAction(
                        title=f"Schedule detection '{det.name}'",
                        description="Configure a cron schedule for this saved search.",
                        effort="low",
                        steps=[
                            "Edit the saved search in Splunk",
                            "Enable scheduling and set an appropriate cron schedule",
                            "Verify the search runs on the next scheduled interval",
                        ],
                    ),
                )
            )
        else:
            signals.append(
                RuntimeSignal(
                    detection_id=det.id,
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.healthy,
                    title=f"Scheduled: {det.name}",
                    detail="Detection is scheduled to run.",
                )
            )

        # Check recent dispatch history for failures
        history = runtime_data.saved_search_history.get(det.name, [])
        failed_runs = [h for h in history if h.get("is_failed")]
        if failed_runs:
            signals.append(
                RuntimeSignal(
                    detection_id=det.id,
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.unhealthy,
                    title=f"Recent failures: {det.name}",
                    detail=f"{len(failed_runs)} of {len(history)} recent runs failed.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    category=FindingCategory.stale_execution,
                    severity=FindingSeverity.critical,
                    title=f"Detection has recent failures: {det.name}",
                    description=(
                        f"Detection '{det.name}' has {len(failed_runs)} failed "
                        f"executions out of the last {len(history)} runs."
                    ),
                    remediation=RemediationAction(
                        title=f"Investigate failures for '{det.name}'",
                        description="Review the search job inspector for error details.",
                        effort="medium",
                        steps=[
                            "Open the search job inspector in Splunk",
                            "Review the error messages from failed runs",
                            "Fix the underlying search or permission issue",
                            "Verify the detection runs successfully",
                        ],
                    ),
                )
            )
        elif history:
            signals.append(
                RuntimeSignal(
                    detection_id=det.id,
                    signal_type="saved_search",
                    status=RuntimeHealthStatus.healthy,
                    title=f"Recent runs OK: {det.name}",
                    detail=f"Last {len(history)} runs completed successfully.",
                )
            )

        return signals, findings

    # ------------------------------------------------------------------
    # Private: dependency health checks
    # ------------------------------------------------------------------

    def _check_dependency_health(
        self, det: Detection, dep: Dependency, runtime_data: RuntimeData
    ) -> tuple[list[RuntimeSignal], list[Finding]]:
        signals: list[RuntimeSignal] = []
        findings: list[Finding] = []

        if dep.kind == DependencyKind.lookup:
            s, f = self._check_lookup(det, dep, runtime_data)
            signals.extend(s)
            findings.extend(f)
        elif dep.kind == DependencyKind.data_model:
            s, f = self._check_data_model(det, dep, runtime_data)
            signals.extend(s)
            findings.extend(f)

        return signals, findings

    def _check_lookup(
        self, det: Detection, dep: Dependency, runtime_data: RuntimeData
    ) -> tuple[list[RuntimeSignal], list[Finding]]:
        signals: list[RuntimeSignal] = []
        findings: list[Finding] = []

        health = runtime_data.lookup_health.get(dep.name)
        if not health:
            return signals, findings

        if not health.exists:
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="lookup",
                    status=RuntimeHealthStatus.unhealthy,
                    title=f"Lookup missing at runtime: {dep.name}",
                    detail="Lookup definition not found via Splunk API.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    dependency_id=dep.id,
                    category=FindingCategory.runtime_health,
                    severity=FindingSeverity.high,
                    title=f"Lookup not available at runtime: {dep.name}",
                    description=(
                        f"Lookup '{dep.name}' referenced by '{det.name}' "
                        f"is not available on the live Splunk instance."
                    ),
                    remediation=RemediationAction(
                        title=f"Deploy lookup '{dep.name}'",
                        description="Ensure the lookup definition and backing data are deployed.",
                        effort="medium",
                        steps=[
                            "Check if the lookup CSV or KV store collection exists",
                            "Deploy the lookup definition via transforms.conf",
                            "Verify the lookup is accessible via | inputlookup",
                        ],
                    ),
                )
            )
        else:
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="lookup",
                    status=RuntimeHealthStatus.healthy,
                    title=f"Lookup available: {dep.name}",
                    detail=f"Type: {health.lookup_type or 'unknown'}",
                )
            )

        return signals, findings

    def _check_data_model(
        self, det: Detection, dep: Dependency, runtime_data: RuntimeData
    ) -> tuple[list[RuntimeSignal], list[Finding]]:
        signals: list[RuntimeSignal] = []
        findings: list[Finding] = []

        health = runtime_data.data_model_health.get(dep.name)
        if not health:
            return signals, findings

        if not health.exists:
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="data_model",
                    status=RuntimeHealthStatus.unhealthy,
                    title=f"Data model missing: {dep.name}",
                    detail="Data model not found via Splunk API.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    dependency_id=dep.id,
                    category=FindingCategory.runtime_health,
                    severity=FindingSeverity.high,
                    title=f"Data model not available: {dep.name}",
                    description=(
                        f"Data model '{dep.name}' referenced by '{det.name}' "
                        f"is not installed on the live Splunk instance."
                    ),
                    remediation=RemediationAction(
                        title=f"Install data model '{dep.name}'",
                        description=(
                            "Install the app that provides this data model "
                            "(e.g., Splunk CIM)."
                        ),
                        effort="medium",
                        steps=[
                            "Identify which app provides this data model",
                            "Install the app on the Splunk search head",
                            "Enable acceleration if needed for performance",
                        ],
                    ),
                )
            )
        elif health.acceleration_enabled and not health.acceleration_complete:
            pct = health.acceleration_percent * 100
            status = RuntimeHealthStatus.degraded if pct > 50 else RuntimeHealthStatus.unhealthy
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="data_model",
                    status=status,
                    title=f"Acceleration incomplete: {dep.name}",
                    detail=f"Acceleration is {pct:.0f}% complete.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    dependency_id=dep.id,
                    category=FindingCategory.acceleration_issue,
                    severity=FindingSeverity.medium,
                    title=f"Data model acceleration incomplete: {dep.name}",
                    description=(
                        f"Data model '{dep.name}' has acceleration enabled but "
                        f"is only {pct:.0f}% complete. This may cause slow searches."
                    ),
                    remediation=RemediationAction(
                        title=f"Complete acceleration for '{dep.name}'",
                        description=(
                            "Wait for acceleration to complete or "
                            "investigate why it stalled."
                        ),
                        effort="low",
                        steps=[
                            "Check data model acceleration status in Settings > Data Models",
                            "Verify there is sufficient disk space for acceleration",
                            "Review acceleration earliest_time setting",
                        ],
                    ),
                )
            )
        elif not health.acceleration_enabled:
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="data_model",
                    status=RuntimeHealthStatus.degraded,
                    title=f"Acceleration disabled: {dep.name}",
                    detail="Data model exists but acceleration is not enabled.",
                )
            )
            findings.append(
                Finding(
                    detection_id=det.id,
                    dependency_id=dep.id,
                    category=FindingCategory.acceleration_issue,
                    severity=FindingSeverity.low,
                    title=f"Data model not accelerated: {dep.name}",
                    description=(
                        f"Data model '{dep.name}' exists but acceleration is disabled. "
                        f"Searches using tstats will be slow."
                    ),
                    remediation=RemediationAction(
                        title=f"Enable acceleration for '{dep.name}'",
                        description="Enable data model acceleration for better search performance.",
                        effort="low",
                        steps=[
                            "Navigate to Settings > Data Models in Splunk",
                            "Click Edit > Edit Acceleration for the data model",
                            "Enable acceleration and set appropriate time range",
                        ],
                    ),
                )
            )
        else:
            signals.append(
                RuntimeSignal(
                    dependency_id=dep.id,
                    detection_id=det.id,
                    signal_type="data_model",
                    status=RuntimeHealthStatus.healthy,
                    title=f"Data model healthy: {dep.name}",
                    detail="Data model exists and acceleration is complete.",
                )
            )

        return signals, findings

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_runtime_score(
        signals: list[RuntimeSignal],
    ) -> tuple[RuntimeHealthStatus, float]:
        """Derive an overall runtime score from individual signals."""
        if not signals:
            return RuntimeHealthStatus.unknown, 0.0

        status_weights = {
            RuntimeHealthStatus.healthy: 1.0,
            RuntimeHealthStatus.degraded: 0.5,
            RuntimeHealthStatus.unhealthy: 0.0,
            RuntimeHealthStatus.unknown: 0.3,
        }

        total_weight = sum(status_weights[s.status] for s in signals)
        score = total_weight / len(signals)

        # Derive overall status
        unhealthy = any(s.status == RuntimeHealthStatus.unhealthy for s in signals)
        degraded = any(s.status == RuntimeHealthStatus.degraded for s in signals)

        if unhealthy:
            status = RuntimeHealthStatus.unhealthy
        elif degraded:
            status = RuntimeHealthStatus.degraded
        elif all(s.status == RuntimeHealthStatus.unknown for s in signals):
            status = RuntimeHealthStatus.unknown
        else:
            status = RuntimeHealthStatus.healthy

        return status, score

    @staticmethod
    def _derive_combined_status(static_status: str, runtime_status: str) -> str:
        """Derive a combined status from static and runtime statuses."""
        # If either is blocked/unhealthy, the combined status reflects that
        if static_status == "blocked" or runtime_status == "unhealthy":
            return "blocked"
        if static_status == "partially_runnable" or runtime_status == "degraded":
            return "degraded"
        if static_status == "runnable" and runtime_status == "healthy":
            return "healthy"
        if static_status == "unknown" and runtime_status == "unknown":
            return "unknown"
        # Mixed states default to degraded
        return "degraded"
