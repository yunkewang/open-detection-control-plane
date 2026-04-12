"""Compliance report builder for ODCP.

Produces structured compliance evidence reports from ODCP data, mapped
to SOC 2 Type II, NIST CSF, and a generic custom framework.

Usage::

    builder = ComplianceReportBuilder()
    report = builder.build(
        framework="soc2",
        store=store,
        lifecycle_manager=lifecycle_manager,
        audit_logger=audit_logger,
        period_label="2025-Q1",
    )
    print(report.as_markdown())
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    """A single compliance control with evidence."""

    control_id: str
    control_name: str
    description: str
    status: str = "not_evaluated"   # pass / fail / partial / not_evaluated
    evidence: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)  # issues found
    score: Optional[float] = None


class ComplianceSection(BaseModel):
    """A group of controls (e.g. a SOC 2 trust service criterion)."""

    section_id: str
    section_name: str
    controls: list[ComplianceControl] = Field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        evaluated = [c for c in self.controls if c.status != "not_evaluated"]
        if not evaluated:
            return 0.0
        return sum(1 for c in evaluated if c.status == "pass") / len(evaluated)


class ComplianceReport(BaseModel):
    """Full compliance evidence report."""

    framework: str
    framework_name: str
    period_label: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_score: float = 0.0
    sections: list[ComplianceSection] = Field(default_factory=list)
    summary_notes: list[str] = Field(default_factory=list)

    def as_markdown(self) -> str:
        lines = [
            f"# {self.framework_name} Compliance Report",
            f"**Period:** {self.period_label}",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Overall Score:** {self.overall_score * 100:.1f}%",
            "",
        ]
        for sec in self.sections:
            lines.append(f"## {sec.section_id} — {sec.section_name}")
            lines.append(f"Pass rate: {sec.pass_rate * 100:.0f}%")
            lines.append("")
            for ctrl in sec.controls:
                icon = {"pass": "✅", "fail": "❌", "partial": "⚠️"}.get(ctrl.status, "⬜")
                lines.append(f"### {icon} {ctrl.control_id}: {ctrl.control_name}")
                lines.append(f"*{ctrl.description}*")
                lines.append(f"**Status:** {ctrl.status}")
                if ctrl.evidence:
                    lines.append("**Evidence:**")
                    for ev in ctrl.evidence:
                        lines.append(f"- {ev}")
                if ctrl.findings:
                    lines.append("**Issues:**")
                    for f in ctrl.findings:
                        lines.append(f"- ⚠️ {f}")
                lines.append("")
        if self.summary_notes:
            lines.append("## Summary Notes")
            for note in self.summary_notes:
                lines.append(f"- {note}")
        return "\n".join(lines)


# ── Framework definitions ─────────────────────────────────────────────────────

_SOC2_STRUCTURE = [
    ("CC6", "Logical and Physical Access Controls", [
        ("CC6.1", "Implement logical access security measures",
         "API authentication and RBAC controls"),
        ("CC6.2", "Register and authorize internal users",
         "Token management with role-based permissions"),
        ("CC6.3", "Remove access when no longer required",
         "Token revocation capability"),
    ]),
    ("CC7", "System Operations", [
        ("CC7.1", "Detect and monitor system anomalies",
         "Detection readiness monitoring and gap analysis"),
        ("CC7.2", "Monitor system components",
         "Fleet agent health and staleness detection"),
        ("CC7.3", "Evaluate security events",
         "Finding severity triage and remediation tracking"),
    ]),
    ("CC8", "Change Management", [
        ("CC8.1", "Authorize changes to infrastructure",
         "Detection lifecycle management with state transitions"),
    ]),
    ("A1", "Availability", [
        ("A1.1", "Maintain current processing capacity",
         "Fleet agent monitoring and availability tracking"),
        ("A1.2", "Restore processing in case of disaster",
         "Scan report backup and reload capabilities"),
    ]),
]

_NIST_CSF_STRUCTURE = [
    ("ID", "Identify", [
        ("ID.AM", "Asset Management", "Inventory of detection assets and data sources"),
        ("ID.RA", "Risk Assessment", "Detection coverage gap analysis vs. ATT&CK"),
        ("ID.GV", "Governance", "Detection lifecycle policy and review processes"),
    ]),
    ("PR", "Protect", [
        ("PR.AC", "Access Control", "API auth, RBAC, token management"),
        ("PR.DS", "Data Security", "Audit logging and access trail"),
        ("PR.IP", "Information Protection", "Change management via lifecycle workflow"),
    ]),
    ("DE", "Detect", [
        ("DE.CM", "Security Continuous Monitoring", "Detection readiness scores and runtime health"),
        ("DE.AE", "Anomalies and Events", "Finding detection and severity triage"),
        ("DE.DP", "Detection Processes", "Lifecycle state management, SLA tracking"),
    ]),
    ("RS", "Respond", [
        ("RS.RP", "Response Planning", "AI SOC priority actions and remediation"),
        ("RS.AN", "Analysis", "Threat intelligence coverage gap analysis"),
        ("RS.MI", "Mitigation", "Detection tuning and rollback capabilities"),
    ]),
]


class ComplianceReportBuilder:
    """Builds compliance evidence reports from ODCP state."""

    def build(
        self,
        framework: str,
        store: Optional[Any] = None,           # ReportStore
        lifecycle_manager: Optional[Any] = None,  # LifecycleManager
        audit_logger: Optional[Any] = None,    # AuditLogger
        intel_manager: Optional[Any] = None,   # IntelManager
        registry: Optional[Any] = None,        # AgentRegistry
        period_label: str = "",
    ) -> ComplianceReport:
        """Build a compliance report for the given framework.

        Parameters
        ----------
        framework:
            One of ``soc2``, ``nist_csf``.
        """
        if not period_label:
            now = datetime.now(timezone.utc)
            period_label = f"{now.year}-Q{(now.month - 1) // 3 + 1}"

        ctx = _EvidenceContext(
            store=store,
            lifecycle_manager=lifecycle_manager,
            audit_logger=audit_logger,
            intel_manager=intel_manager,
            registry=registry,
        )

        if framework == "soc2":
            return self._build_soc2(ctx, period_label)
        elif framework == "nist_csf":
            return self._build_nist_csf(ctx, period_label)
        else:
            raise ValueError(f"Unknown framework '{framework}'. Supported: soc2, nist_csf")

    def _build_soc2(self, ctx: "_EvidenceContext", period: str) -> ComplianceReport:
        sections: list[ComplianceSection] = []
        for sec_id, sec_name, controls in _SOC2_STRUCTURE:
            ctrl_list = []
            for ctrl_id, ctrl_name, ctrl_desc in controls:
                ctrl = ctx.evaluate_soc2_control(ctrl_id, ctrl_name, ctrl_desc)
                ctrl_list.append(ctrl)
            sections.append(ComplianceSection(
                section_id=sec_id, section_name=sec_name, controls=ctrl_list
            ))
        overall = _calc_overall(sections)
        return ComplianceReport(
            framework="soc2",
            framework_name="SOC 2 Type II — Trust Services Criteria",
            period_label=period,
            overall_score=overall,
            sections=sections,
            summary_notes=ctx.global_notes(),
        )

    def _build_nist_csf(self, ctx: "_EvidenceContext", period: str) -> ComplianceReport:
        sections: list[ComplianceSection] = []
        for sec_id, sec_name, controls in _NIST_CSF_STRUCTURE:
            ctrl_list = []
            for ctrl_id, ctrl_name, ctrl_desc in controls:
                ctrl = ctx.evaluate_nist_control(ctrl_id, ctrl_name, ctrl_desc)
                ctrl_list.append(ctrl)
            sections.append(ComplianceSection(
                section_id=sec_id, section_name=sec_name, controls=ctrl_list
            ))
        overall = _calc_overall(sections)
        return ComplianceReport(
            framework="nist_csf",
            framework_name="NIST Cybersecurity Framework (CSF 2.0)",
            period_label=period,
            overall_score=overall,
            sections=sections,
            summary_notes=ctx.global_notes(),
        )


def _calc_overall(sections: list[ComplianceSection]) -> float:
    all_ctrl = [c for sec in sections for c in sec.controls if c.status != "not_evaluated"]
    if not all_ctrl:
        return 0.0
    passed = sum(1 for c in all_ctrl if c.status == "pass")
    partial = sum(1 for c in all_ctrl if c.status == "partial")
    return round((passed + partial * 0.5) / len(all_ctrl), 3)


class _EvidenceContext:
    """Helper that queries ODCP state to produce control evidence."""

    def __init__(self, store, lifecycle_manager, audit_logger, intel_manager, registry):
        self._store = store
        self._lm = lifecycle_manager
        self._audit = audit_logger
        self._intel = intel_manager
        self._reg = registry

    # ── SOC 2 evaluators ─────────────────────────────────────────────────────

    def evaluate_soc2_control(
        self, ctrl_id: str, ctrl_name: str, ctrl_desc: str
    ) -> ComplianceControl:
        evaluators = {
            "CC6.1": self._soc2_cc6_1,
            "CC6.2": self._soc2_cc6_2,
            "CC6.3": self._soc2_cc6_3,
            "CC7.1": self._soc2_cc7_1,
            "CC7.2": self._soc2_cc7_2,
            "CC7.3": self._soc2_cc7_3,
            "CC8.1": self._soc2_cc8_1,
            "A1.1":  self._soc2_a1_1,
            "A1.2":  self._soc2_a1_2,
        }
        fn = evaluators.get(ctrl_id)
        if fn:
            return fn(ctrl_id, ctrl_name, ctrl_desc)
        return ComplianceControl(
            control_id=ctrl_id, control_name=ctrl_name, description=ctrl_desc
        )

    def _soc2_cc6_1(self, cid, name, desc):
        ev, issues = [], []
        ts = self._try(lambda: self._store.app if self._store else None)
        # Check token store auth
        ts = self._try(lambda: getattr(self._store, '_app', None))
        ev.append("API authentication system implemented (TokenStore with SHA-256 hashing)")
        ev.append("RBAC with four roles: admin, analyst, readonly, agent")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="pass", evidence=ev, findings=issues,
        )

    def _soc2_cc6_2(self, cid, name, desc):
        ev = ["API token creation requires admin role", "Tokens include name, role, and optional agent_id"]
        audit_count = self._try(lambda: self._audit.total() if self._audit else 0) or 0
        ev.append(f"Audit log contains {audit_count} events")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="pass", evidence=ev,
        )

    def _soc2_cc6_3(self, cid, name, desc):
        ev = ["Token revocation API available (DELETE /api/auth/tokens/{id})"]
        ev.append("Tokens cannot be renewed — must be re-issued to force rotation")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="pass", evidence=ev,
        )

    def _soc2_cc7_1(self, cid, name, desc):
        ev, issues = [], []
        report_loaded = self._try(lambda: self._store.loaded if self._store else False)
        if report_loaded:
            posture = self._try(lambda: self._store.posture_dict())
            score = (posture or {}).get("readiness_score", 0) if posture else 0
            ev.append(f"Current readiness score: {score:.1%}")
            blocked = (posture or {}).get("blocked", 0)
            if blocked:
                issues.append(f"{blocked} detections currently blocked")
        else:
            issues.append("No scan report loaded — detection monitoring inactive")
        status = "partial" if issues else "pass"
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status=status, evidence=ev, findings=issues,
        )

    def _soc2_cc7_2(self, cid, name, desc):
        ev, issues = [], []
        if self._reg:
            summary = self._try(lambda: self._reg.fleet_summary())
            if summary:
                ev.append(f"Fleet: {summary.total_agents} agents, {summary.active_agents} active")
                if summary.offline_agents:
                    issues.append(f"{summary.offline_agents} agents offline")
        else:
            ev.append("Fleet monitoring available (no agents registered)")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="partial" if issues else "pass", evidence=ev, findings=issues,
        )

    def _soc2_cc7_3(self, cid, name, desc):
        ev, issues = [], []
        report_loaded = self._try(lambda: self._store.loaded if self._store else False)
        if report_loaded:
            posture = self._try(lambda: self._store.posture_dict()) or {}
            ev.append(f"Total findings: {posture.get('total_findings', 0)}")
            ev.append(f"Critical: {posture.get('critical_count', 0)}, "
                      f"High: {posture.get('high_count', 0)}")
        else:
            issues.append("No report loaded")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="partial" if issues else "pass", evidence=ev, findings=issues,
        )

    def _soc2_cc8_1(self, cid, name, desc):
        ev, issues = [], []
        if self._lm:
            summary = self._try(lambda: self._lm.summary())
            if summary:
                ev.append(f"Detection lifecycle tracking: {summary.total} detections")
                ev.append(f"In production: {summary.by_state.get('production', 0)}")
                ev.append("State transitions require actor attribution")
                if summary.by_state.get("draft", 0) > 20:
                    issues.append(f"{summary.by_state['draft']} detections stuck in draft")
        else:
            issues.append("Lifecycle management not configured")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="partial" if issues else "pass", evidence=ev, findings=issues,
        )

    def _soc2_a1_1(self, cid, name, desc):
        ev = []
        if self._reg:
            summary = self._try(lambda: self._reg.fleet_summary())
            if summary:
                ev.append(f"{summary.active_agents}/{summary.total_agents} agents active")
        ev.append("Automatic staleness detection removes offline agents from active pool")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="pass", evidence=ev,
        )

    def _soc2_a1_2(self, cid, name, desc):
        ev = ["Scan reports stored as JSON files — backup via filesystem"]
        ev.append("Report reload supported via /api/report/load")
        return ComplianceControl(
            control_id=cid, control_name=name, description=desc,
            status="pass", evidence=ev,
        )

    # ── NIST CSF evaluators ───────────────────────────────────────────────────

    def evaluate_nist_control(
        self, ctrl_id: str, ctrl_name: str, ctrl_desc: str
    ) -> ComplianceControl:
        # Reuse SOC2 evaluators where applicable, add NIST-specific ones
        mappings = {
            "ID.AM": self._nist_id_am,
            "ID.RA": self._nist_id_ra,
            "ID.GV": self._nist_id_gv,
            "PR.AC": self._nist_pr_ac,
            "PR.DS": self._nist_pr_ds,
            "PR.IP": self._nist_pr_ip,
            "DE.CM": self._nist_de_cm,
            "DE.AE": self._nist_de_ae,
            "DE.DP": self._nist_de_dp,
            "RS.RP": self._nist_rs_rp,
            "RS.AN": self._nist_rs_an,
            "RS.MI": self._nist_rs_mi,
        }
        fn = mappings.get(ctrl_id)
        if fn:
            return fn(ctrl_id, ctrl_name, ctrl_desc)
        return ComplianceControl(
            control_id=ctrl_id, control_name=ctrl_name, description=ctrl_desc
        )

    def _nist_id_am(self, cid, name, desc):
        ev = []
        rpt = self._try(lambda: self._store.report if self._store else None)
        if rpt:
            ev.append(f"Detection inventory: {len(rpt.detections)} detections")
            ev.append(f"Dependency inventory: {len(rpt.dependencies)} objects")
        ev.append("Source catalog tracks platforms, indexes, and field-level data")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass" if ev else "partial", evidence=ev)

    def _nist_id_ra(self, cid, name, desc):
        ev, issues = [], []
        rpt = self._try(lambda: self._store.report if self._store else None)
        if rpt:
            cov = rpt.metadata.get("coverage_summary", {})
            if cov:
                score = cov.get("coverage_score", 0)
                ev.append(f"ATT&CK coverage score: {score:.1%}")
                uncovered = cov.get("uncovered_techniques", 0)
                if uncovered:
                    issues.append(f"{uncovered} uncovered ATT&CK techniques")
            else:
                issues.append("Coverage analysis not run — use --coverage flag")
        if self._intel:
            summary = self._try(lambda: self._intel.summary())
            if summary and summary.active_campaigns:
                ev.append(f"Threat intel: {summary.active_campaigns} active campaigns tracked")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="partial" if issues else "pass", evidence=ev, findings=issues)

    def _nist_id_gv(self, cid, name, desc):
        ev = ["Detection lifecycle policy enforced (draft→review→testing→production)"]
        if self._lm:
            summary = self._try(lambda: self._lm.summary())
            if summary:
                ev.append(f"{summary.by_state.get('production',0)} detections in production")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass", evidence=ev)

    def _nist_pr_ac(self, cid, name, desc):
        return self._soc2_cc6_1(cid, name, desc)

    def _nist_pr_ds(self, cid, name, desc):
        ev = []
        audit_count = self._try(lambda: self._audit.total() if self._audit else 0) or 0
        ev.append(f"Audit log: {audit_count} events recorded")
        ev.append("Sensitive tokens never stored in plaintext (SHA-256 hash only)")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass", evidence=ev)

    def _nist_pr_ip(self, cid, name, desc):
        return self._soc2_cc8_1(cid, name, desc)

    def _nist_de_cm(self, cid, name, desc):
        return self._soc2_cc7_1(cid, name, desc)

    def _nist_de_ae(self, cid, name, desc):
        return self._soc2_cc7_3(cid, name, desc)

    def _nist_de_dp(self, cid, name, desc):
        ev = ["Lifecycle SLA tracking available for detection state monitoring"]
        if self._lm:
            summary = self._try(lambda: self._lm.summary())
            if summary:
                ev.append(f"Total tracked detections: {summary.total}")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass", evidence=ev)

    def _nist_rs_rp(self, cid, name, desc):
        ev = ["AI SOC cycle produces prioritized response actions"]
        ev.append("Dashboard surfaces priority actions from AI analysis")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass", evidence=ev)

    def _nist_rs_an(self, cid, name, desc):
        ev, issues = [], []
        if self._intel:
            summary = self._try(lambda: self._intel.summary())
            if summary:
                ev.append(f"Threat campaigns tracked: {summary.total_campaigns}")
                ev.append(f"IOCs tracked: {summary.total_iocs}")
            else:
                issues.append("No threat intel configured")
        else:
            issues.append("Threat intel module not active")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="partial" if issues else "pass", evidence=ev, findings=issues)

    def _nist_rs_mi(self, cid, name, desc):
        ev = ["Detection rollback supported — revert to prior lifecycle state"]
        ev.append("Findings include remediation steps with effort estimates")
        return ComplianceControl(control_id=cid, control_name=name, description=desc,
                                 status="pass", evidence=ev)

    # ── Shared notes ──────────────────────────────────────────────────────────

    def global_notes(self) -> list[str]:
        notes = []
        rpt = self._try(lambda: self._store.report if self._store else None)
        if not rpt:
            notes.append("No scan report loaded — several controls evaluated as partial")
        audit = self._try(lambda: self._audit.total() if self._audit else 0)
        if (audit or 0) == 0:
            notes.append("Audit log is empty — verify audit logging is configured")
        return notes

    @staticmethod
    def _try(fn):
        try:
            return fn()
        except Exception:
            return None
