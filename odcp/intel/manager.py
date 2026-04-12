"""IntelManager — thread-safe store for threat intelligence data.

Tracks campaigns, IOCs, actors, and feeds. Provides gap analysis by
mapping active-threat techniques to ODCP detection coverage.

Usage::

    mgr = IntelManager()
    mgr.add_campaign(ThreatCampaign(
        name="APT29 SolarWinds",
        actor="APT29",
        techniques=["T1195", "T1078", "T1059"],
        confidence=0.9,
    ))
    report = mgr.analyze_coverage(scan_report)
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from odcp.models.intel import (
    IntelFeed,
    IntelGapReport,
    IocCoverageResult,
    IocEntry,
    IocType,
    TechniqueRisk,
    ThreatActor,
    ThreatCampaign,
    ThreatIntelSummary,
)

logger = logging.getLogger(__name__)


class IntelManager:
    """Thread-safe store for threat intelligence data.

    Parameters
    ----------
    persist_path:
        Optional JSON file path for state persistence across restarts.
    """

    def __init__(self, persist_path: Optional[str | Path] = None) -> None:
        self._campaigns: dict[str, ThreatCampaign] = {}
        self._iocs: dict[str, IocEntry] = {}
        self._actors: dict[str, ThreatActor] = {}
        self._feeds: dict[str, IntelFeed] = {}
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path and self._persist_path.exists():
            self._load()

    # ── Campaigns ───────────────────────────────────────────────────────────

    def add_campaign(self, campaign: ThreatCampaign) -> ThreatCampaign:
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
        self._save()
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[ThreatCampaign]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def get_campaigns(self, active_only: bool = False) -> list[ThreatCampaign]:
        with self._lock:
            campaigns = list(self._campaigns.values())
        if active_only:
            campaigns = [c for c in campaigns if c.active]
        return sorted(campaigns, key=lambda c: c.last_seen or c.created_at, reverse=True)

    def remove_campaign(self, campaign_id: str) -> bool:
        with self._lock:
            if campaign_id not in self._campaigns:
                return False
            del self._campaigns[campaign_id]
        self._save()
        return True

    # ── IOCs ─────────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: IocEntry) -> IocEntry:
        with self._lock:
            self._iocs[ioc.ioc_id] = ioc
        self._save()
        return ioc

    def add_iocs_bulk(self, iocs: list[IocEntry]) -> int:
        with self._lock:
            for ioc in iocs:
                self._iocs[ioc.ioc_id] = ioc
        self._save()
        return len(iocs)

    def get_iocs(self, ioc_type: Optional[str] = None) -> list[IocEntry]:
        with self._lock:
            iocs = list(self._iocs.values())
        if ioc_type:
            iocs = [i for i in iocs if i.ioc_type.value == ioc_type]
        return sorted(iocs, key=lambda i: i.created_at, reverse=True)

    # ── Actors ────────────────────────────────────────────────────────────────

    def add_actor(self, actor: ThreatActor) -> ThreatActor:
        with self._lock:
            self._actors[actor.actor_id] = actor
        self._save()
        return actor

    def get_actors(self) -> list[ThreatActor]:
        with self._lock:
            return sorted(self._actors.values(), key=lambda a: a.name)

    # ── Feeds ─────────────────────────────────────────────────────────────────

    def add_feed(self, feed: IntelFeed) -> IntelFeed:
        with self._lock:
            self._feeds[feed.feed_id] = feed
        self._save()
        return feed

    def get_feeds(self) -> list[IntelFeed]:
        with self._lock:
            return list(self._feeds.values())

    def update_feed_sync(self, feed_id: str, entry_count: int) -> bool:
        with self._lock:
            feed = self._feeds.get(feed_id)
            if not feed:
                return False
            feed.last_synced = datetime.now(timezone.utc)
            feed.entry_count = entry_count
        self._save()
        return True

    # ── Analysis ─────────────────────────────────────────────────────────────

    def get_active_techniques(self) -> dict[str, list[str]]:
        """Return {technique_id: [campaign_ids]} for all active campaigns."""
        result: dict[str, list[str]] = {}
        with self._lock:
            campaigns = [c for c in self._campaigns.values() if c.active]
        for c in campaigns:
            for tid in c.techniques + c.sub_techniques:
                result.setdefault(tid, []).append(c.campaign_id)
        return result

    def summary(self) -> ThreatIntelSummary:
        with self._lock:
            campaigns = list(self._campaigns.values())
            iocs = list(self._iocs.values())
            actors = list(self._actors.values())
            feeds = list(self._feeds.values())

        active_campaigns = [c for c in campaigns if c.active]
        all_techniques: set[str] = set()
        high_conf: set[str] = set()
        for c in campaigns:
            tids = set(c.techniques + c.sub_techniques)
            all_techniques.update(tids)
            if c.confidence >= 0.7:
                high_conf.update(tids)

        return ThreatIntelSummary(
            total_campaigns=len(campaigns),
            active_campaigns=len(active_campaigns),
            total_iocs=len(iocs),
            total_actors=len(actors),
            total_feeds=len(feeds),
            tracked_techniques=len(all_techniques),
            high_confidence_techniques=len(high_conf),
        )

    def analyze_coverage(self, report: "ScanReport") -> IntelGapReport:  # type: ignore[name-defined]  # noqa: F821
        """Produce a threat-weighted gap report against a scan report.

        Maps active-campaign techniques to ODCP detections via the
        report's coverage metadata and readiness scores.
        """
        # Build detection-to-technique map from coverage metadata
        det_technique_map: dict[str, set[str]] = {}  # technique_id → {det_id}
        techniques_meta: dict[str, str] = {}          # technique_id → name
        cov_meta = report.metadata.get("coverage_summary", {})
        for tech in cov_meta.get("techniques", []):
            tid = tech.get("technique_id", "")
            tname = tech.get("technique_name", "")
            techniques_meta[tid] = tname
            if tech.get("coverage") in ("covered", "partial"):
                # Approximate: associate covered techniques with enabled detections
                for det in report.detections:
                    if tid.lower() in " ".join(det.tags).lower() or \
                       tid.lower() in (det.description or "").lower():
                        det_technique_map.setdefault(tid, set()).add(det.id)

        # Also build from readiness scores — runnable detections count
        runnable_ids = {
            s.detection_id for s in report.readiness_scores
            if s.status.value in ("runnable", "partially_runnable")
        }

        active_techniques = self.get_active_techniques()  # tid → [campaign_ids]

        # Build per-campaign confidence map
        with self._lock:
            campaigns_snap = {k: v for k, v in self._campaigns.items()}
        camp_conf: dict[str, float] = {c.campaign_id: c.confidence for c in campaigns_snap.values()}

        # Score each active technique
        tech_risks: list[TechniqueRisk] = []
        covered_count = 0
        critical_gap_count = 0

        for tid, camp_ids in active_techniques.items():
            covering_dets = det_technique_map.get(tid, set()) & runnable_ids
            covered = len(covering_dets) > 0
            max_conf = max((camp_conf.get(cid, 0) for cid in camp_ids), default=0.0)
            campaign_count = len(camp_ids)

            # Threat score: higher activity + higher confidence = more critical
            threat_score = min(1.0, (campaign_count / 5) * 0.4 + max_conf * 0.6)

            if covered:
                priority = "low"
                covered_count += 1
            elif threat_score >= 0.7:
                priority = "critical"
                critical_gap_count += 1
            elif threat_score >= 0.4:
                priority = "high"
                critical_gap_count += 1
            else:
                priority = "medium"

            tech_risks.append(TechniqueRisk(
                technique_id=tid,
                technique_name=techniques_meta.get(tid, ""),
                active_campaign_count=campaign_count,
                max_confidence=round(max_conf, 3),
                threat_score=round(threat_score, 3),
                covered=covered,
                detection_ids=list(covering_dets),
                priority=priority,
            ))

        tech_risks.sort(key=lambda r: (-r.threat_score, r.technique_id))

        # IOC coverage
        ioc_results = self._analyze_ioc_coverage(
            det_technique_map, runnable_ids, camp_conf
        )

        total = len(active_techniques)
        threat_coverage = covered_count / total if total > 0 else 0.0

        return IntelGapReport(
            total_techniques_in_scope=total,
            covered_techniques=covered_count,
            gap_techniques=total - covered_count,
            critical_gaps=critical_gap_count,
            threat_coverage_score=round(threat_coverage, 3),
            technique_risks=tech_risks,
            ioc_coverage=ioc_results,
        )

    def _analyze_ioc_coverage(
        self,
        det_technique_map: dict[str, set[str]],
        runnable_ids: set[str],
        camp_conf: dict[str, float],
    ) -> list[IocCoverageResult]:
        with self._lock:
            iocs = list(self._iocs.values())

        results: list[IocCoverageResult] = []
        for ioc in iocs:
            if not ioc.related_techniques:
                continue
            covered_by: set[str] = set()
            gaps: list[str] = []
            for tid in ioc.related_techniques:
                dets = det_technique_map.get(tid, set()) & runnable_ids
                if dets:
                    covered_by.update(dets)
                else:
                    gaps.append(tid)

            ratio = (len(ioc.related_techniques) - len(gaps)) / len(ioc.related_techniques)
            # Risk: high confidence IOC with low coverage = high risk
            max_camp_conf = max(
                (camp_conf.get(cid, 0) for cid in ioc.campaign_ids), default=ioc.confidence
            )
            risk = round(max_camp_conf * (1 - ratio), 3)

            results.append(IocCoverageResult(
                ioc_id=ioc.ioc_id,
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type.value,
                relevant_techniques=ioc.related_techniques,
                covered_by=list(covered_by),
                gap_techniques=gaps,
                coverage_ratio=round(ratio, 3),
                risk_score=risk,
            ))

        return sorted(results, key=lambda r: -r.risk_score)

    # ── Persistence ──────────────────────────────────────────────────────────

    def _save(self) -> None:
        if not self._persist_path:
            return
        try:
            with self._lock:
                data = {
                    "campaigns": {k: v.model_dump(mode="json") for k, v in self._campaigns.items()},
                    "iocs": {k: v.model_dump(mode="json") for k, v in self._iocs.items()},
                    "actors": {k: v.model_dump(mode="json") for k, v in self._actors.items()},
                    "feeds": {k: v.model_dump(mode="json") for k, v in self._feeds.items()},
                }
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._persist_path.write_text(
                json.dumps(data, default=str, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed to persist intel store: %s", exc)

    def _load(self) -> None:
        try:
            raw = json.loads(self._persist_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
            with self._lock:
                for k, v in raw.get("campaigns", {}).items():
                    self._campaigns[k] = ThreatCampaign.model_validate(v)
                for k, v in raw.get("iocs", {}).items():
                    self._iocs[k] = IocEntry.model_validate(v)
                for k, v in raw.get("actors", {}).items():
                    self._actors[k] = ThreatActor.model_validate(v)
                for k, v in raw.get("feeds", {}).items():
                    self._feeds[k] = IntelFeed.model_validate(v)
            logger.info("Loaded intel store from %s", self._persist_path)
        except Exception as exc:
            logger.error("Failed to load intel store: %s", exc)
