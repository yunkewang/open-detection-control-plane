"""Threat intelligence data models.

These models represent threat actors, campaigns, IOCs, and the analysis
results that connect intelligence feeds to ODCP detection coverage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class IocType(str, Enum):
    hash_md5 = "hash_md5"
    hash_sha256 = "hash_sha256"
    ip = "ip"
    domain = "domain"
    url = "url"
    email = "email"
    file_path = "file_path"
    registry_key = "registry_key"
    other = "other"


class FeedType(str, Enum):
    stix_taxii = "stix_taxii"
    misp = "misp"
    otx = "otx"
    manual = "manual"
    csv = "csv"


class ThreatActor(BaseModel):
    """A tracked threat actor or group."""

    actor_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str
    aliases: list[str] = Field(default_factory=list)
    motivation: Optional[str] = None   # espionage, financial, hacktivism …
    sophistication: Optional[str] = None  # low, medium, high, nation-state
    source: str = "manual"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatCampaign(BaseModel):
    """A tracked attack campaign, linked to a threat actor and MITRE techniques."""

    campaign_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str
    actor: Optional[str] = None        # actor name or ID
    techniques: list[str] = Field(default_factory=list)   # T-IDs, e.g. ["T1055", "T1566"]
    sub_techniques: list[str] = Field(default_factory=list)  # T1055.001 …
    confidence: float = 0.5            # 0–1; how confident we are this campaign is real
    active: bool = True
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    source: str = "manual"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IocEntry(BaseModel):
    """A single indicator of compromise."""

    ioc_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    value: str
    ioc_type: IocType
    related_techniques: list[str] = Field(default_factory=list)  # T-IDs
    campaign_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    source_feed: str = "manual"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntelFeed(BaseModel):
    """Configuration for an external intelligence feed."""

    feed_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str
    feed_type: FeedType = FeedType.manual
    url: Optional[str] = None
    api_key: Optional[str] = None      # stored as reference — never logged
    last_synced: Optional[datetime] = None
    entry_count: int = 0
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IocCoverageResult(BaseModel):
    """Coverage analysis result for a single IOC."""

    ioc_id: str
    ioc_value: str
    ioc_type: str
    relevant_techniques: list[str]     # T-IDs related to this IOC
    covered_by: list[str]              # detection IDs that cover at least one technique
    gap_techniques: list[str]          # T-IDs with no detection coverage
    coverage_ratio: float = 0.0        # covered / total relevant techniques
    risk_score: float = 0.0            # 0–1, factoring in confidence + coverage gap


class TechniqueRisk(BaseModel):
    """Risk assessment for a single MITRE technique in context of active threats."""

    technique_id: str
    technique_name: str = ""
    active_campaign_count: int = 0
    max_confidence: float = 0.0
    threat_score: float = 0.0          # 0–1, composite of activity + confidence
    covered: bool = False
    detection_ids: list[str] = Field(default_factory=list)
    priority: str = "low"              # critical/high/medium/low


class IntelGapReport(BaseModel):
    """Full threat-weighted gap analysis against a scan report."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_techniques_in_scope: int = 0
    covered_techniques: int = 0
    gap_techniques: int = 0
    critical_gaps: int = 0             # actively-targeted + not covered
    threat_coverage_score: float = 0.0  # threat-weighted coverage %
    technique_risks: list[TechniqueRisk] = Field(default_factory=list)
    ioc_coverage: list[IocCoverageResult] = Field(default_factory=list)


class ThreatIntelSummary(BaseModel):
    """High-level summary of the current intel state."""

    total_campaigns: int = 0
    active_campaigns: int = 0
    total_iocs: int = 0
    total_actors: int = 0
    total_feeds: int = 0
    tracked_techniques: int = 0        # unique T-IDs across all campaigns
    high_confidence_techniques: int = 0  # confidence >= 0.7
