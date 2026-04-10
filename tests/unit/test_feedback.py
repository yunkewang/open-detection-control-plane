"""Tests for feedback analyzer."""

from odcp.analyzers.ai_soc.feedback import FeedbackAnalyzer
from odcp.models import (
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary


def _report(
    detections: list[Detection],
    scores: list[ReadinessScore],
    *,
    runtime_enabled: bool = False,
    combined_scores: list[dict] | None = None,
    **meta_kw,
) -> ScanReport:
    meta = dict(meta_kw)
    if runtime_enabled:
        meta["runtime_enabled"] = True
        meta["runtime_summary"] = {"total_detections": len(detections)}
    if combined_scores is not None:
        meta["combined_scores"] = combined_scores
    rs = ReadinessSummary(
        total_detections=len(detections),
        runnable=sum(1 for s in scores if s.status == ReadinessStatus.runnable),
        blocked=sum(1 for s in scores if s.status == ReadinessStatus.blocked),
        overall_score=sum(s.score for s in scores) / len(scores) if scores else 0,
    )
    return ScanReport(
        environment=Environment(
            name="Test",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=detections,
        readiness_scores=scores,
        readiness_summary=rs,
        metadata=meta,
    )


class TestFeedbackAnalyzer:
    def test_all_healthy(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q")]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.runnable, score=1.0)]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        assert fb.healthy_detections == 1
        assert fb.stale_detections == 0
        assert len(fb.proposals) == 0

    def test_blocked_detection_proposes_disable(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q", enabled=True)]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.blocked, score=0.0)]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        assert fb.stale_detections >= 1
        disable_proposals = [p for p in fb.proposals if p.proposal_type == "disable"]
        assert len(disable_proposals) >= 1

    def test_blocked_disabled_no_disable_proposal(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q", enabled=False)]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.blocked, score=0.0)]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        disable_proposals = [p for p in fb.proposals if p.proposal_type == "disable"]
        assert len(disable_proposals) == 0

    def test_partially_runnable_proposes_update(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q")]
        scores = [ReadinessScore(
            detection_id="d1", detection_name="D1",
            status=ReadinessStatus.partially_runnable, score=0.5,
            missing_dependencies=2,
        )]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        update_proposals = [p for p in fb.proposals if p.proposal_type == "update_query"]
        assert len(update_proposals) >= 1

    def test_disabled_runnable_proposes_reenable(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q", enabled=False)]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.runnable, score=1.0)]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        adjust = [p for p in fb.proposals if p.proposal_type == "adjust_threshold"]
        assert len(adjust) >= 1

    def test_runtime_unhealthy_escalates(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q")]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.runnable, score=1.0)]
        combined = [{"detection_id": "d1", "detection_name": "D1",
                     "runtime_status": "unhealthy", "combined_status": "degraded",
                     "runtime_score": 0.2}]
        fb = FeedbackAnalyzer().analyze(
            _report(dets, scores, runtime_enabled=True, combined_scores=combined)
        )
        escalate = [p for p in fb.proposals if p.proposal_type == "escalate_severity"]
        assert len(escalate) >= 1

    def test_runtime_degraded_proposes_review(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q")]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.runnable, score=1.0)]
        combined = [{"detection_id": "d1", "detection_name": "D1",
                     "runtime_status": "degraded", "combined_status": "degraded",
                     "runtime_score": 0.3}]
        fb = FeedbackAnalyzer().analyze(
            _report(dets, scores, runtime_enabled=True, combined_scores=combined)
        )
        update = [p for p in fb.proposals if p.proposal_type == "update_query"]
        assert len(update) >= 1

    def test_noisy_detection_from_runtime(self) -> None:
        dets = [Detection(id="d1", name="D1", search_query="q")]
        scores = [ReadinessScore(detection_id="d1", detection_name="D1",
                                 status=ReadinessStatus.runnable, score=1.0)]
        combined = [{"detection_id": "d1", "detection_name": "D1",
                     "runtime_status": "healthy", "combined_status": "healthy",
                     "runtime_score": 1.0, "alert_count": 5000}]
        fb = FeedbackAnalyzer(noisy_volume_threshold=1000).analyze(
            _report(dets, scores, runtime_enabled=True, combined_scores=combined)
        )
        assert fb.noisy_detections >= 1
        noisy = [p for p in fb.proposals if "noise" in p.rationale.lower() or "threshold" in p.rationale.lower()]
        assert len(noisy) >= 1

    def test_recommendations_generated(self) -> None:
        dets = [
            Detection(id="d1", name="D1", search_query="q", enabled=True),
            Detection(id="d2", name="D2", search_query="q", enabled=True),
        ]
        scores = [
            ReadinessScore(detection_id="d1", detection_name="D1",
                           status=ReadinessStatus.runnable, score=1.0),
            ReadinessScore(detection_id="d2", detection_name="D2",
                           status=ReadinessStatus.blocked, score=0.0),
        ]
        fb = FeedbackAnalyzer().analyze(_report(dets, scores))
        assert len(fb.recommendations) > 0

    def test_empty_report(self) -> None:
        fb = FeedbackAnalyzer().analyze(_report([], []))
        assert fb.total_detections_analyzed == 0
        assert fb.healthy_detections == 0
