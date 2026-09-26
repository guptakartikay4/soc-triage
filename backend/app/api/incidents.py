"""
FastAPI router for SOC incident queue, detail, AI briefing, and analyst actions (Task 10).
"""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.models.api import (
    AnalystActionRecord,
    AnalystActionRequest,
    DashboardMetricsResponse,
    IncidentBriefResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
)
from app.services.briefing import generate_incident_brief
from app.services.repository import VALID_ACTIONS, get_repository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["incidents"])


@router.get("/incidents", response_model=list[IncidentSummaryResponse])
def list_incidents(
    priority: Optional[str] = Query(
        None,
        description="Filter by priority: critical, high, medium, low",
    ),
    limit: Optional[int] = Query(
        None,
        ge=1,
        description="Optional limit on returned incidents",
    ),
    offset: int = Query(
        0,
        ge=0,
        description="Number of incidents to skip",
    ),
) -> list[IncidentSummaryResponse]:
    """
    Return triaged incidents sorted by deterministic Task 7 prioritization logic.
    """
    repo = get_repository()
    return repo.get_incidents(priority=priority, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(incident_id: str) -> IncidentDetailResponse:
    """
    Return comprehensive detail and evidence timeline for a single incident.
    """
    repo = get_repository()
    incident = repo.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.post("/incidents/{incident_id}/brief", response_model=IncidentBriefResponse)
def generate_incident_brief_endpoint(incident_id: str) -> IncidentBriefResponse:
    """
    Explicitly trigger evidence-grounded AI briefing for the selected incident.

    Uses Groq (gpt-oss-120b) if configured; falls back seamlessly to deterministic
    template brief if Groq is unavailable, unconfigured, or fails validation.
    """
    repo = get_repository()
    ti = repo.incidents_by_id.get(incident_id)
    if ti is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    inc_alerts = repo.get_incident_alerts(incident_id)
    brief = generate_incident_brief(ti, inc_alerts)

    brief_resp = IncidentBriefResponse(
        incident_id=brief.incident_id,
        summary=brief.summary,
        why_it_matters=brief.why_it_matters,
        key_evidence=brief.key_evidence,
        mitre_summary=brief.mitre_summary,
        recommended_next_steps=brief.recommended_next_steps,
        confidence=brief.confidence,
        generation_source=getattr(brief, "generation_source", "deterministic_fallback"),
        is_fallback=getattr(brief, "is_fallback", True),
    )
    repo.set_brief(incident_id, brief_resp)
    return brief_resp


@router.post("/incidents/{incident_id}/action", response_model=AnalystActionRecord)
def record_analyst_action_endpoint(
    incident_id: str,
    payload: AnalystActionRequest,
) -> AnalystActionRecord:
    """
    Record human-in-the-loop analyst decision and calculate triage time (MTTT).

    Supported actions: investigate, escalate, dismiss, resolve.
    Does NOT perform automated remediation.
    """
    repo = get_repository()
    ti = repo.incidents_by_id.get(incident_id)
    if ti is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    action_clean = payload.action.strip().lower()
    if action_clean not in VALID_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{payload.action}'. Supported actions: {', '.join(sorted(VALID_ACTIONS))}",
        )

    record = repo.record_action(
        incident_id=incident_id,
        action=action_clean,
        note=payload.note,
        timestamp=payload.timestamp,
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to record analyst action",
        )
    return record


@router.get("/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics() -> DashboardMetricsResponse:
    """
    Return top-level summary metrics for SOC dashboard cards.
    """
    repo = get_repository()
    return repo.get_metrics()
