"""
FastAPI router for SOC incident queue, detail, AI briefing, and analyst actions (Task 10).
"""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.api import (
    AnalystActionRecord,
    AnalystActionRequest,
    DashboardMetricsResponse,
    IncidentBriefResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
)
from app.services.briefing import generate_incident_brief
from app.repositories.incident_repository import IncidentRepository
from app.repositories.briefing_repository import BriefingRepository
from app.services.incident_views import build_incident_summary, build_incident_detail

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["incidents"])

@router.get("/incidents", response_model=list[IncidentSummaryResponse])
def list_incidents(
    priority: Optional[str] = Query(None, description="Filter by priority: P1, P2, P3, P4"),
    limit: Optional[int] = Query(None, ge=1),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
) -> list[IncidentSummaryResponse]:
    repo = IncidentRepository(db)
    # the repo get_all currently doesn't filter by priority, but for now we fetch and filter
    incidents = repo.get_all(limit=1000, offset=offset) # Temporary logic
    if priority:
        incidents = [i for i in incidents if i.priority == priority.upper()]
    if limit:
        incidents = incidents[:limit]
        
    return [build_incident_summary(inc) for inc in incidents]

@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)) -> IncidentDetailResponse:
    repo = IncidentRepository(db)
    incident = repo.get_by_id(incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found")
    return build_incident_detail(incident)

@router.post("/incidents/{incident_id}/brief", response_model=IncidentBriefResponse)
def generate_incident_brief_endpoint(incident_id: str, db: Session = Depends(get_db)) -> IncidentBriefResponse:
    repo = IncidentRepository(db)
    incident = repo.get_by_id(incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found")

    from app.models.triage import TriagedIncident
    from app.services.mitre import build_mitre_context
    from app.models.alert import Alert
    
    inc_alerts = [Alert.model_validate(a, from_attributes=True) for a in incident.alerts]
    mitre_context = build_mitre_context(inc_alerts)
    
    ti = TriagedIncident(
        incident_id=incident.incident_id,
        alert_ids=[a.alert_id for a in inc_alerts],
        start_time=incident.start_time,
        end_time=incident.end_time,
        correlation_score=incident.correlation_score,
        correlation_evidence=[],
        risk_score=incident.risk_score or 0.0,
        priority=incident.priority, # It's a string, we might need enum, but briefing uses it as string
        severity_score=incident.risk_severity_score or 0.0,
        asset_criticality_score=incident.risk_criticality_score or 0.0,
        correlation_strength_score=0.0,
        evidence_strength_score=incident.risk_alert_count_score or 0.0,
        attack_context_score=incident.risk_mitre_score or 0.0,
        explanation="",
        mitre_context=mitre_context
    )
    
    brief = generate_incident_brief(ti, inc_alerts, force_ai=True) # Forced regeneration

    # Persist
    briefing_repo = BriefingRepository(db)
    brief_data = {
        "incident_id": incident.id,
        "summary": brief.summary,
        "attack_vector": brief.why_it_matters,
        "impact": "\n".join(brief.key_evidence),
        "recommendation": "\n".join(brief.recommended_next_steps),
        "model_name": getattr(brief, "generation_source", "deterministic_fallback")
    }
    # Might need to update if exists, BriefingRepository logic should handle or we assume it creates anew or fails unique
    # For now, just generate and return. The persistence here would be to recreate it.
    
    return IncidentBriefResponse(
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

@router.post("/incidents/{incident_id}/action", response_model=dict)
def record_analyst_action_endpoint(
    incident_id: str,
    payload: AnalystActionRequest,
    db: Session = Depends(get_db)
):
    from app.services.analyst import record_decision
    result = record_decision(db, incident_id, payload.action, justification=payload.note or "")
    return {"status": "success", "action": result["action"]}

# Note: /api/metrics moved to api/metrics.py
