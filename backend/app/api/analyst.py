from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.analyst import record_decision, start_review
from app.models.api import AnalystActionRecord, AnalystActionRequest
from app.repositories.analyst_repository import AnalystRepository
from app.database.models import IncidentModel, AnalystDecisionModel

router = APIRouter(prefix="/api/analyst", tags=["analyst"])

@router.post("/decision", response_model=dict)
def make_decision(payload: AnalystActionRequest, incident_id: str, db: Session = Depends(get_db)):
    """
    Record an analyst decision.
    """
    result = record_decision(db, incident_id=incident_id, action=payload.action, justification=payload.note or "")
    return result

@router.get("/incidents/{incident_id}/decisions")
def get_decisions(incident_id: str, db: Session = Depends(get_db)):
    """
    Audit trail of decisions.
    """
    repo = AnalystRepository(db)
    # The AnalystRepository currently doesn't have get_decisions_for_incident. We'll query direct for now or add it.
    from app.database.models import AnalystDecisionModel
    decisions = db.query(AnalystDecisionModel).filter(AnalystDecisionModel.incident_id == db.query(IncidentModel.id).filter(IncidentModel.incident_id==incident_id).scalar()).all()
    return [{"action": d.decision, "note": d.notes, "timestamp": d.created_at} for d in decisions]
