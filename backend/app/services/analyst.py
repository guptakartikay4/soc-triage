from typing import Optional
from sqlalchemy.orm import Session
from app.repositories.analyst_repository import AnalystRepository
from app.repositories.incident_repository import IncidentRepository
from app.models.incident import IncidentStatus

def record_decision(db: Session, incident_id: str, action: str, username: str = "analyst", justification: str = "") -> dict:
    """
    Record an analyst decision and update the incident status.
    Legacy actions mapped:
    investigate -> CONFIRM
    escalate -> ESCALATE
    dismiss -> DISMISS
    resolve -> CONFIRM
    """
    action_map = {
        "investigate": "CONFIRM",
        "escalate": "ESCALATE",
        "dismiss": "DISMISS",
        "resolve": "CONFIRM",
        "confirm": "CONFIRM"
    }
    
    normalized_action = action.lower()
    mapped_action = action_map.get(normalized_action, "CONFIRM")

    status_map = {
        "CONFIRM": IncidentStatus.INVESTIGATING,
        "ESCALATE": IncidentStatus.ESCALATED,
        "DISMISS": IncidentStatus.DISMISSED
    }
    
    # If it's a 'resolve', we can set it to resolved
    if normalized_action == "resolve":
        new_status = IncidentStatus.RESOLVED
    else:
        new_status = status_map.get(mapped_action, IncidentStatus.INVESTIGATING)

    analyst_repo = AnalystRepository(db)
    incident_repo = IncidentRepository(db)

    # Get incident internal ID
    incident = incident_repo.get_by_id(incident_id)
    if not incident:
        return {"status": "error", "message": "Incident not found"}

    # Record the decision
    analyst_repo.record_decision(
        incident_db_id=incident.id,
        decision=mapped_action,
        notes=justification
    )

    # Update incident status
    incident_repo.update_status(incident_id, new_status.value)
    
    return {"status": "success", "action": mapped_action, "incident_status": new_status.value}

def start_review(db: Session, incident_id: str) -> dict:
    """
    Start reviewing an incident (sets the investigating status if NEW).
    """
    incident_repo = IncidentRepository(db)
    incident = incident_repo.get_by_id(incident_id)
    if incident and incident.status == IncidentStatus.NEW.value:
        incident_repo.update_status(incident_id, IncidentStatus.INVESTIGATING.value)
        return {"status": "started"}
    return {"status": "already_started_or_not_found"}
