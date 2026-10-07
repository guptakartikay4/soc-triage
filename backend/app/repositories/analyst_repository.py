from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AnalystDecisionModel, IncidentModel

class AnalystRepository:
    def __init__(self, db: Session):
        self.db = db

    def record_decision(self, incident_db_id: int, decision: str, notes: Optional[str] = None) -> AnalystDecisionModel:
        record = AnalystDecisionModel(
            incident_id=incident_db_id,
            decision=decision,
            notes=notes
        )
        self.db.add(record)
        self.db.flush()
        return record

    def get_decisions_for_incident(self, incident_id: str) -> Sequence[AnalystDecisionModel]:
        return self.db.execute(
            select(AnalystDecisionModel)
            .join(IncidentModel)
            .where(IncidentModel.incident_id == incident_id)
            .order_by(AnalystDecisionModel.created_at)
        ).scalars().all()
