from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import BriefingModel, IncidentModel

class BriefingRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_briefing(self, briefing_data: dict) -> BriefingModel:
        briefing = BriefingModel(**briefing_data)
        self.db.add(briefing)
        self.db.flush()
        return briefing

    def get_by_incident_id(self, incident_id: str) -> Optional[BriefingModel]:
        return self.db.execute(
            select(BriefingModel)
            .join(IncidentModel)
            .where(IncidentModel.incident_id == incident_id)
        ).scalar_one_or_none()
