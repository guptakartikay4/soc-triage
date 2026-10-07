from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import TriageMetricModel, IncidentModel

class MetricsRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_or_create(self, incident_db_id: int) -> TriageMetricModel:
        metric = self.db.execute(
            select(TriageMetricModel).where(TriageMetricModel.incident_id == incident_db_id)
        ).scalar_one_or_none()
        
        if not metric:
            # Note: We need alert_received_at. Typically we fetch the earliest alert timestamp.
            # But here we just create it and it should be populated with data.
            metric = TriageMetricModel(incident_id=incident_db_id)
            self.db.add(metric)
            self.db.flush()
            
        return metric

    def update_metrics(self, metric: TriageMetricModel):
        self.db.add(metric)
        self.db.flush()
