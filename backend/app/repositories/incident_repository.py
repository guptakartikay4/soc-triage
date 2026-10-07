from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import IncidentModel, CorrelationEdgeModel, MitreMappingModel

class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_incident(self, incident_data: dict, alert_ids: list[str]) -> IncidentModel:
        incident = IncidentModel(**incident_data)
        
        # Link alerts
        from app.database.models import AlertModel
        alerts = self.db.execute(select(AlertModel).where(AlertModel.alert_id.in_(alert_ids))).scalars().all()
        incident.alerts.extend(alerts)
        
        self.db.add(incident)
        self.db.flush()
        return incident

    def add_correlation_edges(self, edges_data: list[dict]):
        for edge in edges_data:
            self.db.add(CorrelationEdgeModel(**edge))
            
    def add_mitre_mappings(self, mappings_data: list[dict]):
        for mapping in mappings_data:
            self.db.add(MitreMappingModel(**mapping))

    def get_by_id(self, incident_id: str) -> Optional[IncidentModel]:
        return self.db.execute(
            select(IncidentModel).where(IncidentModel.incident_id == incident_id)
        ).scalar_one_or_none()
        
    def get_all(self, limit: Optional[int] = None, offset: int = 0) -> Sequence[IncidentModel]:
        stmt = select(IncidentModel).order_by(
            # Ordering could be by risk_score desc, start_time desc
            IncidentModel.risk_score.desc().nulls_last(),
            IncidentModel.start_time.desc()
        ).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return self.db.execute(stmt).scalars().all()
        
    def count(self) -> int:
        from sqlalchemy import func
        return self.db.execute(select(func.count(IncidentModel.id))).scalar() or 0

    def update_status(self, incident_id: str, status: str) -> None:
        incident = self.get_by_id(incident_id)
        if incident:
            incident.status = status
            self.db.flush()
