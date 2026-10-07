from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.dialects.sqlite import insert

from app.database.models import AlertModel

class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def bulk_insert(self, alerts_data: list[dict]) -> int:
        """
        Idempotent bulk insert using ON CONFLICT DO NOTHING.
        Returns the number of alerts successfully inserted.
        """
        if not alerts_data:
            return 0
        
        total_inserted = 0
        chunk_size = 500
        for i in range(0, len(alerts_data), chunk_size):
            chunk = alerts_data[i:i + chunk_size]
            stmt = insert(AlertModel).values(chunk)
            stmt = stmt.on_conflict_do_nothing(index_elements=['alert_id'])
            result = self.db.execute(stmt)
            total_inserted += result.rowcount
            
        self.db.commit()
        return total_inserted

    def get_by_id(self, alert_id: str) -> Optional[AlertModel]:
        return self.db.execute(
            select(AlertModel).where(AlertModel.alert_id == alert_id)
        ).scalar_one_or_none()

    def get_unassigned_alerts(self) -> Sequence[AlertModel]:
        """Fetch alerts that are not yet part of any incident."""
        return self.db.execute(
            select(AlertModel).where(~AlertModel.incidents.any())
        ).scalars().all()
