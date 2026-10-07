"""
Alert ingestion service.

Accepts a list of raw alert dictionaries, validates each one against the
Alert Pydantic model, and returns a structured result containing the
accepted alerts and any validation errors — without crashing the batch
when individual alerts are malformed.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.alert_repository import AlertRepository


class IngestionResult:
    """Holds the outcome of a single ingestion batch."""

    def __init__(self, total_received: int = 0) -> None:
        self.total_received: int = total_received
        self.accepted: list[Alert] = []
        self.validation_errors: list[dict[str, Any]] = []
        self.duplicates: int = 0

    @property
    def rejected(self) -> int:
        return len(self.validation_errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_received": self.total_received,
            "accepted": len(self.accepted),
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "validation_errors": self.validation_errors,
        }


def ingest_alerts(raw_alerts: list[dict[str, Any]], db: Optional[Session] = None) -> IngestionResult:
    """
    Validate each raw alert dict against the Alert model.

    Accepted alerts are stored as Alert instances on the result.
    Rejected alerts are recorded with their index and Pydantic error detail.
    In-batch duplicates (same alert_id) are tracked and ignored.
    If db is provided, accepted alerts are persisted.
    """
    result = IngestionResult(total_received=len(raw_alerts))
    seen_ids = set()
    valid_alerts = []

    for index, raw in enumerate(raw_alerts):
        alert_id = raw.get("alert_id")
        if alert_id in seen_ids:
            result.duplicates += 1
            continue

        try:
            alert = Alert.model_validate(raw)
            if alert.alert_id in seen_ids:
                result.duplicates += 1
                continue
            
            seen_ids.add(alert.alert_id)
            valid_alerts.append(alert)
        except ValidationError as exc:
            result.validation_errors.append({
                "index": index,
                "alert_id": alert_id or "<unknown>",
                "errors": exc.errors(include_url=False),
            })

    if db and valid_alerts:
        repo = AlertRepository(db)
        alerts_data = []
        from enum import Enum
        for a in valid_alerts:
            d = a.model_dump(exclude_unset=True)
            for k, v in d.items():
                if isinstance(v, Enum):
                    d[k] = v.value
            alerts_data.append(d)
        # Any alert that was already in the DB will be ignored by ON CONFLICT DO NOTHING
        inserted_count = repo.bulk_insert(alerts_data)
        
        # We can calculate DB duplicates by comparing valid_alerts length with inserted_count
        db_duplicates = len(valid_alerts) - inserted_count
        result.duplicates += db_duplicates
        
        # We only consider 'accepted' those that were actually inserted
        # But wait, for pipeline use, we might just return valid alerts as accepted.
        # Let's keep all valid alerts in result.accepted so downstream works,
        # but the actual "accepted" metric will be valid_alerts length.
        
    result.accepted = valid_alerts
    return result
