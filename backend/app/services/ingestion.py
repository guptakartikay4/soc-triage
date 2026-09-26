"""
Alert ingestion service.

Accepts a list of raw alert dictionaries, validates each one against the
Alert Pydantic model, and returns a structured result containing the
accepted alerts and any validation errors — without crashing the batch
when individual alerts are malformed.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.models.alert import Alert


class IngestionResult:
    """Holds the outcome of a single ingestion batch."""

    def __init__(self) -> None:
        self.accepted: list[Alert] = []
        self.validation_errors: list[dict[str, Any]] = []

    @property
    def total_received(self) -> int:
        return len(self.accepted) + len(self.validation_errors)

    @property
    def rejected(self) -> int:
        return len(self.validation_errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_received": self.total_received,
            "accepted": len(self.accepted),
            "rejected": self.rejected,
            "validation_errors": self.validation_errors,
        }


def ingest_alerts(raw_alerts: list[dict[str, Any]]) -> IngestionResult:
    """
    Validate each raw alert dict against the Alert model.

    Accepted alerts are stored as Alert instances on the result.
    Rejected alerts are recorded with their index and Pydantic error detail.
    """
    result = IngestionResult()

    for index, raw in enumerate(raw_alerts):
        try:
            alert = Alert.model_validate(raw)
            result.accepted.append(alert)
        except ValidationError as exc:
            result.validation_errors.append({
                "index": index,
                "alert_id": raw.get("alert_id", "<unknown>"),
                "errors": exc.errors(include_url=False),
            })

    return result
