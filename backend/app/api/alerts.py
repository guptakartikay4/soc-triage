"""
POST /api/alerts/ingest

Accepts a JSON batch of raw SOC alerts, runs them through the ingestion
service, and returns a normalisation summary.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.ingestion import ingest_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class IngestRequest(BaseModel):
    alerts: list[dict[str, Any]]


class ValidationErrorDetail(BaseModel):
    index: int
    alert_id: str
    errors: list[dict[str, Any]]


class IngestResponse(BaseModel):
    total_received: int
    accepted: int
    rejected: int
    validation_errors: list[ValidationErrorDetail]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/ingest", response_model=IngestResponse, status_code=200)
def ingest(body: IngestRequest) -> IngestResponse:
    """
    Normalise a batch of raw SOC alerts.

    Each alert is validated independently; a bad alert is rejected with
    structured error detail without affecting the rest of the batch.
    """
    result = ingest_alerts(body.alerts)
    return IngestResponse(
        total_received=result.total_received,
        accepted=len(result.accepted),
        rejected=result.rejected,
        validation_errors=[
            ValidationErrorDetail(**e) for e in result.validation_errors
        ],
    )
