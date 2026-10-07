"""
POST /api/alerts/ingest

Accepts a JSON batch of raw SOC alerts, runs them through the ingestion
service, and returns a normalisation summary.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Any
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.ingestion import ingest_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

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

@router.post("/ingest", response_model=IngestResponse, status_code=200)
def ingest(body: IngestRequest, db: Session = Depends(get_db)) -> IngestResponse:
    """
    Normalise and persist a batch of raw SOC alerts.
    """
    result = ingest_alerts(body.alerts, db=db)
    return IngestResponse(
        total_received=result.total_received,
        accepted=len(result.accepted),
        rejected=result.rejected,
        validation_errors=[
            ValidationErrorDetail(**e) for e in result.validation_errors
        ],
    )
