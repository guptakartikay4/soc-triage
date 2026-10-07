from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import os
import csv
from pathlib import Path

from app.database.connection import get_db
from app.services.pipeline import run_triage_pipeline

router = APIRouter(prefix="/api/triage", tags=["triage"])

class RunTriageRequest(BaseModel):
    source: str = "dataset" # dataset or payload
    reset: bool = False

@router.post("/run")
def run_triage(payload: RunTriageRequest, db: Session = Depends(get_db)):
    """
    Run the full triage pipeline.
    """
    alerts_data = []
    if payload.source == "dataset":
        # Load from synthetic_alerts.csv
        csv_path = Path(__file__).parent.parent.parent / "data" / "synthetic_alerts.csv"
        if csv_path.exists():
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                alerts_data = [row for row in reader]
    else:
        # We would use payload alerts if we had them in the request
        pass
        
    result = run_triage_pipeline(db, alerts_data, source=payload.source, reset=payload.reset)
    return result
