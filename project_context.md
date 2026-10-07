# SOC Triage Project Context

This document contains the complete file structure and key code components for our SOC-Triage project (AI-assisted SOC alert triage and incident prioritization platform). This context should provide a complete understanding of the project's current state.

## 1. Project Directory Structure

```text
.
├── .gitignore
├── README.md
├── project_context.md
└── backend
    ├── requirements.txt
    ├── app
    │   ├── main.py
    │   ├── __init__.py
    │   ├── api
    │   │   ├── alerts.py
    │   │   ├── incidents.py
    │   │   └── __init__.py
    │   ├── models
    │   │   ├── alert.py
    │   │   ├── api.py
    │   │   ├── brief.py
    │   │   ├── incident.py
    │   │   ├── mitre.py
    │   │   ├── risk.py
    │   │   ├── triage.py
    │   │   └── __init__.py
    │   ├── services
    │   │   ├── briefing.py
    │   │   ├── correlation.py
    │   │   ├── ingestion.py
    │   │   ├── mitre.py
    │   │   ├── repository.py
    │   │   ├── risk.py
    │   │   ├── triage.py
    │   │   └── __init__.py
    │   └── static
    │       └── index.html
    ├── data
    │   ├── assets.csv
    │   ├── generate_dataset.py
    │   └── synthetic_alerts.csv
    └── tests
        ├── test_alert_model.py
        ├── test_api.py
        ├── test_briefing.py
        ├── test_correlation.py
        ├── test_dataset.py
        ├── test_health.py
        ├── test_ingestion.py
        ├── test_mitre.py
        ├── test_risk.py
        └── test_triage.py
```

## 2. Core Application Setup (`backend/app/main.py`)

This is the main entry point for the FastAPI application.

```python
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router

app = FastAPI(title="SOC Triage API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts_router)
app.include_router(incidents_router)

INDEX_HTML_PATH = Path(__file__).parent / "static" / "index.html"

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    if INDEX_HTML_PATH.exists():
        return HTMLResponse(content=INDEX_HTML_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SOC Triage Dashboard</h1><p>Dashboard UI loading...</p>")
```

## 3. Data Models (`backend/app/models/`)

### `alert.py`
```python
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel

class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class AssetCriticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    source: str
    alert_type: str
    severity: SeverityLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    asset_id: str
    asset_criticality: AssetCriticality
    ioc: Optional[str] = None
    description: str
    mitre_technique: Optional[str] = None
```

### `incident.py`
```python
from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel

class CorrelationEdge(BaseModel):
    """Records why two specific alerts were placed in the same incident."""
    alert_a: str          # alert_id of the first alert
    alert_b: str          # alert_id of the second alert
    score: float          # computed correlation score (0.0–1.0)
    signals: list[str]    # names of the signals that fired, e.g. ["host", "user", "time"]

class Incident(BaseModel):
    """
    A collection of correlated alerts that likely belong to the same
    real-world event or attack chain.
    """
    incident_id: str                              # e.g. "INC-001"
    alert_ids: list[str]                          # chronologically ordered
    start_time: datetime                          # timestamp of the earliest alert
    end_time: datetime                            # timestamp of the latest alert
    correlation_score: float                      # mean edge score within the incident
    correlation_evidence: list[CorrelationEdge]   # one entry per correlated pair
```

## 4. API Endpoints (`backend/app/api/`)

### `alerts.py`
```python
from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from pydantic import BaseModel
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
def ingest(body: IngestRequest) -> IngestResponse:
    """
    Normalise a batch of raw SOC alerts.
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
```

## 5. Summary of Architecture

- **Framework:** FastAPI (Python)
- **Data Models:** Pydantic (Alert, Incident, Risk, Triage, etc.)
- **Services layer:** Handles business logic including alert ingestion, correlation into incidents, mapping to MITRE ATT&CK techniques, risk scoring, and triaging/briefing.
- **Data layer:** Uses CSVs (`assets.csv`, `synthetic_alerts.csv`) and `generate_dataset.py` to create a mock database of alerts.
- **Tests:** A full test suite using `pytest` is present in the `tests/` directory covering models, APIs, and all services.
- **Frontend:** There is a static UI (`index.html`) served from `app/static/` at the root `/` and `/dashboard` endpoints.
