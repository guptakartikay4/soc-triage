from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.metrics import get_metrics
from app.models.api import DashboardMetricsResponse
from app.database.models import IncidentModel, AlertModel
from sqlalchemy import func

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

@router.get("/overview", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """
    Return top-level summary metrics for SOC dashboard cards.
    """
    total_alerts = db.query(func.count(AlertModel.id)).scalar() or 0
    total_incidents = db.query(func.count(IncidentModel.id)).scalar() or 0
    
    critical_incidents = db.query(func.count(IncidentModel.id)).filter(IncidentModel.priority == "P1").scalar() or 0
    high_incidents = db.query(func.count(IncidentModel.id)).filter(IncidentModel.priority == "P2").scalar() or 0
    medium_incidents = db.query(func.count(IncidentModel.id)).filter(IncidentModel.priority == "P3").scalar() or 0
    low_incidents = db.query(func.count(IncidentModel.id)).filter(IncidentModel.priority == "P4").scalar() or 0
    
    avg_risk = db.query(func.avg(IncidentModel.risk_score)).scalar() or 0.0
    
    # Triaged count = number of incidents not in NEW state
    triaged_count = db.query(func.count(IncidentModel.id)).filter(IncidentModel.status != "NEW").scalar() or 0
    
    mttt_stats = get_metrics(db)
    
    return DashboardMetricsResponse(
        alerts_ingested=total_alerts,
        total_incidents=total_incidents,
        critical_incidents=critical_incidents,
        high_incidents=high_incidents,
        medium_incidents=medium_incidents,
        low_incidents=low_incidents,
        average_risk=round(avg_risk, 2),
        triaged_count=triaged_count,
        average_mttt_seconds=mttt_stats["mean_seconds"],
        median_mttt_seconds=mttt_stats["median_seconds"],
        mttt_baseline=mttt_stats["baseline_source"]
    )
