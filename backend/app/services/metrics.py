import statistics
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.models import TriageMetricModel
from app.core.config import get_settings

def get_metrics(db: Session) -> dict:
    """
    Calculate and return aggregate metrics for triage times.
    """
    settings = get_settings()
    
    metrics = db.query(TriageMetricModel.triage_seconds).filter(
        TriageMetricModel.triage_seconds.isnot(None)
    ).all()
    
    times = [m[0] for m in metrics if m[0] is not None]
    
    count = len(times)
    if count == 0:
        return {
            "count": 0,
            "mean_seconds": None,
            "median_seconds": None,
            "p90_seconds": None,
            "baseline_source": "not_configured" if not settings.mttt_baseline_minutes else "configured_assumption",
            "reduction_percent": None
        }
        
    mean = statistics.mean(times)
    median = statistics.median(times)
    
    # Calculate P90
    sorted_times = sorted(times)
    index = int(0.9 * count)
    p90 = sorted_times[index] if index < count else sorted_times[-1]
    
    baseline = settings.mttt_baseline_minutes
    baseline_source = "configured_assumption" if baseline else "not_configured"
    
    reduction_percent = None
    if baseline:
        baseline_seconds = baseline * 60
        reduction_percent = ((baseline_seconds - mean) / baseline_seconds) * 100
        reduction_percent = round(max(reduction_percent, 0.0), 2)
        
    return {
        "count": count,
        "mean_seconds": round(mean, 2),
        "median_seconds": round(median, 2),
        "p90_seconds": round(p90, 2),
        "baseline_source": baseline_source,
        "reduction_percent": reduction_percent
    }
