import time
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import get_settings
from app.database.models import TriageRunModel, AlertModel, IncidentModel, CorrelationEdgeModel, MitreMappingModel, BriefingModel, AnalystDecisionModel, TriageMetricModel
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.briefing_repository import BriefingRepository
from app.services.ingestion import ingest_alerts
from app.services.correlation import correlate_alerts
from app.services.mitre import build_mitre_context
from app.services.risk import assess_risk
from app.services.briefing import generate_incident_brief
from app.models.triage import TriagedIncident

settings = get_settings()

def reset_database(db: Session):
    """Wipes all tables for a clean run."""
    # SQLite/Postgres friendly delete
    db.query(AnalystDecisionModel).delete()
    db.query(BriefingModel).delete()
    db.query(MitreMappingModel).delete()
    db.query(CorrelationEdgeModel).delete()
    db.query(TriageMetricModel).delete()
    
    # Association table
    db.execute(text("DELETE FROM incident_alerts"))
    
    db.query(IncidentModel).delete()
    db.query(AlertModel).delete()
    db.query(TriageRunModel).delete()
    db.commit()

def run_triage_pipeline(db: Session, alerts_data: list[dict], source: str, reset: bool = False) -> dict:
    """
    Orchestrates the full SOC triage pipeline.
    """
    if reset:
        reset_database(db)
        
    start_time = time.time()
    timings = {}
    
    # 1. Ingest
    t0 = time.time()
    ingestion_result = ingest_alerts(alerts_data, db=db)
    timings["ingest"] = round(time.time() - t0, 3)
    db.commit() # Ensure alerts are available
    
    # 2. Fetch unassigned alerts
    alert_repo = AlertRepository(db)
    unassigned_alerts = alert_repo.get_unassigned_alerts()
    if not unassigned_alerts:
        return {
            "status": "success",
            "alerts_processed": ingestion_result.total_received,
            "incidents_created": 0,
            "timings": timings,
            "total_seconds": round(time.time() - start_time, 3)
        }
    
    # Convert ORM models to Pydantic for the engine
    from app.models.alert import Alert
    pydantic_alerts = [Alert.model_validate(a, from_attributes=True) for a in unassigned_alerts]
    
    # 3. Correlate
    t0 = time.time()
    # Provide a simple sequence generator for incident IDs
    incident_count = IncidentRepository(db).count()
    def id_generator():
        nonlocal incident_count
        incident_count += 1
        return f"INC-{incident_count:05d}"
        
    incidents = correlate_alerts(pydantic_alerts, id_generator=id_generator)
    timings["correlate"] = round(time.time() - t0, 3)
    
    # Prepare mapping for fast lookup
    alert_map = {a.alert_id: a for a in pydantic_alerts}
    
    # 4. Assess risk and enrich MITRE
    t0 = time.time()
    t0_mitre = time.time()
    
    incident_repo = IncidentRepository(db)
    briefing_repo = BriefingRepository(db)
    
    created_incidents = []
    
    for inc in incidents:
        inc_alerts = [alert_map[aid] for aid in inc.alert_ids if aid in alert_map]
        
        # Risk
        risk_assessment = assess_risk(inc, inc_alerts)
        
        # MITRE
        mitre_context = build_mitre_context(inc_alerts)
        
        # Build TriagedIncident for later AI Briefing
        ti = TriagedIncident(
            incident_id=inc.incident_id,
            alert_ids=inc.alert_ids,
            start_time=inc.start_time,
            end_time=inc.end_time,
            correlation_score=inc.correlation_score,
            correlation_evidence=inc.correlation_evidence,
            risk_score=risk_assessment.risk_score,
            priority=risk_assessment.priority,
            severity_score=risk_assessment.components.severity,
            asset_criticality_score=risk_assessment.components.asset_criticality,
            correlation_strength_score=risk_assessment.components.correlation_strength,
            evidence_strength_score=risk_assessment.components.evidence_strength,
            attack_context_score=risk_assessment.components.attack_context,
            explanation=risk_assessment.explanation,
            mitre_context=mitre_context
        )
        created_incidents.append((ti, inc_alerts, inc))
        
        # Persist Incident
        incident_data = {
            "incident_id": inc.incident_id,
            "start_time": inc.start_time,
            "end_time": inc.end_time,
            "correlation_score": inc.correlation_score,
            "status": "NEW",
            "priority": risk_assessment.priority.value,
            "risk_score": risk_assessment.risk_score,
            "risk_severity_score": risk_assessment.components.severity,
            "risk_criticality_score": risk_assessment.components.asset_criticality,
            "risk_alert_count_score": risk_assessment.components.evidence_strength, # Not exact mapping but close enough
            "risk_mitre_score": risk_assessment.components.attack_context,
            "risk_lateral_movement_score": 0.0
        }
        db_incident = incident_repo.create_incident(incident_data, inc.alert_ids)
        
        # Persist correlation edges
        if inc.correlation_evidence:
            edges_data = [
                {
                    "incident_id": db_incident.id,
                    "alert_a_id": e.alert_a,
                    "alert_b_id": e.alert_b,
                    "score": e.score,
                    "signals": "[]", # Simplified, usually dump to JSON
                    "explanation": getattr(e, "explanation", "")
                } for e in inc.correlation_evidence
            ]
            import json
            for i, e in enumerate(inc.correlation_evidence):
                edges_data[i]["signals"] = json.dumps(e.signals)
            incident_repo.add_correlation_edges(edges_data)
            
        # Persist Mitre mappings
        if mitre_context.techniques:
            mitre_data = [
                {
                    "incident_id": db_incident.id,
                    "technique_id": t.technique_id,
                    "tactic": t.tactic,
                    "reason": getattr(t, "reason", ""),
                    "source": getattr(t, "source", ""),
                    "in_catalogue": getattr(t, "in_catalogue", True)
                } for t in mitre_context.techniques
            ]
            incident_repo.add_mitre_mappings(mitre_data)
            
        # Initialize Triage Metrics (MTTT start point)
        min_created_at = min([a.timestamp for a in inc_alerts]) if inc_alerts else inc.start_time
        metric = TriageMetricModel(
            incident_id=db_incident.id,
            alert_received_at=min_created_at
        )
        db.add(metric)
        db.flush()
        
    timings["risk_and_mitre"] = round(time.time() - t0, 3)
    db.commit() # Save incidents
    
    # 5. Briefings (capped at AI_BRIEF_MAX_PER_RUN)
    t0 = time.time()
    # Sort incidents by risk to prioritize briefings
    created_incidents.sort(key=lambda x: x[0].risk_score, reverse=True)
    
    ai_count = 0
    max_ai = settings.ai_brief_max_per_run
    
    for ti, inc_alerts, _ in created_incidents:
        db_incident = incident_repo.get_by_id(ti.incident_id)
        if not db_incident:
            continue
            
        # Determine if we should attempt AI
        force_fallback = True
        if ti.priority.value in ("P1", "P2") and ai_count < max_ai:
            force_fallback = False
            ai_count += 1
            
        brief = generate_incident_brief(ti, inc_alerts, force_fallback=force_fallback)
        
        # Persist briefing
        import json
        assets = sorted({a.asset_id for a in inc_alerts if getattr(a, "asset_id", None)})
        brief_data = {
            "incident_id": db_incident.id,
            "summary": brief.summary,
            "attack_vector": brief.why_it_matters,
            "impact": "\n".join(brief.key_evidence),
            "recommendation": "\n".join(brief.recommended_next_steps),
            "affected_assets": json.dumps(assets),
            "model_name": getattr(brief, "generation_source", "deterministic_fallback")
        }
        briefing_repo.save_briefing(brief_data)
        
    timings["briefings"] = round(time.time() - t0, 3)
    db.commit()
    
    total_seconds = round(time.time() - start_time, 3)
    
    # Log run
    run_model = TriageRunModel(
        run_id=str(uuid.uuid4()),
        started_at=datetime.fromtimestamp(start_time, tz=timezone.utc),
        completed_at=datetime.now(timezone.utc),
        alerts_processed=ingestion_result.total_received,
        incidents_created=len(created_incidents),
        total_seconds=total_seconds,
        source=source,
        timing_ingest=timings.get("ingest"),
        timing_correlate=timings.get("correlate"),
        timing_mitre=timings.get("risk_and_mitre"),
        timing_briefing=timings.get("briefings")
    )
    db.add(run_model)
    db.commit()
    
    return {
        "status": "success",
        "alerts_processed": ingestion_result.total_received,
        "incidents_created": len(created_incidents),
        "timings": timings,
        "total_seconds": total_seconds
    }
