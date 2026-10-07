from typing import Optional
from app.database.models import IncidentModel
from app.models.api import (
    IncidentSummaryResponse,
    IncidentDetailResponse,
    AlertDetailItem,
    AnalystActionRecord,
    IncidentBriefResponse
)
from app.models.incident import CorrelationEdge
from app.models.mitre import IncidentMITREContext, MITRETechniqueContext

def build_incident_summary(incident: IncidentModel) -> IncidentSummaryResponse:
    inc_alerts = incident.alerts
    assets = sorted({a.asset_id for a in inc_alerts if a.asset_id})
    criticalities = sorted({a.asset_criticality for a in inc_alerts})
    users = sorted({a.user for a in inc_alerts if a.user})
    
    mitre_list = [
        f"{m.technique_id} - {m.tactic}" 
        for m in incident.mitre_mappings
    ]
    
    action = incident.decisions[-1].decision if incident.decisions else None

    edge_count = len(incident.edges)
    if edge_count > 0:
        import json
        all_signals = set()
        for edge in incident.edges:
            try:
                signals = json.loads(edge.signals)
                all_signals.update(signals)
            except:
                pass
        all_signals = sorted(all_signals)
        sig_str = f" ({', '.join(all_signals)})" if all_signals else ""
        corr_summary = f"{edge_count} correlated pair(s){sig_str}"
    else:
        corr_summary = "Single-alert incident"
        
    # Construct explanation based on scores
    parts = []
    if incident.risk_severity_score: parts.append(f"Severity +{incident.risk_severity_score:.1f}")
    if incident.risk_criticality_score: parts.append(f"Criticality +{incident.risk_criticality_score:.1f}")
    if incident.risk_alert_count_score: parts.append(f"Evidence +{incident.risk_alert_count_score:.1f}")
    if incident.risk_mitre_score: parts.append(f"MITRE +{incident.risk_mitre_score:.1f}")
    explanation = " | ".join(parts) if parts else "No risk components"

    return IncidentSummaryResponse(
        incident_id=incident.incident_id,
        priority=incident.priority,
        risk_score=incident.risk_score or 0.0,
        risk_explanation=explanation,
        start_time=incident.start_time,
        end_time=incident.end_time,
        alert_count=len(inc_alerts),
        affected_assets=assets,
        asset_criticality=criticalities,
        users=users,
        mitre_techniques=mitre_list,
        correlation_evidence_summary=corr_summary,
        has_brief=incident.briefing is not None,
        analyst_action=action,
    )

def build_incident_detail(incident: IncidentModel) -> IncidentDetailResponse:
    inc_alerts = incident.alerts
    
    timeline = []
    for a in inc_alerts:
        timeline.append(AlertDetailItem(
            alert_id=a.alert_id,
            timestamp=a.timestamp,
            source=a.source,
            alert_type=a.alert_type,
            severity=a.severity,
            host=a.host,
            user=a.user,
            source_ip=a.source_ip,
            destination_ip=a.destination_ip,
            asset_id=a.asset_id,
            asset_criticality=a.asset_criticality,
            ioc=a.ioc,
            description=a.description,
            mitre_technique=a.mitre_technique
        ))
        
    assets = sorted({a.asset_id for a in inc_alerts if a.asset_id})
    criticalities = sorted({a.asset_criticality for a in inc_alerts})
    users = sorted({a.user for a in inc_alerts if a.user})
    source_ips = sorted({a.source_ip for a in inc_alerts if a.source_ip})
    dest_ips = sorted({a.destination_ip for a in inc_alerts if a.destination_ip})
    iocs = sorted({a.ioc for a in inc_alerts if a.ioc})
    
    # Correlation Edge parsing
    import json
    corr_edges = []
    for e in incident.edges:
        try:
            sigs = json.loads(e.signals)
        except:
            sigs = []
        corr_edges.append(CorrelationEdge(
            alert_a=e.alert_a_id,
            alert_b=e.alert_b_id,
            score=e.score,
            signals=sigs,
            explanation=e.explanation or ""
        ))
        
    # MITRE Context parsing
    techniques = []
    for m in incident.mitre_mappings:
        techniques.append(MITRETechniqueContext(
            technique_id=m.technique_id,
            name="Unknown", # Name is dropped from mapping table for brevity, normally fetched from catalog
            tactic=m.tactic,
            reason=m.reason,
            source=m.source,
            in_catalogue=m.in_catalogue,
            alert_ids=[]
        ))
    mitre_ctx = IncidentMITREContext(techniques=techniques, tactics_roll_up=[t.tactic for t in techniques])
    
    # Brief parsing
    brief_resp = None
    if incident.briefing:
        b = incident.briefing
        brief_resp = IncidentBriefResponse(
            incident_id=incident.incident_id,
            summary=b.summary,
            why_it_matters=b.attack_vector,
            key_evidence=b.impact.split("\n") if b.impact else [],
            mitre_summary=[],
            recommended_next_steps=b.recommendation.split("\n") if b.recommendation else [],
            confidence="Medium", # DB doesn't have it directly, default
            generation_source=b.model_name,
            is_fallback=b.model_name == "deterministic_fallback"
        )
        
    # Analyst action parsing
    action_resp = None
    if incident.decisions:
        d = incident.decisions[-1]
        action_resp = AnalystActionRecord(
            incident_id=incident.incident_id,
            action=d.decision,
            timestamp=d.created_at,
            note=d.notes
        )

    # Explanation reconstruct
    parts = []
    if incident.risk_severity_score: parts.append(f"Severity +{incident.risk_severity_score:.1f}")
    if incident.risk_criticality_score: parts.append(f"Criticality +{incident.risk_criticality_score:.1f}")
    if incident.risk_alert_count_score: parts.append(f"Evidence +{incident.risk_alert_count_score:.1f}")
    if incident.risk_mitre_score: parts.append(f"MITRE +{incident.risk_mitre_score:.1f}")
    explanation = " | ".join(parts) if parts else "No risk components"

    return IncidentDetailResponse(
        incident_id=incident.incident_id,
        priority=incident.priority,
        risk_score=incident.risk_score or 0.0,
        risk_explanation=explanation,
        severity_score=incident.risk_severity_score or 0.0,
        asset_criticality_score=incident.risk_criticality_score or 0.0,
        correlation_strength_score=0.0, # Approximate
        evidence_strength_score=incident.risk_alert_count_score or 0.0,
        attack_context_score=incident.risk_mitre_score or 0.0,
        start_time=incident.start_time,
        end_time=incident.end_time,
        alert_count=len(inc_alerts),
        alert_ids=[a.alert_id for a in inc_alerts],
        timeline=timeline,
        affected_assets=assets,
        asset_criticality=criticalities,
        users=users,
        source_ips=source_ips,
        destination_ips=dest_ips,
        iocs=iocs,
        correlation_score=incident.correlation_score,
        correlation_evidence=corr_edges,
        mitre_context=mitre_ctx,
        brief=brief_resp,
        analyst_action=action_resp
    )
