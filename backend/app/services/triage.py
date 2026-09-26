"""
End-to-end SOC triage pipeline.

Entry point
-----------
    run_triage(alerts: list[Alert]) -> list[TriagedIncident]

Pipeline stages
---------------
1. Correlation   — group alerts into Incidents (Task 5)
2. Risk scoring  — assess each Incident (Task 6)
3. Flattening    — merge Incident + RiskAssessment into TriagedIncident
4. Prioritization — sort by risk_score desc, then deterministic tie-breakers

Prioritization order
--------------------
1. risk_score            descending  (highest risk first)
2. _PRIORITY_RANK[priority] descending  (Critical > High > Medium > Low)
3. start_time            ascending   (earlier incidents first among ties)
4. incident_id           ascending   (lexicographic, for fully stable sort)

The risk engine (Task 6) is the ONLY source of risk_score and priority.
This service does NOT recompute risk.
"""

from __future__ import annotations

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.risk import RiskAssessment, RiskPriority
from app.models.triage import TriagedIncident
from app.services.correlation import correlate_alerts
from app.services.risk import assess_risk

# ---------------------------------------------------------------------------
# Priority sort rank (higher = more severe)
# ---------------------------------------------------------------------------

_PRIORITY_RANK: dict[RiskPriority, int] = {
    RiskPriority.low:      0,
    RiskPriority.medium:   1,
    RiskPriority.high:     2,
    RiskPriority.critical: 3,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_incident_alerts(
    incident: Incident,
    alert_map: dict[str, Alert],
) -> list[Alert]:
    """Return the Alert objects that belong to this Incident, in alert_id order."""
    return [alert_map[aid] for aid in incident.alert_ids if aid in alert_map]


def _merge(incident: Incident, assessment: RiskAssessment) -> TriagedIncident:
    """Flatten an Incident + RiskAssessment into a single TriagedIncident."""
    c = assessment.components
    return TriagedIncident(
        # -- Incident fields --
        incident_id=incident.incident_id,
        alert_ids=incident.alert_ids,
        start_time=incident.start_time,
        end_time=incident.end_time,
        correlation_score=incident.correlation_score,
        correlation_evidence=incident.correlation_evidence,
        # -- Risk fields (verbatim from Task 6) --
        risk_score=assessment.risk_score,
        priority=assessment.priority,
        severity_score=c.severity,
        asset_criticality_score=c.asset_criticality,
        correlation_strength_score=c.correlation_strength,
        evidence_strength_score=c.evidence_strength,
        attack_context_score=c.attack_context,
        explanation=assessment.explanation,
    )


def _sort_key(ti: TriagedIncident) -> tuple:
    """
    Deterministic four-level sort key.

    Negated floats / rank to achieve descending order on the primary
    and secondary keys while ascending on the remaining two.
    """
    return (
        -ti.risk_score,                    # 1. highest risk first
        -_PRIORITY_RANK[ti.priority],      # 2. Critical > High > Medium > Low
        ti.start_time,                     # 3. earlier incidents first
        ti.incident_id,                    # 4. lexicographic (INC-001 < INC-002)
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_triage(alerts: list[Alert]) -> list[TriagedIncident]:
    """
    Run the full SOC triage pipeline and return a prioritized list of
    enriched incidents.

    Parameters
    ----------
    alerts : list[Alert]
        Normalized Alert objects (may be empty).

    Returns
    -------
    list[TriagedIncident]
        Every incident (including single-alert ones) enriched with risk
        information, sorted highest-risk first.  Empty if alerts is empty.

    Notes
    -----
    - Deterministic: given identical input, always produces identical output.
    - Does NOT recalculate risk; delegates entirely to assess_risk().
    - Does NOT persist anything; purely in-memory.
    """
    if not alerts:
        return []

    # Stage 1: build a fast look-up map
    alert_map: dict[str, Alert] = {a.alert_id: a for a in alerts}

    # Stage 2: correlate alerts → incidents  (Task 5)
    incidents: list[Incident] = correlate_alerts(alerts)

    # Stage 3: risk-assess each incident  (Task 6) + flatten
    triaged: list[TriagedIncident] = []
    for incident in incidents:
        incident_alerts = _collect_incident_alerts(incident, alert_map)
        assessment: RiskAssessment = assess_risk(incident, incident_alerts)
        triaged.append(_merge(incident, assessment))

    # Stage 4: sort by deterministic priority key
    triaged.sort(key=_sort_key)

    return triaged
