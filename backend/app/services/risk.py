"""
Deterministic risk engine.

Entry point
-----------
    assess_risk(incident: Incident, alerts: list[Alert]) -> RiskAssessment

Formula
-------
    risk = 0.30 × severity_score
         + 0.30 × asset_criticality_score
         + 0.15 × correlation_strength_score
         + 0.15 × evidence_strength_score
         + 0.10 × attack_context_score

All component inputs are normalised to [0, 100].
The final score is clamped to [0, 100].

Priority thresholds
-------------------
    80–100  →  Critical
    60–79   →  High
    40–59   →  Medium
    0–39    →  Low

No AI, no database, no randomness.  Given the same Incident and Alert
objects the function always returns the same RiskAssessment.
"""

from __future__ import annotations

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.incident import Incident
from app.models.risk import RiskAssessment, RiskComponentScores, RiskPriority

# ---------------------------------------------------------------------------
# Formula weights (must sum to 1.0)
# ---------------------------------------------------------------------------

_W_SEVERITY             = 0.30
_W_ASSET_CRITICALITY    = 0.30
_W_CORRELATION_STRENGTH = 0.15
_W_EVIDENCE_STRENGTH    = 0.15
_W_ATTACK_CONTEXT       = 0.10

# ---------------------------------------------------------------------------
# Priority thresholds
# ---------------------------------------------------------------------------

_THRESHOLD_CRITICAL = 80.0
_THRESHOLD_HIGH     = 60.0
_THRESHOLD_MEDIUM   = 40.0

# ---------------------------------------------------------------------------
# Ordinal maps (to [0, 100] in equal steps)
# ---------------------------------------------------------------------------

_SEVERITY_SCORE: dict[SeverityLevel, float] = {
    SeverityLevel.low:      25.0,
    SeverityLevel.medium:   50.0,
    SeverityLevel.high:     75.0,
    SeverityLevel.critical: 100.0,
}

_CRITICALITY_SCORE: dict[AssetCriticality, float] = {
    AssetCriticality.low:      25.0,
    AssetCriticality.medium:   50.0,
    AssetCriticality.high:     75.0,
    AssetCriticality.critical: 100.0,
}

# ---------------------------------------------------------------------------
# Keyword signals used for attack context
# ---------------------------------------------------------------------------

_ATTACK_KEYWORDS = frozenset({
    "exploit", "injection", "lateral", "exfil", "ransomware",
    "mimikatz", "credential", "dump", "shell", "backdoor",
    "c2", "beacon", "spray", "brute", "privilege", "escalat",
    "persist", "golden ticket", "dcsync", "encoded", "payload",
    "webshell", "web shell", "lsass", "shadow copy", "powershell",
    "wmi", "scheduled task", "lolbin",
})


# ---------------------------------------------------------------------------
# Component calculators
# ---------------------------------------------------------------------------

def _severity_component(alerts: list[Alert]) -> float:
    """
    Return the normalised severity score (0–100).

    Uses the *maximum* severity observed across all alerts in the incident
    so that a single critical alert drives the score upward.
    """
    if not alerts:
        return 0.0
    return max(_SEVERITY_SCORE[a.severity] for a in alerts)


def _asset_criticality_component(alerts: list[Alert]) -> float:
    """
    Return the normalised asset-criticality score (0–100).

    Uses the *maximum* asset criticality across all alerts.
    """
    if not alerts:
        return 0.0
    return max(_CRITICALITY_SCORE[a.asset_criticality] for a in alerts)


def _correlation_strength_component(incident: Incident) -> float:
    """
    Map Incident.correlation_score (0.0–1.0) linearly to 0–100.

    A single-alert incident has correlation_score == 0.0 → 0.0.
    A perfectly correlated pair → 100.0.
    """
    return round(min(incident.correlation_score * 100.0, 100.0), 6)


def _evidence_strength_component(alerts: list[Alert]) -> float:
    """
    Score based on observable evidence richness (0–100).

    Factors (each capped to prevent one dimension dominating):
    - Alert count          : up to 40 pts  (saturates at 8+ alerts)
    - Unique IOCs          : up to 30 pts  (saturates at 3+ IOCs)
    - Unique MITRE IDs     : up to 30 pts  (saturates at 3+ techniques)
    """
    if not alerts:
        return 0.0

    count = len(alerts)
    count_pts = min(count / 8.0, 1.0) * 40.0

    unique_iocs = len({a.ioc for a in alerts if a.ioc and a.ioc.strip()})
    ioc_pts = min(unique_iocs / 3.0, 1.0) * 30.0

    unique_techniques = len(
        {a.mitre_technique for a in alerts
         if a.mitre_technique and a.mitre_technique.strip()}
    )
    technique_pts = min(unique_techniques / 3.0, 1.0) * 30.0

    return round(count_pts + ioc_pts + technique_pts, 6)


def _attack_context_component(alerts: list[Alert]) -> float:
    """
    Score based on MITRE technique presence and attack keyword density
    in alert descriptions (0–100).

    Factors:
    - MITRE technique presence : up to 50 pts (saturates at 2+ techniques)
    - Keyword hits in descriptions : up to 50 pts (saturates at 4+ hits)
    """
    if not alerts:
        return 0.0

    # MITRE presence
    unique_techniques = len(
        {a.mitre_technique for a in alerts
         if a.mitre_technique and a.mitre_technique.strip()}
    )
    technique_pts = min(unique_techniques / 2.0, 1.0) * 50.0

    # Keyword hits across all descriptions (de-duplicated per alert)
    keyword_hits = 0
    for alert in alerts:
        desc_lower = alert.description.lower()
        if any(kw in desc_lower for kw in _ATTACK_KEYWORDS):
            keyword_hits += 1

    keyword_pts = min(keyword_hits / 4.0, 1.0) * 50.0

    return round(technique_pts + keyword_pts, 6)


# ---------------------------------------------------------------------------
# Priority band
# ---------------------------------------------------------------------------

def _priority(score: float) -> RiskPriority:
    if score >= _THRESHOLD_CRITICAL:
        return RiskPriority.critical
    if score >= _THRESHOLD_HIGH:
        return RiskPriority.high
    if score >= _THRESHOLD_MEDIUM:
        return RiskPriority.medium
    return RiskPriority.low


# ---------------------------------------------------------------------------
# Explanation builder
# ---------------------------------------------------------------------------

def _build_explanation(
    alerts: list[Alert],
    components: RiskComponentScores,
    priority: RiskPriority,
) -> str:
    """
    Produce a concise, human-readable description of the primary risk drivers.
    The explanation is fully deterministic — it contains no random elements.
    """
    parts: list[str] = []

    # Asset criticality
    max_crit = max((_CRITICALITY_SCORE[a.asset_criticality] for a in alerts), default=0.0)
    if max_crit >= 100.0:
        parts.append("critical asset")
    elif max_crit >= 75.0:
        parts.append("high-criticality asset")
    elif max_crit >= 50.0:
        parts.append("medium-criticality asset")

    # Severity
    max_sev = max((_SEVERITY_SCORE[a.severity] for a in alerts), default=0.0)
    if max_sev >= 100.0:
        parts.append("critical severity activity")
    elif max_sev >= 75.0:
        parts.append("high severity activity")
    elif max_sev >= 50.0:
        parts.append("medium severity activity")

    # Alert count
    n = len(alerts)
    if n == 1:
        parts.append("1 alert")
    else:
        parts.append(f"{n} correlated alerts")

    # MITRE techniques
    techniques = sorted(
        {a.mitre_technique for a in alerts
         if a.mitre_technique and a.mitre_technique.strip()}
    )
    if techniques:
        count = len(techniques)
        label = "MITRE technique" if count == 1 else "MITRE techniques"
        parts.append(f"{count} {label} ({', '.join(techniques[:3])}{'...' if count > 3 else ''})")

    # IOCs
    iocs = {a.ioc for a in alerts if a.ioc and a.ioc.strip()}
    if iocs:
        parts.append(f"{len(iocs)} unique IOC{'s' if len(iocs) > 1 else ''}")

    sentence = "; ".join(parts).capitalize() + "."
    return f"[{priority.value}] {sentence}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assess_risk(incident: Incident, alerts: list[Alert]) -> RiskAssessment:
    """
    Produce a deterministic RiskAssessment for the given Incident.

    Parameters
    ----------
    incident : Incident
        The correlated incident from the correlation service.
    alerts : list[Alert]
        The Alert objects whose alert_ids are listed in incident.alert_ids.
        The caller is responsible for providing only the alerts that belong
        to this incident; extra alerts are ignored if they are present.

    Returns
    -------
    RiskAssessment
        Fully populated, deterministic risk assessment.
    """
    # Filter to only the alerts that belong to this incident
    incident_alert_set = set(incident.alert_ids)
    relevant = [a for a in alerts if a.alert_id in incident_alert_set]

    # Compute components
    sev   = _severity_component(relevant)
    crit  = _asset_criticality_component(relevant)
    corr  = _correlation_strength_component(incident)
    evid  = _evidence_strength_component(relevant)
    ctx   = _attack_context_component(relevant)

    components = RiskComponentScores(
        severity=sev,
        asset_criticality=crit,
        correlation_strength=corr,
        evidence_strength=evid,
        attack_context=ctx,
    )

    # Final weighted score, clamped to [0, 100]
    raw = (
        _W_SEVERITY             * sev
        + _W_ASSET_CRITICALITY  * crit
        + _W_CORRELATION_STRENGTH * corr
        + _W_EVIDENCE_STRENGTH  * evid
        + _W_ATTACK_CONTEXT     * ctx
    )
    risk_score = round(min(max(raw, 0.0), 100.0), 2)

    priority = _priority(risk_score)
    explanation = _build_explanation(relevant, components, priority)

    return RiskAssessment(
        incident_id=incident.incident_id,
        risk_score=risk_score,
        priority=priority,
        components=components,
        explanation=explanation,
    )
