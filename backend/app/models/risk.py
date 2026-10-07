"""
Risk assessment model.

Produced by the risk engine for a single Incident.
No AI, no database, no external calls.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskPriority(str, Enum):
    """Named priority bands derived from the numeric risk score."""
    P1 = "P1"       # 80–100 (Critical)
    P2 = "P2"       # 60–79 (High)
    P3 = "P3"       # 40–59 (Medium)
    P4 = "P4"       # 0–39 (Low)


class RiskComponentScores(BaseModel):
    """
    The individual normalised component scores (each 0–100) that were
    combined to produce the final risk score.  Stored for auditability.
    """
    severity:             float   # max severity across alerts in the incident
    asset_criticality:    float   # max asset criticality across alerts
    correlation_strength: float   # derived from Incident.correlation_score
    evidence_strength:    float   # alert count + unique IOCs + unique techniques
    attack_context:       float   # MITRE technique presence + description signals


class RiskAssessment(BaseModel):
    """
    Deterministic risk assessment for one Incident.

    Fields
    ------
    incident_id       : mirrors the source Incident.incident_id
    risk_score        : 0–100, two decimal places
    priority          : P1 / P2 / P3 / P4 band
    components        : individual normalised component scores
    contributions     : weighted points per component, summing to the score
    explanation       : human-readable summary of the primary drivers
    """

    incident_id:  str
    risk_score:   float = Field(ge=0.0, le=100.0)
    priority:     RiskPriority
    components:   RiskComponentScores
    contributions: dict[str, float]
    explanation:  str
