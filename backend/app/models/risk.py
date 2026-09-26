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
    critical = "Critical"   # 80–100
    high     = "High"       # 60–79
    medium   = "Medium"     # 40–59
    low      = "Low"        # 0–39


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
    priority          : Low / Medium / High / Critical band
    components        : individual normalised component scores
    explanation       : human-readable summary of the primary drivers
    """

    incident_id:  str
    risk_score:   float = Field(ge=0.0, le=100.0)
    priority:     RiskPriority
    components:   RiskComponentScores
    explanation:  str
