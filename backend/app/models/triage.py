"""
Triage pipeline output model.

A TriagedIncident is a flat, API-ready view of one correlated incident
enriched with the Task 6 risk assessment.  It contains every field that
a future API, frontend, or evaluation script will need without requiring
the caller to join two separate objects.

No new risk formula is introduced here.  All risk_score / priority /
component values are taken verbatim from the existing RiskAssessment
produced by app.services.risk.assess_risk.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.incident import CorrelationEdge
from app.models.risk import RiskPriority


class TriagedIncident(BaseModel):
    """
    A correlated incident enriched with deterministic risk information,
    ready for prioritized display or downstream processing.

    Incident fields
    ---------------
    incident_id            : e.g. "INC-001"
    alert_ids              : chronologically ordered alert IDs
    start_time             : timestamp of the earliest alert
    end_time               : timestamp of the latest alert
    correlation_score      : mean edge score within the incident (0.0–1.0)
    correlation_evidence   : one entry per correlated alert pair

    Risk fields (from Task 6 RiskAssessment — never recalculated here)
    -----------
    risk_score             : 0–100 (two decimal places)
    priority               : Low / Medium / High / Critical
    severity_score         : normalised max-severity component (0–100)
    asset_criticality_score: normalised max-asset-criticality component (0–100)
    correlation_strength_score : normalised correlation component (0–100)
    evidence_strength_score    : normalised evidence component (0–100)
    attack_context_score       : normalised attack-context component (0–100)
    explanation            : human-readable summary of primary risk drivers
    """

    # -- Incident fields --
    incident_id:           str
    alert_ids:             list[str]
    start_time:            datetime
    end_time:              datetime
    correlation_score:     float
    correlation_evidence:  list[CorrelationEdge]

    # -- Risk fields (Task 6 verbatim) --
    risk_score:                  float = Field(ge=0.0, le=100.0)
    priority:                    RiskPriority
    severity_score:              float
    asset_criticality_score:     float
    correlation_strength_score:  float
    evidence_strength_score:     float
    attack_context_score:        float
    explanation:                 str
