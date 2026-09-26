"""
MITRE ATT&CK security context models (Task 8).

Defines Pydantic models for representing MITRE ATT&CK techniques,
per-technique evidence within an incident, and aggregated incident-level
MITRE context.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class MITRETechnique(BaseModel):
    """
    Reference model for a MITRE ATT&CK technique or sub-technique.

    Fields
    ------
    technique_id : Official technique or sub-technique ID (e.g. 'T1059.001')
    name         : Human-readable technique/sub-technique name
    tactic       : Associated MITRE ATT&CK tactic (e.g. 'Execution')
    """
    technique_id: str
    name: str
    tactic: str


class MITRETechniqueContext(BaseModel):
    """
    Security context for a single MITRE technique identified within an incident,
    including all supporting alert IDs.

    Fields
    ------
    technique_id : Official technique or sub-technique ID (e.g. 'T1059.001')
    name         : Human-readable technique name or fallback for unknown IDs
    tactic       : MITRE ATT&CK tactic or fallback for unknown IDs
    alert_ids    : Deterministically sorted list of alert IDs supporting this technique
    """
    technique_id: str
    name: str
    tactic: str
    alert_ids: list[str] = Field(default_factory=list)


class IncidentMITREContext(BaseModel):
    """
    Aggregated MITRE ATT&CK context for an entire incident.

    Fields
    ------
    techniques      : Deterministically sorted list (by technique_id asc) of technique contexts
    technique_count : Count of distinct MITRE techniques present in the incident
    """
    techniques: list[MITRETechniqueContext] = Field(default_factory=list)
    technique_count: int = 0
