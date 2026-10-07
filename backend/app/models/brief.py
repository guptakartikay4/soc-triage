"""
Incident briefing models (Task 9).

Pydantic model representing a structured, evidence-grounded Tier-1 SOC analyst brief.
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field, field_validator


class IncidentBrief(BaseModel):
    """
    Evidence-grounded Tier-1 SOC analyst brief for a triaged incident.

    Fields
    ------
    incident_id            : ID of the triaged incident
    summary                : 1-3 sentences describing what occurred
    why_it_matters         : 1-2 sentences explaining why the incident was prioritized
    key_evidence           : 3-5 factual bullet points drawn from the supplied evidence
    mitre_summary          : 1 concise item per relevant MITRE technique present
    recommended_next_steps : 2-4 practical investigation/verification steps (NOT remediation)
    confidence             : High, Medium, or Low
    """

    incident_id: str
    summary: str
    why_it_matters: str
    key_evidence: list[str] = Field(default_factory=list)
    mitre_summary: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    confidence: Literal["High", "Medium", "Low"]
    generation_source: str = "deterministic_fallback"
    is_fallback: bool = True

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: str) -> str:
        if isinstance(v, str):
            v_title = v.strip().capitalize()
            if v_title in ("High", "Medium", "Low"):
                return v_title
        return v
