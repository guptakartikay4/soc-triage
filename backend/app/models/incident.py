"""
Incident model.

An Incident groups one or more correlated Alert objects and records
the evidence that connected them.  Risk scoring and prioritisation are
deliberately NOT included here; they belong to a future task.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CorrelationEdge(BaseModel):
    """Records why two specific alerts were placed in the same incident."""

    alert_a: str          # alert_id of the first alert
    alert_b: str          # alert_id of the second alert
    score: float          # computed correlation score (0.0–1.0)
    signals: list[str]    # names of the signals that fired, e.g. ["host", "user", "time"]


class Incident(BaseModel):
    """
    A collection of correlated alerts that likely belong to the same
    real-world event or attack chain.
    """

    incident_id: str                              # e.g. "INC-001"
    alert_ids: list[str]                          # chronologically ordered
    start_time: datetime                          # timestamp of the earliest alert
    end_time: datetime                            # timestamp of the latest alert
    correlation_score: float                      # mean edge score within the incident
    correlation_evidence: list[CorrelationEdge]   # one entry per correlated pair
