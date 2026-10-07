"""
API request and response schemas for Task 10 SOC Dashboard and API integration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

from app.models.brief import IncidentBrief
from app.models.incident import CorrelationEdge
from app.models.mitre import IncidentMITREContext
from app.models.risk import RiskPriority


class IncidentSummaryResponse(BaseModel):
    """Compact summary of a triaged incident for the queue view."""
    incident_id: str
    priority: RiskPriority
    risk_score: float
    risk_explanation: str
    start_time: datetime
    end_time: datetime
    alert_count: int
    affected_assets: list[str]
    asset_criticality: list[str]
    users: list[str]
    mitre_techniques: list[str]
    correlation_evidence_summary: str
    has_brief: bool = False
    analyst_action: Optional[str] = None


class AlertDetailItem(BaseModel):
    """Detailed representation of an individual alert within an incident."""
    alert_id: str
    timestamp: datetime
    source: str
    alert_type: str
    severity: str
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    asset_id: str
    asset_criticality: str
    ioc: Optional[str] = None
    description: str
    mitre_technique: Optional[str] = None


class AnalystActionRecord(BaseModel):
    """Record of a human analyst action taken on an incident."""
    incident_id: str
    action: str
    timestamp: datetime
    note: Optional[str] = None
    triage_time_seconds: Optional[float] = None


class AnalystActionRequest(BaseModel):
    """Request payload to record an analyst action."""
    action: str
    note: Optional[str] = None
    timestamp: Optional[datetime] = None


class IncidentBriefResponse(IncidentBrief):
    """Enriched briefing response including generation source metadata."""
    generation_source: str = "deterministic_fallback"
    is_fallback: bool = True


class IncidentDetailResponse(BaseModel):
    """Full detail of a triaged incident for the detail panel."""
    incident_id: str
    priority: RiskPriority
    risk_score: float
    risk_explanation: str
    severity_score: float
    asset_criticality_score: float
    correlation_strength_score: float
    evidence_strength_score: float
    attack_context_score: float
    start_time: datetime
    end_time: datetime
    alert_count: int
    alert_ids: list[str]
    timeline: list[AlertDetailItem]
    affected_assets: list[str]
    asset_criticality: list[str]
    users: list[str]
    source_ips: list[str]
    destination_ips: list[str]
    iocs: list[str]
    correlation_score: float
    correlation_evidence: list[CorrelationEdge]
    mitre_context: IncidentMITREContext
    brief: Optional[IncidentBriefResponse] = None
    analyst_action: Optional[AnalystActionRecord] = None


class DashboardMetricsResponse(BaseModel):
    """Top-level metrics for SOC dashboard summary cards."""
    alerts_ingested: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    average_risk: float
    triaged_count: int
    average_mttt_seconds: Optional[float] = None
    median_mttt_seconds: Optional[float] = None
    mttt_baseline: str = "Baseline not yet measured"
