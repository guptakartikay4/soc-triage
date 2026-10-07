from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.connection import Base

# Association table for Incident <-> Alert many-to-many relationship
incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(50))
    user: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    host: Mapped[Optional[str]] = mapped_column(String(200), index=True)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_criticality: Mapped[str] = mapped_column(String(20), nullable=False)
    ioc: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(50))
    
    # New fields proposed in plan
    status: Mapped[str] = mapped_column(String(20), default="NEW", index=True, nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    source_event_id: Mapped[Optional[str]] = mapped_column(String(100))
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    incidents: Mapped[List["IncidentModel"]] = relationship(
        secondary=incident_alerts, back_populates="alerts"
    )

class IncidentModel(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    correlation_score: Mapped[float] = mapped_column(Float, nullable=False)
    
    # New fields proposed in plan
    status: Mapped[str] = mapped_column(String(20), default="NEW", index=True, nullable=False)
    priority: Mapped[Optional[str]] = mapped_column(String(10), index=True) # P1, P2, P3, P4
    
    # Risk component scores
    risk_score: Mapped[Optional[float]] = mapped_column(Float, index=True)
    risk_severity_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_criticality_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_alert_count_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_mitre_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_lateral_movement_score: Mapped[Optional[float]] = mapped_column(Float)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    alerts: Mapped[List["AlertModel"]] = relationship(
        secondary=incident_alerts, back_populates="incidents", order_by="AlertModel.timestamp"
    )
    edges: Mapped[List["CorrelationEdgeModel"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[List["MitreMappingModel"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    briefing: Mapped[Optional["BriefingModel"]] = relationship(
        back_populates="incident", uselist=False, cascade="all, delete-orphan"
    )
    decisions: Mapped[List["AnalystDecisionModel"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="AnalystDecisionModel.created_at"
    )
    metrics: Mapped[Optional["TriageMetricModel"]] = relationship(
        back_populates="incident", uselist=False, cascade="all, delete-orphan"
    )

class CorrelationEdgeModel(Base):
    __tablename__ = "correlation_edges"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    alert_a_id: Mapped[str] = mapped_column(String(50), nullable=False)
    alert_b_id: Mapped[str] = mapped_column(String(50), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[str] = mapped_column(Text, nullable=False) # JSON list of strings
    explanation: Mapped[Optional[str]] = mapped_column(Text)

    incident: Mapped["IncidentModel"] = relationship(back_populates="edges")

class MitreMappingModel(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    tactic: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    in_catalogue: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    incident: Mapped["IncidentModel"] = relationship(back_populates="mitre_mappings")

class BriefingModel(Base):
    __tablename__ = "briefings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    attack_vector: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_rationale: Mapped[Optional[str]] = mapped_column(Text)
    affected_assets: Mapped[str] = mapped_column(Text) # JSON list of strings
    
    model_name: Mapped[str] = mapped_column(String(50), nullable=False)
    latency_seconds: Mapped[Optional[float]] = mapped_column(Float)
    fallback_reason: Mapped[Optional[str]] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    incident: Mapped["IncidentModel"] = relationship(back_populates="briefing")

class AnalystDecisionModel(Base):
    __tablename__ = "analyst_decisions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False) # CONFIRM, ESCALATE, DISMISS
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    incident: Mapped["IncidentModel"] = relationship(back_populates="decisions")

class TriageMetricModel(Base):
    __tablename__ = "triage_metrics"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False)
    alert_received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    analyst_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    first_decision_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    triage_seconds: Mapped[Optional[float]] = mapped_column(Float)

    incident: Mapped["IncidentModel"] = relationship(back_populates="metrics")

class TriageRunModel(Base):
    __tablename__ = "triage_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    alerts_processed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    incidents_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False) # dataset, payload
    
    # JSON strings or discrete columns for stage timings
    timing_ingest: Mapped[Optional[float]] = mapped_column(Float)
    timing_correlate: Mapped[Optional[float]] = mapped_column(Float)
    timing_mitre: Mapped[Optional[float]] = mapped_column(Float)
    timing_risk: Mapped[Optional[float]] = mapped_column(Float)
    timing_briefing: Mapped[Optional[float]] = mapped_column(Float)
