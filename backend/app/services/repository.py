"""
In-memory incident repository and state store for the SOC API (Task 10).

Loads and caches the 3,000 synthetic SOC alerts, runs the deterministic
triage pipeline once at startup, and provides fast querying, briefing caching,
and human analyst action recording with MTTT tracking.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import logging
from pathlib import Path
import statistics
from typing import Optional, Sequence

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.api import (
    AlertDetailItem,
    AnalystActionRecord,
    DashboardMetricsResponse,
    IncidentBriefResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
)
from app.models.risk import RiskPriority
from app.models.triage import TriagedIncident
from app.services.triage import run_triage

logger = logging.getLogger(__name__)

DEFAULT_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "synthetic_alerts.csv"

VALID_ACTIONS = {"investigate", "escalate", "dismiss", "resolve"}


def load_dataset_alerts(csv_path: Optional[Path] = None) -> list[Alert]:
    """
    Read synthetic alerts CSV and normalize into Alert instances.

    Handles lowercasing of enum fields (severity, asset_criticality) and empty
    string conversion to None for optional fields.
    """
    path = csv_path or DEFAULT_DATA_PATH
    if not path.exists():
        logger.warning("Dataset CSV not found at %s", path)
        return []

    alerts: list[Alert] = []
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cleaned = {
                "alert_id": row["alert_id"],
                "timestamp": row["timestamp"],
                "source": row["source"],
                "alert_type": row["alert_type"],
                "severity": row["severity"].lower(),
                "source_ip": row.get("source_ip") or None,
                "destination_ip": row.get("destination_ip") or None,
                "user": row.get("user") or None,
                "host": row.get("host") or None,
                "asset_id": row["asset_id"],
                "asset_criticality": row["asset_criticality"].lower(),
                "ioc": row.get("ioc") or None,
                "description": row["description"],
                "mitre_technique": row.get("mitre_technique") or None,
            }
            alerts.append(Alert.model_validate(cleaned))
    return alerts


class IncidentRepository:
    """
    In-memory storage and query interface for triaged incidents and analyst actions.
    """

    def __init__(self, alerts: Optional[list[Alert]] = None) -> None:
        self.alerts: list[Alert] = []
        self.alerts_by_id: dict[str, Alert] = {}
        self.triaged_incidents: list[TriagedIncident] = []
        self.incidents_by_id: dict[str, TriagedIncident] = {}
        self.briefs: dict[str, IncidentBriefResponse] = {}
        self.actions: dict[str, AnalystActionRecord] = {}

        if alerts is not None:
            self.initialize(alerts)

    def initialize(self, alerts: list[Alert]) -> None:
        """Populate repository with alerts and execute deterministic triage pipeline."""
        self.alerts = alerts
        self.alerts_by_id = {a.alert_id: a for a in alerts}
        self.triaged_incidents = run_triage(alerts)
        self.incidents_by_id = {ti.incident_id: ti for ti in self.triaged_incidents}
        logger.info(
            "IncidentRepository initialized with %d alerts and %d incidents.",
            len(self.alerts),
            len(self.triaged_incidents),
        )

    def is_initialized(self) -> bool:
        return len(self.alerts) > 0 or len(self.triaged_incidents) > 0

    def get_incidents(
        self,
        priority: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[IncidentSummaryResponse]:
        """
        Return paginated list of triaged incident summaries.

        Preserves the deterministic Task 7 prioritization order.
        """
        filtered = self.triaged_incidents
        if priority:
            p_lower = priority.lower()
            filtered = [ti for ti in filtered if ti.priority.value.lower() == p_lower]

        selected = filtered[offset : offset + limit] if limit is not None else filtered[offset:]

        summaries: list[IncidentSummaryResponse] = []
        for ti in selected:
            inc_alerts = [self.alerts_by_id[aid] for aid in ti.alert_ids if aid in self.alerts_by_id]
            assets = sorted({a.asset_id for a in inc_alerts if a.asset_id})
            criticalities = sorted({a.asset_criticality.value for a in inc_alerts})
            users = sorted({a.user for a in inc_alerts if a.user})
            mitre_list = [
                f"{t.technique_id} - {t.name}"
                for t in ti.mitre_context.techniques
            ]
            action_record = self.actions.get(ti.incident_id)

            edge_count = len(ti.correlation_evidence)
            if edge_count > 0:
                all_signals = sorted({sig for edge in ti.correlation_evidence for sig in edge.signals})
                sig_str = f" ({', '.join(all_signals)})" if all_signals else ""
                corr_summary = f"{edge_count} correlated pair(s){sig_str}"
            else:
                corr_summary = "Single-alert incident"

            summaries.append(
                IncidentSummaryResponse(
                    incident_id=ti.incident_id,
                    priority=ti.priority,
                    risk_score=ti.risk_score,
                    risk_explanation=ti.explanation,
                    start_time=ti.start_time,
                    end_time=ti.end_time,
                    alert_count=len(ti.alert_ids),
                    affected_assets=assets,
                    asset_criticality=criticalities,
                    users=users,
                    mitre_techniques=mitre_list,
                    correlation_evidence_summary=corr_summary,
                    has_brief=ti.incident_id in self.briefs,
                    analyst_action=action_record.action if action_record else None,
                )
            )
        return summaries

    def get_incident(self, incident_id: str) -> Optional[IncidentDetailResponse]:
        """Return full details for a single incident, or None if not found."""
        ti = self.incidents_by_id.get(incident_id)
        if ti is None:
            return None

        inc_alerts = [self.alerts_by_id[aid] for aid in ti.alert_ids if aid in self.alerts_by_id]
        sorted_alerts = sorted(inc_alerts, key=lambda a: (a.timestamp, a.alert_id))

        timeline = [
            AlertDetailItem(
                alert_id=a.alert_id,
                timestamp=a.timestamp,
                source=a.source,
                alert_type=a.alert_type,
                severity=a.severity.value,
                host=a.host,
                user=a.user,
                source_ip=a.source_ip,
                destination_ip=a.destination_ip,
                asset_id=a.asset_id,
                asset_criticality=a.asset_criticality.value,
                ioc=a.ioc,
                description=a.description,
                mitre_technique=a.mitre_technique,
            )
            for a in sorted_alerts
        ]

        assets = sorted({a.asset_id for a in inc_alerts if a.asset_id})
        criticalities = sorted({a.asset_criticality.value for a in inc_alerts})
        users = sorted({a.user for a in inc_alerts if a.user})
        source_ips = sorted({a.source_ip for a in inc_alerts if a.source_ip})
        dest_ips = sorted({a.destination_ip for a in inc_alerts if a.destination_ip})
        iocs = sorted({a.ioc for a in inc_alerts if a.ioc})

        return IncidentDetailResponse(
            incident_id=ti.incident_id,
            priority=ti.priority,
            risk_score=ti.risk_score,
            risk_explanation=ti.explanation,
            severity_score=ti.severity_score,
            asset_criticality_score=ti.asset_criticality_score,
            correlation_strength_score=ti.correlation_strength_score,
            evidence_strength_score=ti.evidence_strength_score,
            attack_context_score=ti.attack_context_score,
            start_time=ti.start_time,
            end_time=ti.end_time,
            alert_count=len(ti.alert_ids),
            alert_ids=ti.alert_ids,
            timeline=timeline,
            affected_assets=assets,
            asset_criticality=criticalities,
            users=users,
            source_ips=source_ips,
            destination_ips=dest_ips,
            iocs=iocs,
            correlation_score=ti.correlation_score,
            correlation_evidence=ti.correlation_evidence,
            mitre_context=ti.mitre_context,
            brief=self.briefs.get(incident_id),
            analyst_action=self.actions.get(incident_id),
        )

    def get_incident_alerts(self, incident_id: str) -> list[Alert]:
        """Return the Alert objects associated with an incident."""
        ti = self.incidents_by_id.get(incident_id)
        if ti is None:
            return []
        return [self.alerts_by_id[aid] for aid in ti.alert_ids if aid in self.alerts_by_id]

    def set_brief(self, incident_id: str, brief: IncidentBriefResponse) -> None:
        """Cache an AI/fallback brief for an incident."""
        self.briefs[incident_id] = brief

    def record_action(
        self,
        incident_id: str,
        action: str,
        note: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> Optional[AnalystActionRecord]:
        """
        Record a human analyst decision and compute triage time.

        triage_time = analyst_action_timestamp - incident_start_time
        """
        ti = self.incidents_by_id.get(incident_id)
        if ti is None:
            return None

        act_clean = action.strip().lower()
        if act_clean not in VALID_ACTIONS:
            return None

        ts = timestamp or datetime.now(timezone.utc)
        start_ts = ti.start_time
        if start_ts.tzinfo is None:
            start_ts = start_ts.replace(tzinfo=timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        delta = (ts - start_ts).total_seconds()
        # If the action timestamp is earlier than the incident start time,
        # it represents invalid runtime/test timing. Do NOT silently clamp to 0.
        triage_time: Optional[float] = None
        if delta >= 0.0:
            triage_time = round(delta, 2)
        else:
            logger.warning(
                "Analyst action timestamp %s is earlier than incident %s start time %s. "
                "Setting triage_time_seconds to None.",
                ts.isoformat(),
                incident_id,
                start_ts.isoformat(),
            )

        record = AnalystActionRecord(
            incident_id=incident_id,
            action=act_clean,
            timestamp=ts,
            note=note,
            triage_time_seconds=triage_time,
        )
        self.actions[incident_id] = record
        return record

    def get_metrics(self) -> DashboardMetricsResponse:
        """Compute top-level summary metrics across all incidents."""
        total_incidents = len(self.triaged_incidents)
        critical_count = sum(1 for ti in self.triaged_incidents if ti.priority == RiskPriority.critical)
        high_count = sum(1 for ti in self.triaged_incidents if ti.priority == RiskPriority.high)
        medium_count = sum(1 for ti in self.triaged_incidents if ti.priority == RiskPriority.medium)
        low_count = sum(1 for ti in self.triaged_incidents if ti.priority == RiskPriority.low)

        avg_risk = (
            sum(ti.risk_score for ti in self.triaged_incidents) / total_incidents
            if total_incidents > 0
            else 0.0
        )

        triage_times = [
            a.triage_time_seconds
            for a in self.actions.values()
            if a.triage_time_seconds is not None and a.triage_time_seconds >= 0.0
        ]

        avg_mttt = statistics.mean(triage_times) if triage_times else None
        median_mttt = statistics.median(triage_times) if triage_times else None

        return DashboardMetricsResponse(
            alerts_ingested=len(self.alerts),
            total_incidents=total_incidents,
            critical_incidents=critical_count,
            high_incidents=high_count,
            medium_incidents=medium_count,
            low_incidents=low_count,
            average_risk=round(avg_risk, 2),
            triaged_count=len(self.actions),
            average_mttt_seconds=round(avg_mttt, 2) if avg_mttt is not None else None,
            median_mttt_seconds=round(median_mttt, 2) if median_mttt is not None else None,
            mttt_baseline="Baseline not yet measured",
        )


# Global singleton instance for application use
_default_repo: Optional[IncidentRepository] = None


def get_repository() -> IncidentRepository:
    """Retrieve or lazily initialize the singleton IncidentRepository."""
    global _default_repo
    if _default_repo is None:
        _default_repo = IncidentRepository()
        alerts = load_dataset_alerts()
        _default_repo.initialize(alerts)
    return _default_repo


def reset_repository(alerts: Optional[list[Alert]] = None) -> IncidentRepository:
    """Reset repository with specific alerts (primarily for testing)."""
    global _default_repo
    _default_repo = IncidentRepository(alerts)
    return _default_repo
