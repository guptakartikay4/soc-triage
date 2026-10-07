"""
Tests for the end-to-end triage pipeline (Task 7).

Run from backend/ with:  python -m pytest tests/ -v
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.risk import RiskPriority
from app.models.triage import TriagedIncident
from app.services.risk import assess_risk
from app.services.triage import run_triage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)
_counter = 0


def _ts(offset_minutes: int = 0) -> datetime:
    return _T0 + timedelta(minutes=offset_minutes)


def _alert(
    *,
    alert_id: str | None = None,
    severity: str = "medium",
    asset_criticality: str = "low",
    host: str = "HOST-A",
    user: str = "alice",
    source_ip: str = "10.0.0.1",
    ioc: str | None = None,
    mitre_technique: str | None = None,
    description: str = "Routine test alert.",
    timestamp: datetime | None = None,
    asset_id: str = "ASSET-001",
) -> Alert:
    global _counter
    _counter += 1
    return Alert(
        alert_id=alert_id or f"TRIAGE-{_counter:05d}",
        timestamp=timestamp or _T0,
        source="EDR",
        alert_type="Test",
        severity=SeverityLevel(severity),
        source_ip=source_ip,
        destination_ip=None,
        user=user,
        host=host,
        asset_id=asset_id,
        asset_criticality=AssetCriticality(asset_criticality),
        ioc=ioc,
        description=description,
        mitre_technique=mitre_technique,
    )


# ---------------------------------------------------------------------------
# TEST 1 — Empty input returns empty list
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_list():
    result = run_triage([])
    assert result == []


# ---------------------------------------------------------------------------
# TEST 2 — Alerts are correlated into incidents
# ---------------------------------------------------------------------------

def test_alerts_correlated_into_incidents():
    """Same host+user within 30 min should produce fewer incidents than alerts."""
    alerts = [
        _alert(alert_id="COR-A", host="SRV-01", user="bob",
               source_ip="10.1.1.1", timestamp=_ts(0)),
        _alert(alert_id="COR-B", host="SRV-01", user="bob",
               source_ip="10.1.1.1", timestamp=_ts(5)),
        _alert(alert_id="COR-C", host="SRV-01", user="bob",
               source_ip="10.1.1.1", timestamp=_ts(10)),
    ]
    result = run_triage(alerts)
    # All three should be grouped into one incident
    assert len(result) == 1
    assert set(result[0].alert_ids) == {"COR-A", "COR-B", "COR-C"}


# ---------------------------------------------------------------------------
# TEST 3 — Every incident receives a RiskAssessment
# ---------------------------------------------------------------------------

def test_every_incident_has_risk_assessment():
    alerts = [
        _alert(alert_id="RA-A", host="H1", user="u1", source_ip="10.0.0.1",
               timestamp=_ts(0)),
        _alert(alert_id="RA-B", host="H2", user="u2", source_ip="10.0.0.2",
               timestamp=_ts(1)),
    ]
    result = run_triage(alerts)
    for ti in result:
        assert isinstance(ti, TriagedIncident)
        assert 0.0 <= ti.risk_score <= 100.0
        assert isinstance(ti.priority, RiskPriority)
        assert ti.explanation.strip() != ""


# ---------------------------------------------------------------------------
# TEST 4 — Higher risk incidents appear before lower risk incidents
# ---------------------------------------------------------------------------

def test_higher_risk_appears_first():
    # Critical asset + critical severity → high risk
    critical = _alert(
        alert_id="HI-001",
        host="SRV-CRIT", user="crit_user", source_ip="10.5.5.5",
        severity="critical", asset_criticality="critical",
        mitre_technique="T1059.001",
        description="Mimikatz credential dump lateral exfil shell c2 beacon.",
        timestamp=_ts(0),
    )
    # Low asset + low severity → low risk
    benign = _alert(
        alert_id="LO-001",
        host="WS-BENIGN", user="benign_user", source_ip="10.9.9.9",
        severity="low", asset_criticality="low",
        description="Routine antivirus scan completed.",
        timestamp=_ts(1),
    )

    result = run_triage([critical, benign])

    assert len(result) == 2
    assert result[0].risk_score >= result[1].risk_score
    # The critical alert's incident must be first
    assert "HI-001" in result[0].alert_ids


# ---------------------------------------------------------------------------
# TEST 5 — Equal-risk incidents use deterministic tie-breakers
# ---------------------------------------------------------------------------

def test_equal_risk_uses_deterministic_tiebreakers():
    """Two identical-profile independent alerts → same risk score.
    Earlier start_time should appear first."""
    early = _alert(
        alert_id="TIE-EARLY",
        host="H-EARLY", user="u_early", source_ip="10.2.2.2",
        severity="medium", asset_criticality="medium",
        description="Normal activity.",
        timestamp=_ts(0),
    )
    late = _alert(
        alert_id="TIE-LATE",
        host="H-LATE", user="u_late", source_ip="10.3.3.3",
        severity="medium", asset_criticality="medium",
        description="Normal activity.",
        timestamp=_ts(60),   # 60 min later — outside correlation window
    )

    result = run_triage([early, late])

    assert len(result) == 2
    assert result[0].risk_score == result[1].risk_score
    # Earlier start_time wins the tie
    assert result[0].start_time <= result[1].start_time


# ---------------------------------------------------------------------------
# TEST 6 — Risk score is NOT recalculated by the prioritization layer
# ---------------------------------------------------------------------------

def test_risk_score_comes_verbatim_from_task6():
    """
    Build an Incident manually, call assess_risk directly, then run the
    full pipeline on the same alerts and confirm the score matches.
    """
    from app.models.incident import Incident
    from app.services.correlation import correlate_alerts

    a = _alert(
        alert_id="VER-A", host="SRV-X", user="veronica",
        source_ip="10.7.7.7", severity="high",
        asset_criticality="high",
        mitre_technique="T1078",
        description="Credential access lateral exfil.",
        timestamp=_ts(0),
    )
    b = _alert(
        alert_id="VER-B", host="SRV-X", user="veronica",
        source_ip="10.7.7.7", severity="high",
        asset_criticality="high",
        mitre_technique="T1078",
        description="Repeated credential access attempt.",
        timestamp=_ts(4),
    )

    # Directly correlate + assess to get the "ground truth" score
    incidents = correlate_alerts([a, b])
    assert len(incidents) == 1
    expected_score = assess_risk(incidents[0], [a, b]).risk_score

    # Pipeline result must match exactly
    result = run_triage([a, b])
    assert len(result) == 1
    assert result[0].risk_score == expected_score


# ---------------------------------------------------------------------------
# TEST 7 — Incident IDs are deterministic
# ---------------------------------------------------------------------------

def test_incident_ids_are_deterministic():
    alerts = [
        _alert(alert_id="DET-A", host="H-D", user="u_d", source_ip="10.4.4.4",
               timestamp=_ts(0)),
        _alert(alert_id="DET-B", host="H-E", user="u_e", source_ip="10.4.4.5",
               timestamp=_ts(2)),
    ]
    run1 = run_triage(alerts)
    run2 = run_triage(alerts)
    assert [ti.incident_id for ti in run1] == [ti.incident_id for ti in run2]


# ---------------------------------------------------------------------------
# TEST 8 — Repeated execution with identical input produces identical output
# ---------------------------------------------------------------------------

def test_repeated_execution_is_deterministic():
    alerts = [
        _alert(alert_id="REP-A", host="SRV-REP", user="rep_user",
               source_ip="10.8.8.8", severity="high",
               asset_criticality="critical",
               mitre_technique="T1059",
               description="exploit shell payload beacon c2.",
               timestamp=_ts(0)),
        _alert(alert_id="REP-B", host="SRV-REP", user="rep_user",
               source_ip="10.8.8.8", severity="critical",
               asset_criticality="critical",
               mitre_technique="T1078",
               description="Credential dump lateral movement.",
               timestamp=_ts(8)),
    ]
    run1 = run_triage(alerts)
    run2 = run_triage(alerts)

    assert len(run1) == len(run2)
    for t1, t2 in zip(run1, run2):
        assert t1.incident_id   == t2.incident_id
        assert t1.risk_score    == t2.risk_score
        assert t1.priority      == t2.priority
        assert t1.explanation   == t2.explanation
        assert t1.alert_ids     == t2.alert_ids


# ---------------------------------------------------------------------------
# TEST 9 — Single-alert incidents are handled correctly
# ---------------------------------------------------------------------------

def test_single_alert_incident():
    a = _alert(alert_id="SOLO-001", host="WS-SOLO", user="solo_user",
               source_ip="10.6.6.6", severity="medium",
               asset_criticality="medium",
               description="Standalone alert.",
               timestamp=_ts(0))

    result = run_triage([a])

    assert len(result) == 1
    ti = result[0]
    assert ti.alert_ids == ["SOLO-001"]
    assert ti.correlation_score == 0.0           # no edges
    assert ti.correlation_evidence == []
    assert 0.0 <= ti.risk_score <= 100.0
    assert ti.explanation.strip() != ""


# ---------------------------------------------------------------------------
# TEST 10 — Multiple independent incidents are all retained
# ---------------------------------------------------------------------------

def test_multiple_independent_incidents_all_retained():
    """Three alerts with completely disjoint profiles → three incidents."""
    alerts = [
        _alert(alert_id="IND-A", host="H-A", user="u_a", source_ip="10.0.1.1",
               timestamp=_ts(0)),
        _alert(alert_id="IND-B", host="H-B", user="u_b", source_ip="10.0.2.2",
               timestamp=_ts(0)),
        _alert(alert_id="IND-C", host="H-C", user="u_c", source_ip="10.0.3.3",
               timestamp=_ts(0)),
    ]
    result = run_triage(alerts)
    assert len(result) == 3
    all_ids = {tid for ti in result for tid in ti.alert_ids}
    assert all_ids == {"IND-A", "IND-B", "IND-C"}


# ---------------------------------------------------------------------------
# TEST 11 — Critical asset incident receives correct risk result from Task 6
# ---------------------------------------------------------------------------

def test_critical_asset_receives_task6_risk_result():
    from app.services.correlation import correlate_alerts

    a = _alert(
        alert_id="CRIT-ASSET-001",
        host="ERP-SRV", user="erp_admin",
        source_ip="10.0.0.50",
        severity="critical", asset_criticality="critical",
        mitre_technique="T1003.001",
        description="LSASS memory access credential dump mimikatz lateral exfil.",
        timestamp=_ts(0),
    )

    # Ground truth via direct Task 6 call
    incidents = correlate_alerts([a])
    from app.services.risk import assess_risk as _assess
    expected = _assess(incidents[0], [a])

    result = run_triage([a])
    assert len(result) == 1
    ti = result[0]

    assert ti.risk_score              == expected.risk_score
    assert ti.priority                == expected.priority
    assert ti.severity_score          == expected.components.severity
    assert ti.asset_criticality_score == expected.components.asset_criticality
    assert ti.explanation             == expected.explanation


# ---------------------------------------------------------------------------
# Additional structural / field tests
# ---------------------------------------------------------------------------

def test_triaged_incident_has_all_required_fields():
    a = _alert(alert_id="FIELD-001")
    result = run_triage([a])
    ti = result[0]

    required = {
        "incident_id", "alert_ids", "start_time", "end_time",
        "correlation_score", "correlation_evidence",
        "risk_score", "priority", "explanation",
        "severity_score", "asset_criticality_score",
        "correlation_strength_score", "evidence_strength_score",
        "attack_context_score",
    }
    for field in required:
        assert hasattr(ti, field), f"Missing field: {field}"


def test_output_is_list_of_triaged_incidents():
    a = _alert(alert_id="TYPE-001")
    result = run_triage([a])
    assert isinstance(result, list)
    assert all(isinstance(ti, TriagedIncident) for ti in result)


def test_alert_ids_within_triaged_incident_are_chronological():
    c = _alert(alert_id="CHR-C", host="SRV-CHR", user="chr_user",
               source_ip="10.5.5.5", timestamp=_ts(20))
    a = _alert(alert_id="CHR-A", host="SRV-CHR", user="chr_user",
               source_ip="10.5.5.5", timestamp=_ts(0))
    b = _alert(alert_id="CHR-B", host="SRV-CHR", user="chr_user",
               source_ip="10.5.5.5", timestamp=_ts(10))

    result = run_triage([c, a, b])
    assert len(result) == 1
    assert result[0].alert_ids == ["CHR-A", "CHR-B", "CHR-C"]


def test_risk_score_in_0_to_100_range():
    alerts = [
        _alert(severity="critical", asset_criticality="critical",
               mitre_technique="T1059", ioc="evil.io",
               description="exploit shell lateral exfil credential dump mimikatz."),
        _alert(severity="low", asset_criticality="low",
               description="Routine scan."),
    ]
    result = run_triage(alerts)
    for ti in result:
        assert 0.0 <= ti.risk_score <= 100.0


def test_priority_descending_order():
    """Result list should have priority ranks non-increasing."""
    from app.services.triage import _PRIORITY_RANK
    alerts = [
        _alert(alert_id=f"PO-{i:03d}", host=f"H-{i}",
               user=f"u{i}", source_ip=f"10.0.{i}.1",
               severity="medium", asset_criticality="medium",
               timestamp=_ts(i * 2))
        for i in range(5)
    ]
    result = run_triage(alerts)
    ranks = [_PRIORITY_RANK[ti.priority] for ti in result]
    assert ranks == sorted(ranks, reverse=True)
