"""
Unit and integration tests for MITRE ATT&CK mapping and security context (Task 8).

Test coverage includes:
1. Empty incident list/input.
2. Incident with one known MITRE technique.
3. Incident with multiple techniques.
4. Multiple alerts sharing the same technique are grouped correctly.
5. Alert IDs associated with each technique are correct.
6. Technique IDs are sorted deterministically (ascending).
7. Alert IDs are sorted deterministically within each technique (ascending).
8. Missing/null MITRE technique is ignored.
9. Unknown MITRE technique does not crash.
10. Unknown technique is preserved with safe fallback metadata.
11. Incident with no MITRE techniques is handled correctly.
12. Repeated execution produces identical output.
13. Existing Tasks 1-7 behavior remains unchanged.
14. Full triage integration exposes MITRE context correctly.
15. Local catalogue contains all 24 synthetic dataset techniques.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.mitre import (
    IncidentMITREContext,
    MITRETechnique,
    MITRETechniqueContext,
)
from app.services.mitre import (
    MITRE_CATALOGUE,
    FALLBACK_NAME,
    FALLBACK_TACTIC,
    build_mitre_context,
    get_technique,
)
from app.services.triage import run_triage
from app.models.triage import TriagedIncident

_T0 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)
_counter = 0


def _alert(
    *,
    alert_id: str | None = None,
    severity: str = "medium",
    asset_criticality: str = "low",
    host: str = "HOST-01",
    user: str = "alice",
    source_ip: str = "10.0.0.1",
    ioc: str | None = None,
    mitre_technique: str | None = None,
    description: str = "Test alert description.",
    timestamp: datetime | None = None,
    asset_id: str = "ASSET-001",
) -> Alert:
    global _counter
    _counter += 1
    return Alert(
        alert_id=alert_id or f"MITRE-{_counter:05d}",
        timestamp=timestamp or _T0,
        source="EDR",
        alert_type="SecurityEvent",
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
# TEST 1: Empty input returns empty context
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_context():
    context = build_mitre_context([])
    assert isinstance(context, IncidentMITREContext)
    assert context.techniques == []
    assert context.technique_count == 0


# ---------------------------------------------------------------------------
# TEST 2: Incident with one known MITRE technique
# ---------------------------------------------------------------------------

def test_incident_with_one_known_technique():
    alerts = [
        _alert(alert_id="ALT-001", mitre_technique="T1059.001"),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 1
    assert len(context.techniques) == 1
    t = context.techniques[0]
    assert t.technique_id == "T1059.001"
    assert t.name == "Command and Scripting Interpreter: PowerShell"
    assert t.tactic == "Execution"
    assert t.alert_ids == ["ALT-001"]


# ---------------------------------------------------------------------------
# TEST 3: Incident with multiple techniques
# ---------------------------------------------------------------------------

def test_incident_with_multiple_techniques():
    alerts = [
        _alert(alert_id="ALT-001", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-002", mitre_technique="T1078"),
        _alert(alert_id="ALT-003", mitre_technique="T1003.001"),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 3
    technique_ids = [t.technique_id for t in context.techniques]
    assert technique_ids == ["T1003.001", "T1059.001", "T1078"]


# ---------------------------------------------------------------------------
# TEST 4: Multiple alerts sharing the same technique are grouped correctly
# ---------------------------------------------------------------------------

def test_multiple_alerts_same_technique_grouped():
    alerts = [
        _alert(alert_id="ALT-001", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-002", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-003", mitre_technique="T1059.001"),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 1
    assert len(context.techniques) == 1
    assert context.techniques[0].technique_id == "T1059.001"
    assert len(context.techniques[0].alert_ids) == 3


# ---------------------------------------------------------------------------
# TEST 5: Alert IDs associated with each technique are correct
# ---------------------------------------------------------------------------

def test_alert_ids_associated_with_each_technique():
    alerts = [
        _alert(alert_id="ALT-P1", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-L1", mitre_technique="T1078"),
        _alert(alert_id="ALT-P2", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-L2", mitre_technique="T1078"),
    ]
    context = build_mitre_context(alerts)

    tech_map = {t.technique_id: t.alert_ids for t in context.techniques}
    assert tech_map["T1059.001"] == ["ALT-P1", "ALT-P2"]
    assert tech_map["T1078"] == ["ALT-L1", "ALT-L2"]


# ---------------------------------------------------------------------------
# TEST 6: Technique IDs are sorted deterministically
# ---------------------------------------------------------------------------

def test_technique_ids_sorted_deterministically():
    # Pass in reverse order
    alerts = [
        _alert(alert_id="A1", mitre_technique="T1566.001"),
        _alert(alert_id="A2", mitre_technique="T1078"),
        _alert(alert_id="A3", mitre_technique="T1003.001"),
        _alert(alert_id="A4", mitre_technique="T1046"),
    ]
    context = build_mitre_context(alerts)

    ids = [t.technique_id for t in context.techniques]
    assert ids == sorted(ids)
    assert ids == ["T1003.001", "T1046", "T1078", "T1566.001"]


# ---------------------------------------------------------------------------
# TEST 7: Alert IDs are sorted deterministically within each technique
# ---------------------------------------------------------------------------

def test_alert_ids_sorted_deterministically_within_technique():
    # Pass alerts with disordered alert IDs
    alerts = [
        _alert(alert_id="ALT-099", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-003", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-042", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-001", mitre_technique="T1059.001"),
    ]
    context = build_mitre_context(alerts)

    assert context.techniques[0].alert_ids == ["ALT-001", "ALT-003", "ALT-042", "ALT-099"]


# ---------------------------------------------------------------------------
# TEST 8: Missing/null MITRE technique is ignored
# ---------------------------------------------------------------------------

def test_missing_or_null_technique_is_ignored():
    alerts = [
        _alert(alert_id="ALT-N1", mitre_technique=None),
        _alert(alert_id="ALT-N2", mitre_technique="   "),
        _alert(alert_id="ALT-V1", mitre_technique="T1078"),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 1
    assert context.techniques[0].technique_id == "T1078"
    assert context.techniques[0].alert_ids == ["ALT-V1"]


# ---------------------------------------------------------------------------
# TEST 9: Unknown MITRE technique does not crash
# ---------------------------------------------------------------------------

def test_unknown_mitre_technique_does_not_crash():
    alerts = [
        _alert(alert_id="ALT-U1", mitre_technique="T9999.999"),
        _alert(alert_id="ALT-U2", mitre_technique="CUSTOM-TECH-01"),
    ]
    # Should execute cleanly without raising KeyError or any exception
    context = build_mitre_context(alerts)
    assert context.technique_count == 2


# ---------------------------------------------------------------------------
# TEST 10: Unknown technique is preserved with safe fallback metadata
# ---------------------------------------------------------------------------

def test_unknown_technique_preserved_with_fallback_metadata():
    unknown_id = "T9999.001"
    alerts = [
        _alert(alert_id="ALT-001", mitre_technique=unknown_id),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 1
    tech = context.techniques[0]
    assert tech.technique_id == unknown_id
    assert tech.name == FALLBACK_NAME
    assert tech.tactic == FALLBACK_TACTIC
    assert tech.alert_ids == ["ALT-001"]

    # Also test get_technique directly
    item = get_technique("NON-EXISTENT")
    assert item.technique_id == "NON-EXISTENT"
    assert item.name == FALLBACK_NAME
    assert item.tactic == FALLBACK_TACTIC


# ---------------------------------------------------------------------------
# TEST 11: Incident with no MITRE techniques is handled correctly
# ---------------------------------------------------------------------------

def test_incident_with_no_mitre_techniques():
    alerts = [
        _alert(alert_id="ALT-001", mitre_technique=None),
        _alert(alert_id="ALT-002", mitre_technique=None),
    ]
    context = build_mitre_context(alerts)

    assert context.technique_count == 0
    assert context.techniques == []


# ---------------------------------------------------------------------------
# TEST 12: Repeated execution produces identical output (determinism)
# ---------------------------------------------------------------------------

def test_repeated_execution_is_deterministic():
    alerts = [
        _alert(alert_id="ALT-B", mitre_technique="T1078"),
        _alert(alert_id="ALT-A", mitre_technique="T1059.001"),
        _alert(alert_id="ALT-C", mitre_technique="T1078"),
        _alert(alert_id="ALT-D", mitre_technique="T1003.001"),
    ]
    res1 = build_mitre_context(alerts)
    res2 = build_mitre_context(alerts)

    assert res1.technique_count == res2.technique_count
    assert len(res1.techniques) == len(res2.techniques)
    for t1, t2 in zip(res1.techniques, res2.techniques):
        assert t1.technique_id == t2.technique_id
        assert t1.name == t2.name
        assert t1.tactic == t2.tactic
        assert t1.alert_ids == t2.alert_ids


# ---------------------------------------------------------------------------
# TEST 13: Existing Tasks 1-7 behavior remains unchanged
# ---------------------------------------------------------------------------

def test_existing_tasks_1_to_7_behavior_unchanged():
    """Verify triage pipeline output invariants and risk calculation are unchanged."""
    alerts = [
        _alert(alert_id="T1-A", host="SRV-01", user="admin",
               source_ip="10.1.1.1", severity="critical", asset_criticality="critical",
               mitre_technique="T1078", timestamp=_T0),
        _alert(alert_id="T1-B", host="SRV-01", user="admin",
               source_ip="10.1.1.1", severity="high", asset_criticality="critical",
               mitre_technique="T1059.001", timestamp=_T0 + timedelta(minutes=5)),
    ]
    triaged = run_triage(alerts)

    assert len(triaged) == 1
    ti = triaged[0]

    # Tasks 5-6 invariant: correlated and risk-assessed
    assert set(ti.alert_ids) == {"T1-A", "T1-B"}
    assert 0.0 <= ti.risk_score <= 100.0
    assert ti.priority in {"Critical", "High", "Medium", "Low"}
    assert ti.explanation != ""
    assert ti.correlation_score > 0.0

    # Task 8 addition: MITRE context present
    assert isinstance(ti.mitre_context, IncidentMITREContext)
    assert ti.mitre_context.technique_count == 2
    assert [t.technique_id for t in ti.mitre_context.techniques] == ["T1059.001", "T1078"]


# ---------------------------------------------------------------------------
# TEST 14: Full triage integration exposes MITRE context correctly
# ---------------------------------------------------------------------------

def test_full_triage_integration_exposes_mitre_context():
    """Test full triage pipeline with multiple incidents and mixed techniques."""
    alerts = [
        # Incident 1 (Host A, User 1) - Has 2 techniques
        _alert(alert_id="INC1-A1", host="HOST-ALPHA", user="user1",
               source_ip="10.0.1.1", mitre_technique="T1059.001",
               timestamp=_T0),
        _alert(alert_id="INC1-A2", host="HOST-ALPHA", user="user1",
               source_ip="10.0.1.1", mitre_technique="T1071.001",
               timestamp=_T0 + timedelta(minutes=2)),

        # Incident 2 (Host B, User 2) - No techniques
        _alert(alert_id="INC2-A1", host="HOST-BETA", user="user2",
               source_ip="10.0.2.2", mitre_technique=None,
               timestamp=_T0 + timedelta(minutes=10)),

        # Incident 3 (Host C, User 3) - Unknown technique
        _alert(alert_id="INC3-A1", host="HOST-GAMMA", user="user3",
               source_ip="10.0.3.3", mitre_technique="T9999",
               timestamp=_T0 + timedelta(minutes=20)),
    ]

    triaged = run_triage(alerts)
    assert len(triaged) == 3

    # Map by incident_id
    ti_map = {ti.alert_ids[0]: ti for ti in triaged}

    # Incident 1 check
    ti_alpha = ti_map["INC1-A1"]
    assert ti_alpha.mitre_context.technique_count == 2
    alpha_techs = {t.technique_id: t for t in ti_alpha.mitre_context.techniques}
    assert "T1059.001" in alpha_techs
    assert alpha_techs["T1059.001"].name == "Command and Scripting Interpreter: PowerShell"
    assert alpha_techs["T1059.001"].tactic == "Execution"
    assert alpha_techs["T1059.001"].alert_ids == ["INC1-A1"]
    assert "T1071.001" in alpha_techs
    assert alpha_techs["T1071.001"].tactic == "Command and Control"
    assert alpha_techs["T1071.001"].alert_ids == ["INC1-A2"]

    # Incident 2 check (no MITRE)
    ti_beta = ti_map["INC2-A1"]
    assert ti_beta.mitre_context.technique_count == 0
    assert ti_beta.mitre_context.techniques == []

    # Incident 3 check (Unknown technique fallback)
    ti_gamma = ti_map["INC3-A1"]
    assert ti_gamma.mitre_context.technique_count == 1
    assert ti_gamma.mitre_context.techniques[0].technique_id == "T9999"
    assert ti_gamma.mitre_context.techniques[0].name == FALLBACK_NAME
    assert ti_gamma.mitre_context.techniques[0].tactic == FALLBACK_TACTIC
    assert ti_gamma.mitre_context.techniques[0].alert_ids == ["INC3-A1"]


# ---------------------------------------------------------------------------
# TEST 15: All 24 synthetic dataset techniques are present in local catalogue
# ---------------------------------------------------------------------------

def test_catalogue_contains_all_dataset_techniques():
    dataset_techniques = [
        "T1003.001", "T1003.006", "T1021.002", "T1021.006", "T1046",
        "T1048", "T1052.001", "T1053.005", "T1055", "T1059.001",
        "T1059.004", "T1071.001", "T1074.001", "T1078", "T1110.001",
        "T1110.004", "T1137.001", "T1190", "T1213", "T1218",
        "T1486", "T1505.003", "T1558.001", "T1566.001",
    ]

    for tid in dataset_techniques:
        assert tid in MITRE_CATALOGUE, f"Technique {tid} missing from MITRE_CATALOGUE"
        tech = MITRE_CATALOGUE[tid]
        assert tech.technique_id == tid
        assert isinstance(tech.name, str) and len(tech.name) > 0
        assert isinstance(tech.tactic, str) and len(tech.tactic) > 0
        assert tech.name != FALLBACK_NAME
        assert tech.tactic != FALLBACK_TACTIC
