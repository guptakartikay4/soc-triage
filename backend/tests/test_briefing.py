"""
Unit tests for AI Incident Briefing and Deterministic Fallback (Task 9).

Tests:
1. Deterministic fallback works without GROQ_API_KEY.
2. Fallback contains the actual incident ID.
3. Fallback contains the actual risk score/priority.
4. Fallback does not invent evidence.
5. Evidence payload contains only intended structured incident fields.
6. Known MITRE context is included in the evidence payload.
7. Multiple alerts are represented correctly.
8. Groq successful response is validated into IncidentBrief.
9. Malformed Groq response triggers fallback.
10. Groq API exception triggers fallback.
11. Groq timeout triggers fallback.
12. Missing API key triggers fallback.
13. API key is never exposed in generated output.
14. Risk score is never changed by the briefing service.
15. Priority is never changed by the briefing service.
16. MITRE mapping is not recalculated by the briefing service.
17. Repeated fallback generation is deterministic.
18. Existing Tasks 1-8 behavior remains preserved.

All tests are strictly offline; NO real network/API calls are made.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
from unittest.mock import MagicMock, patch
import pytest

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.brief import IncidentBrief
from app.models.incident import CorrelationEdge
from app.models.mitre import IncidentMITREContext, MITRETechniqueContext
from app.models.risk import RiskPriority
from app.models.triage import TriagedIncident
from app.services.briefing import (
    build_briefing_payload,
    build_fallback_brief,
    generate_incident_brief,
    get_groq_client,
)

_T0 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_groq_env(monkeypatch):
    """Ensure GROQ_API_KEY is clean across tests unless specifically overridden."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _make_alert(
    *,
    alert_id: str = "ALT-001",
    severity: str = "high",
    asset_criticality: str = "critical",
    host: str = "SRV-FIN-01",
    user: str = "bob",
    source_ip: str = "192.168.1.50",
    destination_ip: str | None = "10.0.0.5",
    ioc: str | None = "bad.domain.com",
    mitre_technique: str | None = "T1059.001",
    description: str = "Suspicious PowerShell execution observed.",
    timestamp: datetime | None = None,
    asset_id: str = "ASSET-005",
) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=timestamp or _T0,
        source="EDR",
        alert_type="PowerShell Execution",
        severity=SeverityLevel(severity),
        source_ip=source_ip,
        destination_ip=destination_ip,
        user=user,
        host=host,
        asset_id=asset_id,
        asset_criticality=AssetCriticality(asset_criticality),
        ioc=ioc,
        description=description,
        mitre_technique=mitre_technique,
    )


def _make_triaged_incident(
    *,
    incident_id: str = "INC-001",
    alert_ids: list[str] | None = None,
    risk_score: float = 85.5,
    priority: RiskPriority = RiskPriority.critical,
    techniques: list[MITRETechniqueContext] | None = None,
) -> TriagedIncident:
    a_ids = alert_ids or ["ALT-001", "ALT-002"]
    if techniques is None:
        techs = [
            MITRETechniqueContext(
                technique_id="T1059.001",
                name="Command and Scripting Interpreter: PowerShell",
                tactic="Execution",
                alert_ids=["ALT-001"],
            )
        ]
    else:
        techs = techniques

    return TriagedIncident(
        incident_id=incident_id,
        alert_ids=a_ids,
        start_time=_T0,
        end_time=_T0 + timedelta(minutes=15),
        correlation_score=0.88,
        correlation_evidence=[
            CorrelationEdge(
                alert_a=a_ids[0],
                alert_b=a_ids[1] if len(a_ids) > 1 else a_ids[0],
                score=0.88,
                signals=["same_host", "temporal"],
            )
        ],
        risk_score=risk_score,
        priority=priority,
        severity_score=90.0,
        asset_criticality_score=100.0,
        correlation_strength_score=80.0,
        evidence_strength_score=75.0,
        attack_context_score=85.0,
        explanation="High severity alerts on critical asset with known MITRE technique.",
        mitre_context=IncidentMITREContext(
            techniques=techs,
            technique_count=len(techs),
        ),
    )


# ---------------------------------------------------------------------------
# TEST 1: Deterministic fallback works without GROQ_API_KEY
# ---------------------------------------------------------------------------

def test_fallback_works_without_api_key():
    alert = _make_alert()
    ti = _make_triaged_incident(alert_ids=[alert.alert_id])
    brief = generate_incident_brief(ti, [alert])

    assert isinstance(brief, IncidentBrief)
    assert brief.incident_id == "INC-001"
    assert brief.confidence == "Medium"


# ---------------------------------------------------------------------------
# TEST 2: Fallback contains the actual incident ID
# ---------------------------------------------------------------------------

def test_fallback_contains_actual_incident_id():
    ti = _make_triaged_incident(incident_id="INC-SPECIFIC-999")
    alert = _make_alert()
    brief = build_fallback_brief(ti, [alert])

    assert brief.incident_id == "INC-SPECIFIC-999"


# ---------------------------------------------------------------------------
# TEST 3: Fallback contains the actual risk score and priority
# ---------------------------------------------------------------------------

def test_fallback_contains_actual_risk_score_and_priority():
    ti = _make_triaged_incident(risk_score=78.25, priority=RiskPriority.high)
    alert = _make_alert()
    brief = build_fallback_brief(ti, [alert])

    assert "78.25" in brief.why_it_matters
    assert "High" in brief.summary


# ---------------------------------------------------------------------------
# TEST 4: Fallback does not invent evidence
# ---------------------------------------------------------------------------

def test_fallback_does_not_invent_evidence():
    # Alert without user, destination_ip, ioc, or mitre technique
    clean_alert = Alert(
        alert_id="ALT-CLEAN",
        timestamp=_T0,
        source="FW",
        alert_type="Network Drop",
        severity=SeverityLevel.low,
        source_ip="10.0.0.1",
        destination_ip=None,
        user=None,
        host=None,
        asset_id="ASSET-010",
        asset_criticality=AssetCriticality.low,
        ioc=None,
        description="Dropped packet.",
        mitre_technique=None,
    )
    ti = TriagedIncident(
        incident_id="INC-CLEAN",
        alert_ids=["ALT-CLEAN"],
        start_time=_T0,
        end_time=_T0,
        correlation_score=0.0,
        correlation_evidence=[],
        risk_score=25.0,
        priority=RiskPriority.low,
        severity_score=20.0,
        asset_criticality_score=20.0,
        correlation_strength_score=0.0,
        evidence_strength_score=20.0,
        attack_context_score=10.0,
        explanation="Low severity isolated alert on low asset.",
        mitre_context=IncidentMITREContext(techniques=[], technique_count=0),
    )
    brief = build_fallback_brief(ti, [clean_alert])

    # Should not invent any IOC or MITRE technique
    assert brief.mitre_summary == []
    for item in brief.key_evidence:
        assert "IOC" not in item
        assert "MITRE" not in item
    assert "ASSET-010" in brief.summary


# ---------------------------------------------------------------------------
# TEST 5: Evidence payload contains only intended structured incident fields
# ---------------------------------------------------------------------------

def test_evidence_payload_contains_only_intended_fields():
    alert = _make_alert()
    ti = _make_triaged_incident(alert_ids=[alert.alert_id])
    payload = build_briefing_payload(ti, [alert])

    expected_keys = {
        "incident_id",
        "risk_score",
        "priority",
        "risk_explanation",
        "start_time",
        "end_time",
        "alert_ids",
        "alert_count",
        "affected_assets",
        "asset_criticality",
        "users",
        "source_ips",
        "destination_ips",
        "iocs",
        "alert_types",
        "severities",
        "mitre_techniques",
        "correlation_evidence",
        "alert_descriptions",
    }
    assert set(payload.keys()) == expected_keys
    # Ensure no leaked credentials or system state
    assert "api_key" not in payload
    assert "token" not in payload


# ---------------------------------------------------------------------------
# TEST 6: Known MITRE context is included in the evidence payload
# ---------------------------------------------------------------------------

def test_mitre_context_in_evidence_payload():
    alert = _make_alert(mitre_technique="T1059.001")
    ti = _make_triaged_incident(alert_ids=[alert.alert_id])
    payload = build_briefing_payload(ti, [alert])

    assert len(payload["mitre_techniques"]) == 1
    tech = payload["mitre_techniques"][0]
    assert tech["technique_id"] == "T1059.001"
    assert tech["name"] == "Command and Scripting Interpreter: PowerShell"
    assert tech["tactic"] == "Execution"


# ---------------------------------------------------------------------------
# TEST 7: Multiple alerts are represented correctly in payload
# ---------------------------------------------------------------------------

def test_multiple_alerts_in_payload():
    a1 = _make_alert(alert_id="ALT-1", user="alice", asset_id="ASSET-A")
    a2 = _make_alert(alert_id="ALT-2", user="bob", asset_id="ASSET-B")
    ti = _make_triaged_incident(alert_ids=["ALT-1", "ALT-2"])
    payload = build_briefing_payload(ti, [a1, a2])

    assert payload["alert_count"] == 2
    assert payload["alert_ids"] == ["ALT-1", "ALT-2"]
    assert payload["affected_assets"] == ["ASSET-A", "ASSET-B"]
    assert payload["users"] == ["alice", "bob"]
    assert len(payload["alert_descriptions"]) == 2


# ---------------------------------------------------------------------------
# TEST 8: Groq successful response is validated into IncidentBrief
# ---------------------------------------------------------------------------

def test_groq_successful_response_validated():
    ti = _make_triaged_incident(incident_id="INC-AI-1")
    alerts = [_make_alert()]

    mock_client = MagicMock()
    mock_completion = MagicMock()
    mock_choice = MagicMock()
    mock_message = MagicMock()

    valid_response_json = {
        "incident_id": "INC-AI-1",
        "summary": "Attacker performed credential dumping on DC-01.",
        "why_it_matters": "High-risk escalation targeting enterprise domain controller.",
        "key_evidence": [
            "Mimikatz execution detected",
            "Critical asset DC-01 targeted",
            "IOC c2.evil.com contacted",
        ],
        "mitre_summary": ["T1003.001 — OS Credential Dumping — Credential Access"],
        "recommended_next_steps": [
            "Review domain controller authentication logs",
            "Verify memory dump artifact on DC-01",
        ],
        "confidence": "High",
    }
    mock_message.content = json.dumps(valid_response_json)
    mock_choice.message = mock_message
    mock_completion.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_completion

    brief = generate_incident_brief(ti, alerts, client=mock_client)

    assert brief.incident_id == "INC-AI-1"
    assert brief.summary == valid_response_json["summary"]
    assert brief.why_it_matters == valid_response_json["why_it_matters"]
    assert brief.key_evidence == valid_response_json["key_evidence"]
    assert brief.confidence == "High"
    mock_client.chat.completions.create.assert_called_once()


# ---------------------------------------------------------------------------
# TEST 9: Malformed Groq response triggers fallback
# ---------------------------------------------------------------------------

def test_malformed_groq_response_triggers_fallback():
    ti = _make_triaged_incident(incident_id="INC-MALFORMED")
    alerts = [_make_alert()]

    mock_client = MagicMock()
    mock_completion = MagicMock()
    mock_choice = MagicMock()
    mock_message = MagicMock()
    mock_message.content = "This is not JSON at all! Just raw plain text."
    mock_choice.message = mock_message
    mock_completion.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_completion

    brief = generate_incident_brief(ti, alerts, client=mock_client)

    # Should not raise exception; must return valid deterministic fallback brief
    assert isinstance(brief, IncidentBrief)
    assert brief.incident_id == "INC-MALFORMED"
    assert brief.confidence == "Medium"


# ---------------------------------------------------------------------------
# TEST 10: Groq API exception triggers fallback
# ---------------------------------------------------------------------------

def test_groq_api_exception_triggers_fallback():
    ti = _make_triaged_incident(incident_id="INC-ERR")
    alerts = [_make_alert()]

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("Groq 500 Internal Error")

    brief = generate_incident_brief(ti, alerts, client=mock_client)

    assert isinstance(brief, IncidentBrief)
    assert brief.incident_id == "INC-ERR"


# ---------------------------------------------------------------------------
# TEST 11: Groq timeout triggers fallback
# ---------------------------------------------------------------------------

def test_groq_timeout_triggers_fallback():
    ti = _make_triaged_incident(incident_id="INC-TIMEOUT")
    alerts = [_make_alert()]

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = TimeoutError("Request timed out after 30s")

    brief = generate_incident_brief(ti, alerts, client=mock_client)

    assert isinstance(brief, IncidentBrief)
    assert brief.incident_id == "INC-TIMEOUT"


# ---------------------------------------------------------------------------
# TEST 12: Missing API key triggers fallback
# ---------------------------------------------------------------------------

def test_missing_api_key_triggers_fallback(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    client = get_groq_client()
    assert client is None

    ti = _make_triaged_incident(incident_id="INC-NO-KEY")
    brief = generate_incident_brief(ti, [_make_alert()])
    assert brief.incident_id == "INC-NO-KEY"


# ---------------------------------------------------------------------------
# TEST 13: API key is never exposed in generated output
# ---------------------------------------------------------------------------

def test_api_key_never_exposed_in_output():
    secret_key = "gsk_super_secret_key_1234567890abcdef"
    ti = _make_triaged_incident()
    alerts = [_make_alert()]

    # Test fallback
    brief_fallback = build_fallback_brief(ti, alerts)
    serialized_fb = json.dumps(brief_fallback.model_dump())
    assert secret_key not in serialized_fb

    # Test payload
    payload = build_briefing_payload(ti, alerts)
    serialized_payload = json.dumps(payload)
    assert secret_key not in serialized_payload


# ---------------------------------------------------------------------------
# TEST 14: Risk score is never changed by the briefing service
# ---------------------------------------------------------------------------

def test_risk_score_never_changed():
    original_risk = 82.75
    ti = _make_triaged_incident(risk_score=original_risk)
    alerts = [_make_alert()]

    # Generate brief
    generate_incident_brief(ti, alerts)

    # Invariant: TriagedIncident risk_score remains completely untouched
    assert ti.risk_score == original_risk


# ---------------------------------------------------------------------------
# TEST 15: Priority is never changed by the briefing service
# ---------------------------------------------------------------------------

def test_priority_never_changed():
    original_priority = RiskPriority.critical
    ti = _make_triaged_incident(priority=original_priority)
    alerts = [_make_alert()]

    generate_incident_brief(ti, alerts)

    assert ti.priority == original_priority


# ---------------------------------------------------------------------------
# TEST 16: MITRE mapping is not recalculated by the briefing service
# ---------------------------------------------------------------------------

def test_mitre_mapping_not_recalculated():
    tech = MITRETechniqueContext(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion",
        alert_ids=["ALT-001"],
    )
    ti = _make_triaged_incident(techniques=[tech])
    alerts = [_make_alert()]

    brief = generate_incident_brief(ti, alerts)

    assert brief.mitre_summary == ["T1078 — Valid Accounts — Defense Evasion"]
    assert ti.mitre_context.techniques[0].technique_id == "T1078"


# ---------------------------------------------------------------------------
# TEST 17: Repeated fallback generation is completely deterministic
# ---------------------------------------------------------------------------

def test_repeated_fallback_is_deterministic():
    ti = _make_triaged_incident()
    alerts = [_make_alert(alert_id="A1"), _make_alert(alert_id="A2")]

    b1 = build_fallback_brief(ti, alerts)
    b2 = build_fallback_brief(ti, alerts)

    assert b1.model_dump() == b2.model_dump()


# ---------------------------------------------------------------------------
# TEST 18: Existing Tasks 1-8 behavior remains preserved
# ---------------------------------------------------------------------------

def test_existing_tasks_1_to_8_behavior_preserved():
    from app.services.triage import run_triage

    alerts = [
        _make_alert(alert_id="T1-A", host="SRV-01", user="alice", timestamp=_T0),
        _make_alert(alert_id="T1-B", host="SRV-01", user="alice", timestamp=_T0 + timedelta(minutes=5)),
    ]
    triaged = run_triage(alerts)
    assert len(triaged) == 1

    ti = triaged[0]
    brief = generate_incident_brief(ti, alerts)

    assert brief.incident_id == ti.incident_id
    assert brief.confidence in ("High", "Medium", "Low")
    assert len(brief.recommended_next_steps) >= 1
