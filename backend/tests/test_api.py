"""
Integration and functional tests for SOC API and Dashboard endpoints (Task 10).

Covers:
1. GET /api/health
2. GET /api/incidents returns incidents
3. Incidents are deterministically prioritized (highest risk first)
4. Incident response contains risk data
5. Incident response contains MITRE context
6. Unknown incident returns 404
7. Incident detail returns alert evidence
8. Brief endpoint works with mocked briefing service
9. Missing Groq does not break brief endpoint (deterministic fallback)
10. Analyst action is recorded
11. Invalid analyst action is rejected
12. Triage timestamp is recorded
13. MTTT calculation uses recorded timestamps
14. No risk recalculation in API layer
15. Dashboard HTML endpoint serves correctly
16. Metrics endpoint returns accurate counts
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.brief import IncidentBrief
from app.services.repository import get_repository, reset_repository

client = TestClient(app)

_T0 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure GROQ_API_KEY is clean during tests."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# TEST 1: Health endpoint
# ---------------------------------------------------------------------------

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# TEST 2: GET /api/incidents returns incidents
# ---------------------------------------------------------------------------

def test_get_incidents_returns_list():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0


# ---------------------------------------------------------------------------
# TEST 3: Incidents are deterministically prioritized (highest risk first)
# ---------------------------------------------------------------------------

def test_incidents_are_prioritized_highest_risk_first():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) >= 2

    # Check risk_score monotonic descending (with tie-breakers)
    risk_scores = [inc["risk_score"] for inc in incidents]
    for i in range(len(risk_scores) - 1):
        assert risk_scores[i] >= risk_scores[i + 1]


# ---------------------------------------------------------------------------
# TEST 4: Incident response contains risk data
# ---------------------------------------------------------------------------

def test_incident_response_contains_risk_data():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    first = res.json()[0]

    assert "risk_score" in first
    assert "priority" in first
    assert "risk_explanation" in first
    assert isinstance(first["risk_score"], (int, float))
    assert first["priority"] in ["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"]
    assert len(first["risk_explanation"]) > 0


# ---------------------------------------------------------------------------
# TEST 5: Incident response contains MITRE context
# ---------------------------------------------------------------------------

def test_incident_response_contains_mitre_context():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()

    # Find an incident with MITRE techniques
    with_mitre = next((inc for inc in incidents if len(inc["mitre_techniques"]) > 0), None)
    assert with_mitre is not None
    assert isinstance(with_mitre["mitre_techniques"], list)
    assert any("T" in t for t in with_mitre["mitre_techniques"])


# ---------------------------------------------------------------------------
# TEST 6: Unknown incident returns 404
# ---------------------------------------------------------------------------

def test_unknown_incident_returns_404():
    res = client.get("/api/incidents/INC-DOES-NOT-EXIST-999")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# TEST 7: Incident detail returns alert evidence and timeline
# ---------------------------------------------------------------------------

def test_incident_detail_returns_alert_evidence():
    # Fetch first incident ID from queue
    queue_res = client.get("/api/incidents")
    first_id = queue_res.json()[0]["incident_id"]

    res = client.get(f"/api/incidents/{first_id}")
    assert res.status_code == 200
    detail = res.json()

    assert detail["incident_id"] == first_id
    assert "timeline" in detail
    assert "alert_ids" in detail
    assert "mitre_context" in detail
    assert "correlation_evidence" in detail
    assert len(detail["timeline"]) == len(detail["alert_ids"])
    assert detail["timeline"][0]["alert_id"] == detail["alert_ids"][0]


# ---------------------------------------------------------------------------
# TEST 8: Brief endpoint works with mocked briefing service
# ---------------------------------------------------------------------------

def test_brief_endpoint_with_mocked_briefing():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]

    mock_brief = IncidentBrief(
        incident_id=inc_id,
        summary="Mocked AI brief summary.",
        why_it_matters="Mocked explanation.",
        key_evidence=["Evidence 1", "Evidence 2"],
        mitre_summary=["T1059.001 - PowerShell"],
        recommended_next_steps=["Step 1", "Step 2"],
        confidence="High",
        generation_source="groq",
        is_fallback=False,
    )

    with patch("app.api.incidents.generate_incident_brief", return_value=mock_brief):
        res = client.post(f"/api/incidents/{inc_id}/brief")
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] == inc_id
        assert data["summary"] == "Mocked AI brief summary."
        assert data["confidence"] == "High"
        assert data["generation_source"] == "groq"
        assert data["is_fallback"] is False


# ---------------------------------------------------------------------------
# TEST 9: Missing Groq does not break brief endpoint (fallback returned)
# ---------------------------------------------------------------------------

def test_missing_groq_returns_fallback_brief():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]

    # Without GROQ_API_KEY in environment
    res = client.post(f"/api/incidents/{inc_id}/brief")
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == inc_id
    assert data["confidence"] == "Medium"
    assert data["generation_source"] == "deterministic_fallback"
    assert data["is_fallback"] is True
    assert len(data["summary"]) > 0
    assert len(data["key_evidence"]) >= 1


# ---------------------------------------------------------------------------
# TEST 10: Analyst action is recorded with positive MTTT when timestamp is after start
# ---------------------------------------------------------------------------

def test_analyst_action_recorded():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]

    # Provide an explicit realistic timestamp occurring 15 minutes after incident start
    repo = get_repository()
    ti = repo.incidents_by_id[inc_id]
    action_time = ti.start_time + timedelta(minutes=15)

    payload = {
        "action": "investigate",
        "note": "Analyst assigned to review logs.",
        "timestamp": action_time.isoformat(),
    }
    res = client.post(f"/api/incidents/{inc_id}/action", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == inc_id
    assert data["action"] == "investigate"
    assert data["note"] == "Analyst assigned to review logs."
    assert "timestamp" in data
    assert "triage_time_seconds" in data
    assert data["triage_time_seconds"] == 900.0  # Exactly 15 minutes (positive)

    # Verify detail view now reflects the recorded action
    detail_res = client.get(f"/api/incidents/{inc_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["analyst_action"] is not None
    assert detail["analyst_action"]["action"] == "investigate"
    assert detail["analyst_action"]["triage_time_seconds"] == 900.0


# ---------------------------------------------------------------------------
# TEST 10B: Action timestamp earlier than incident start sets triage_time to None
# ---------------------------------------------------------------------------

def test_action_earlier_than_incident_start_sets_triage_time_none():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[2]["incident_id"]

    repo = get_repository()
    ti = repo.incidents_by_id[inc_id]
    # Intentionally set an action timestamp earlier than incident start time
    earlier_time = ti.start_time - timedelta(minutes=30)

    payload = {
        "action": "escalate",
        "note": "Timestamp earlier than incident start.",
        "timestamp": earlier_time.isoformat(),
    }
    res = client.post(f"/api/incidents/{inc_id}/action", json=payload)
    assert res.status_code == 200
    data = res.json()

    # Invariant: Must NOT clamp to 0.0 and must NOT be negative; must be None
    assert data["triage_time_seconds"] is None
    assert data["action"] == "escalate"



# ---------------------------------------------------------------------------
# TEST 11: Invalid analyst action is rejected
# ---------------------------------------------------------------------------

def test_invalid_analyst_action_rejected():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]

    payload = {"action": "auto_isolate_host"}
    res = client.post(f"/api/incidents/{inc_id}/action", json=payload)
    assert res.status_code == 400
    assert "invalid action" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# TEST 12: Triage timestamp is recorded
# ---------------------------------------------------------------------------

def test_triage_timestamp_recorded():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[1]["incident_id"]

    res = client.post(f"/api/incidents/{inc_id}/action", json={"action": "escalate"})
    assert res.status_code == 200
    data = res.json()
    assert data["timestamp"] is not None
    # Validate timestamp format
    parsed_time = datetime.fromisoformat(data["timestamp"])
    assert parsed_time is not None


# ---------------------------------------------------------------------------
# TEST 13: MTTT calculation uses recorded timestamps
# ---------------------------------------------------------------------------

def test_mttt_calculation_in_metrics():
    metrics_res = client.get("/api/metrics")
    assert metrics_res.status_code == 200
    m = metrics_res.json()

    assert "alerts_ingested" in m
    assert m["alerts_ingested"] == 3000
    assert "total_incidents" in m
    assert m["total_incidents"] > 0
    assert m["triaged_count"] >= 1
    assert m["average_mttt_seconds"] is not None
    assert m["average_mttt_seconds"] >= 0.0
    assert m["mttt_baseline"] == "Baseline not yet measured"


# ---------------------------------------------------------------------------
# TEST 14: No risk recalculation in API layer
# ---------------------------------------------------------------------------

def test_no_risk_recalculation_in_api():
    repo = get_repository()
    queue_res = client.get("/api/incidents")
    api_incidents = queue_res.json()

    for item in api_incidents[:10]:
        ti = repo.incidents_by_id[item["incident_id"]]
        # Must match repository TriagedIncident values verbatim
        assert item["risk_score"] == ti.risk_score
        assert item["priority"].lower() == ti.priority.value.lower()
        assert item["risk_explanation"] == ti.explanation


# ---------------------------------------------------------------------------
# TEST 15: Dashboard HTML endpoints serve 200
# ---------------------------------------------------------------------------

def test_dashboard_html_served():
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "text/html" in res_root.headers.get("content-type", "")
    assert "SOC Triage" in res_root.text

    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert "text/html" in res_dash.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# TEST 16: Priority filtering on queue endpoint
# ---------------------------------------------------------------------------

def test_incidents_priority_filtering():
    res = client.get("/api/incidents?priority=critical")
    assert res.status_code == 200
    crit_incidents = res.json()
    assert all(inc["priority"].lower() == "critical" for inc in crit_incidents)
