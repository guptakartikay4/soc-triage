"""
Tests for POST /api/alerts/ingest and the ingestion service.

Run from backend/ with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.ingestion import ingest_alerts

client = TestClient(app)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

VALID_ALERT = {
    "alert_id": "ALT-00001",
    "timestamp": "2026-09-25T00:07:29Z",
    "source": "EDR",
    "alert_type": "Failed Login",
    "severity": "medium",
    "source_ip": "203.5.29.238",
    "destination_ip": "192.225.253.213",
    "user": "cfo",
    "host": "WS-EXEC-001",
    "asset_id": "ASSET-020",
    "asset_criticality": "critical",
    "ioc": None,
    "description": "Multiple failed login attempts detected.",
    "mitre_technique": "T1110.004",
}

VALID_ALERT_2 = {
    "alert_id": "ALT-00002",
    "timestamp": "2026-09-25T01:12:00Z",
    "source": "SIEM",
    "alert_type": "PowerShell Execution",
    "severity": "high",
    "source_ip": "10.0.1.50",
    "destination_ip": None,
    "user": "admin01",
    "host": "WS-FIN-014",
    "asset_id": "ASSET-014",
    "asset_criticality": "high",
    "ioc": None,
    "description": "PowerShell with encoded command executed.",
    "mitre_technique": "T1059.001",
}

INVALID_ALERT = {
    "alert_id": "ALT-BAD-001",
    # missing required: timestamp, source, alert_type, asset_id, asset_criticality, description
    "severity": "EXTREME",          # also invalid enum value
}


# ---------------------------------------------------------------------------
# Service-level unit tests (no HTTP)
# ---------------------------------------------------------------------------

class TestIngestionService:
    def test_single_valid_alert_accepted(self):
        result = ingest_alerts([VALID_ALERT])
        assert len(result.accepted) == 1
        assert result.rejected == 0
        assert result.total_received == 1

    def test_multiple_valid_alerts_accepted(self):
        result = ingest_alerts([VALID_ALERT, VALID_ALERT_2])
        assert len(result.accepted) == 2
        assert result.rejected == 0

    def test_invalid_alert_rejected_without_crashing_batch(self):
        result = ingest_alerts([VALID_ALERT, INVALID_ALERT, VALID_ALERT_2])
        assert len(result.accepted) == 2
        assert result.rejected == 1
        assert result.total_received == 3

    def test_validation_errors_are_structured(self):
        result = ingest_alerts([INVALID_ALERT])
        assert result.rejected == 1
        err = result.validation_errors[0]
        assert err["index"] == 0
        assert err["alert_id"] == "ALT-BAD-001"
        assert isinstance(err["errors"], list)
        assert len(err["errors"]) > 0

    def test_empty_batch_returns_zero_counts(self):
        result = ingest_alerts([])
        assert result.total_received == 0
        assert len(result.accepted) == 0
        assert result.rejected == 0

    def test_all_invalid_batch_returns_all_rejected(self):
        result = ingest_alerts([INVALID_ALERT, INVALID_ALERT])
        assert result.rejected == 2
        assert len(result.accepted) == 0

    def test_accepted_alert_is_alert_model_instance(self):
        from app.models.alert import Alert
        result = ingest_alerts([VALID_ALERT])
        assert isinstance(result.accepted[0], Alert)

    def test_severity_enum_is_validated(self):
        bad = {**VALID_ALERT, "severity": "EXTREME"}
        result = ingest_alerts([bad])
        assert result.rejected == 1
        fields_with_errors = [
            e["loc"][0] for e in result.validation_errors[0]["errors"]
        ]
        assert "severity" in fields_with_errors

    def test_asset_criticality_enum_is_validated(self):
        bad = {**VALID_ALERT, "asset_criticality": "urgent"}
        result = ingest_alerts([bad])
        assert result.rejected == 1

    def test_optional_fields_may_be_none(self):
        minimal = {
            "alert_id": "ALT-MIN-001",
            "timestamp": "2026-09-25T10:00:00Z",
            "source": "AV",
            "alert_type": "Scan Complete",
            "severity": "low",
            "asset_id": "ASSET-001",
            "asset_criticality": "critical",
            "description": "Routine AV scan completed.",
        }
        result = ingest_alerts([minimal])
        assert result.rejected == 0
        assert result.accepted[0].source_ip is None
        assert result.accepted[0].mitre_technique is None


# ---------------------------------------------------------------------------
# HTTP endpoint tests
# ---------------------------------------------------------------------------

class TestIngestEndpoint:
    def test_single_valid_alert_returns_200(self):
        resp = client.post("/api/alerts/ingest", json={"alerts": [VALID_ALERT]})
        assert resp.status_code == 200

    def test_response_contains_required_fields(self):
        resp = client.post("/api/alerts/ingest", json={"alerts": [VALID_ALERT]})
        body = resp.json()
        assert "total_received" in body
        assert "accepted" in body
        assert "rejected" in body
        assert "validation_errors" in body

    def test_single_valid_alert_counts(self):
        resp = client.post("/api/alerts/ingest", json={"alerts": [VALID_ALERT]})
        body = resp.json()
        assert body["total_received"] == 1
        assert body["accepted"] == 1
        assert body["rejected"] == 0
        assert body["validation_errors"] == []

    def test_multiple_valid_alerts_counts(self):
        resp = client.post(
            "/api/alerts/ingest",
            json={"alerts": [VALID_ALERT, VALID_ALERT_2]},
        )
        body = resp.json()
        assert body["total_received"] == 2
        assert body["accepted"] == 2
        assert body["rejected"] == 0

    def test_mixed_batch_counts(self):
        resp = client.post(
            "/api/alerts/ingest",
            json={"alerts": [VALID_ALERT, INVALID_ALERT, VALID_ALERT_2]},
        )
        body = resp.json()
        assert body["total_received"] == 3
        assert body["accepted"] == 2
        assert body["rejected"] == 1

    def test_invalid_alert_error_detail_is_structured(self):
        resp = client.post(
            "/api/alerts/ingest",
            json={"alerts": [INVALID_ALERT]},
        )
        body = resp.json()
        assert body["rejected"] == 1
        err = body["validation_errors"][0]
        assert err["index"] == 0
        assert err["alert_id"] == "ALT-BAD-001"
        assert isinstance(err["errors"], list)

    def test_empty_batch_accepted(self):
        resp = client.post("/api/alerts/ingest", json={"alerts": []})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_received"] == 0
        assert body["accepted"] == 0
        assert body["rejected"] == 0

    def test_health_endpoint_still_works(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
