import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.alert import Alert, SeverityLevel, AssetCriticality

VALID_ALERT = {
    "alert_id": "ALT-00001",
    "timestamp": "2026-09-26T10:15:32Z",
    "source": "EDR",
    "alert_type": "PowerShell Execution",
    "severity": "high",
    "source_ip": "10.10.4.21",
    "destination_ip": None,
    "user": "admin01",
    "host": "WS-FIN-014",
    "asset_id": "ASSET-014",
    "asset_criticality": "critical",
    "ioc": None,
    "description": "PowerShell executed an encoded command.",
    "mitre_technique": "T1059.001",
}


def test_valid_alert_creation():
    alert = Alert(**VALID_ALERT)
    assert alert.alert_id == "ALT-00001"
    assert alert.severity == SeverityLevel.high
    assert alert.asset_criticality == AssetCriticality.critical
    assert alert.description == "PowerShell executed an encoded command."


def test_required_fields_enforced():
    with pytest.raises(ValidationError) as exc_info:
        Alert()  # no fields at all
    errors = exc_info.value.errors()
    required = {e["loc"][0] for e in errors}
    assert "alert_id" in required
    assert "timestamp" in required
    assert "source" in required
    assert "alert_type" in required
    assert "severity" in required
    assert "asset_id" in required
    assert "asset_criticality" in required
    assert "description" in required


def test_invalid_severity_rejected():
    data = {**VALID_ALERT, "severity": "extreme"}
    with pytest.raises(ValidationError) as exc_info:
        Alert(**data)
    assert any(e["loc"][0] == "severity" for e in exc_info.value.errors())


def test_invalid_asset_criticality_rejected():
    data = {**VALID_ALERT, "asset_criticality": "urgent"}
    with pytest.raises(ValidationError) as exc_info:
        Alert(**data)
    assert any(e["loc"][0] == "asset_criticality" for e in exc_info.value.errors())


def test_optional_fields_accept_none():
    data = {**VALID_ALERT, "source_ip": None, "destination_ip": None,
            "user": None, "host": None, "ioc": None, "mitre_technique": None}
    alert = Alert(**data)
    assert alert.source_ip is None
    assert alert.destination_ip is None
    assert alert.user is None
    assert alert.host is None
    assert alert.ioc is None
    assert alert.mitre_technique is None


def test_timestamp_parsed_correctly():
    alert = Alert(**VALID_ALERT)
    assert isinstance(alert.timestamp, datetime)
    assert alert.timestamp.year == 2026
    assert alert.timestamp.month == 9
    assert alert.timestamp.day == 26
    assert alert.timestamp.hour == 10
    assert alert.timestamp.minute == 15
    assert alert.timestamp.second == 32
