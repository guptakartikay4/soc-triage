"""
Tests for the synthetic SOC dataset generator.

Runs from backend/ with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

# Make backend/data importable regardless of working directory
DATA_DIR = Path(__file__).parent.parent / "data"
sys.path.insert(0, str(DATA_DIR))

from generate_dataset import (  # noqa: E402
    ASSETS,
    SEED,
    TOTAL_ALERTS,
    VALID_CRITICALITIES,
    VALID_SEVERITIES,
    generate,
    write_alerts,
    write_assets,
)

VALID_CRITICALITIES_LOWER = {c.lower() for c in VALID_CRITICALITIES}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def alerts():
    """Generate dataset once per module."""
    return generate(seed=SEED, total=TOTAL_ALERTS)


@pytest.fixture(scope="module")
def asset_ids():
    return {a[0] for a in ASSETS}


# ---------------------------------------------------------------------------
# Core integrity tests
# ---------------------------------------------------------------------------

def test_exactly_3000_alerts(alerts):
    assert len(alerts) == 3000, f"Expected 3000 alerts, got {len(alerts)}"


def test_alert_ids_are_unique(alerts):
    ids = [r["alert_id"] for r in alerts]
    assert len(ids) == len(set(ids)), "Duplicate alert IDs found"


def test_alert_ids_format(alerts):
    for row in alerts:
        assert row["alert_id"].startswith("ALT-"), f"Bad alert_id: {row['alert_id']}"


def test_asset_ids_exist_in_inventory(alerts, asset_ids):
    missing = {r["asset_id"] for r in alerts if r["asset_id"] not in asset_ids}
    assert not missing, f"Alerts reference unknown asset_ids: {missing}"


# ---------------------------------------------------------------------------
# Scenario tests
# ---------------------------------------------------------------------------

def test_scenario_ids_present(alerts):
    scenario_alerts = [r for r in alerts if r["scenario_id"]]
    assert len(scenario_alerts) > 0, "No scenario-linked alerts found"


def test_multiple_unique_scenarios(alerts):
    unique = {r["scenario_id"] for r in alerts if r["scenario_id"]}
    assert len(unique) >= 6, f"Expected ≥6 unique scenarios, got {len(unique)}: {unique}"


def test_both_benign_and_malicious_present(alerts):
    benign     = [r for r in alerts if r["is_benign"] == "true"]
    malicious  = [r for r in alerts if r["is_benign"] == "false"]
    assert len(benign)    > 0, "No benign alerts found"
    assert len(malicious) > 0, "No malicious/scenario alerts found"


def test_critical_asset_scenario_exists(alerts):
    """At least one scenario must target a Critical asset."""
    critical_scenario = [
        r for r in alerts
        if r["scenario_id"]
        and r["asset_criticality"].lower() == "critical"
    ]
    assert len(critical_scenario) > 0, (
        "No scenario alerts found targeting a Critical asset"
    )


# ---------------------------------------------------------------------------
# Field-value validation
# ---------------------------------------------------------------------------

def test_all_severity_values_valid(alerts):
    invalid = {r["severity"] for r in alerts if r["severity"] not in VALID_SEVERITIES}
    assert not invalid, f"Invalid severity values found: {invalid}"


def test_all_asset_criticality_values_valid(alerts):
    """asset_criticality column uses Title-case (Low/Medium/High/Critical)."""
    invalid = {
        r["asset_criticality"] for r in alerts
        if r["asset_criticality"].lower() not in VALID_CRITICALITIES_LOWER
    }
    assert not invalid, f"Invalid asset_criticality values: {invalid}"


def test_required_columns_present(alerts):
    required = {
        "alert_id", "timestamp", "source", "alert_type", "severity",
        "asset_id", "asset_criticality", "description", "scenario_id", "is_benign",
    }
    for col in required:
        assert col in alerts[0], f"Missing required column: {col}"


def test_timestamps_not_empty(alerts):
    empty_ts = [r["alert_id"] for r in alerts if not r["timestamp"]]
    assert not empty_ts, f"Alerts with empty timestamps: {empty_ts[:5]}"


# ---------------------------------------------------------------------------
# Determinism test
# ---------------------------------------------------------------------------

def test_generator_is_deterministic():
    run1 = generate(seed=SEED, total=100)
    run2 = generate(seed=SEED, total=100)
    assert run1 == run2, "Generator is not deterministic with the same seed"


def test_different_seed_produces_different_output():
    run1 = generate(seed=SEED,      total=50)
    run2 = generate(seed=SEED + 1,  total=50)
    # They should differ in at least some rows
    assert run1 != run2, "Different seeds produced identical output"


# ---------------------------------------------------------------------------
# Asset inventory tests
# ---------------------------------------------------------------------------

def test_asset_inventory_not_empty():
    assert len(ASSETS) > 0


def test_asset_inventory_has_required_fields():
    # ASSETS is a list of tuples: (asset_id, hostname, type, criticality, dept, owner)
    for asset in ASSETS:
        assert len(asset) == 6, f"Asset tuple has wrong length: {asset}"
        asset_id, hostname, atype, criticality, dept, owner = asset
        assert asset_id, "Empty asset_id"
        assert hostname, "Empty hostname"
        assert criticality in VALID_CRITICALITIES, f"Invalid criticality: {criticality}"


def test_asset_ids_are_unique_in_inventory():
    ids = [a[0] for a in ASSETS]
    assert len(ids) == len(set(ids)), "Duplicate asset IDs in inventory"


# ---------------------------------------------------------------------------
# CSV round-trip tests
# ---------------------------------------------------------------------------

def test_write_and_read_alerts_csv(tmp_path, alerts):
    csv_path = tmp_path / "test_alerts.csv"
    write_alerts(alerts, csv_path)
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == TOTAL_ALERTS


def test_write_and_read_assets_csv(tmp_path):
    csv_path = tmp_path / "test_assets.csv"
    write_assets(csv_path)
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(ASSETS)
    assert "asset_id" in rows[0]
    assert "criticality" in rows[0]
