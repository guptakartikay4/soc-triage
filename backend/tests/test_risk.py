"""
Unit tests for the deterministic risk engine.

Run from backend/ with:  python -m pytest tests/ -v
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from app.models.alert import Alert, AssetCriticality, SeverityLevel
from app.models.incident import CorrelationEdge, Incident
from app.models.risk import RiskAssessment, RiskPriority
from app.services.risk import (
    assess_risk,
    _severity_component,
    _asset_criticality_component,
    _correlation_strength_component,
    _evidence_strength_component,
    _attack_context_component,
    _priority,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 9, 25, 10, 0, 0, tzinfo=timezone.utc)
_counter = 0


def _ts(offset: int = 0) -> datetime:
    return _T0 + timedelta(minutes=offset)


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
        alert_id=alert_id or f"ALT-{_counter:05d}",
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


def _incident(
    alerts: list[Alert],
    incident_id: str = "INC-001",
    correlation_score: float = 0.0,
    edges: list[CorrelationEdge] | None = None,
) -> Incident:
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    return Incident(
        incident_id=incident_id,
        alert_ids=[a.alert_id for a in sorted_alerts],
        start_time=sorted_alerts[0].timestamp,
        end_time=sorted_alerts[-1].timestamp,
        correlation_score=correlation_score,
        correlation_evidence=edges or [],
    )


# ---------------------------------------------------------------------------
# Score bounds
# ---------------------------------------------------------------------------

class TestScoreBounds:
    def test_risk_score_is_within_0_100(self):
        a = _alert(severity="low", asset_criticality="low")
        inc = _incident([a])
        result = assess_risk(inc, [a])
        assert 0.0 <= result.risk_score <= 100.0

    def test_maximum_inputs_do_not_exceed_100(self):
        a = _alert(
            severity="critical",
            asset_criticality="critical",
            ioc="evil.example.com",
            mitre_technique="T1059.001",
            description="Mimikatz credential dump exfil beacon c2 exploit shell.",
        )
        inc = _incident([a], correlation_score=1.0)
        result = assess_risk(inc, [a])
        assert result.risk_score <= 100.0

    def test_minimum_inputs_are_above_or_equal_0(self):
        a = _alert(severity="low", asset_criticality="low",
                   description="Routine scan.")
        inc = _incident([a], correlation_score=0.0)
        result = assess_risk(inc, [a])
        assert result.risk_score >= 0.0

    def test_component_scores_within_bounds(self):
        a = _alert(severity="high", asset_criticality="high",
                   mitre_technique="T1059", ioc="bad.io")
        inc = _incident([a], correlation_score=0.7)
        result = assess_risk(inc, [a])
        c = result.components
        for score in [c.severity, c.asset_criticality, c.correlation_strength,
                      c.evidence_strength, c.attack_context]:
            assert 0.0 <= score <= 100.0, f"Component out of bounds: {score}"


# ---------------------------------------------------------------------------
# Severity affects risk
# ---------------------------------------------------------------------------

class TestSeverityAffectsRisk:
    def test_critical_severity_higher_than_low(self):
        low_a  = _alert(severity="low",      asset_criticality="medium")
        crit_a = _alert(severity="critical",  asset_criticality="medium")
        low_inc  = _incident([low_a],  correlation_score=0.5)
        crit_inc = _incident([crit_a], correlation_score=0.5)
        low_r  = assess_risk(low_inc,  [low_a])
        crit_r = assess_risk(crit_inc, [crit_a])
        assert crit_r.risk_score > low_r.risk_score

    def test_severity_ordering_is_monotonic(self):
        scores = []
        for sev in ("low", "medium", "high", "critical"):
            a = _alert(severity=sev, asset_criticality="medium")
            inc = _incident([a], correlation_score=0.5)
            scores.append(assess_risk(inc, [a]).risk_score)
        assert scores == sorted(scores), "Severity scores are not monotonically increasing"

    def test_severity_component_values(self):
        for sev, expected in [("low", 25.0), ("medium", 50.0),
                               ("high", 75.0), ("critical", 100.0)]:
            a = _alert(severity=sev)
            assert _severity_component([a]) == expected


# ---------------------------------------------------------------------------
# Asset criticality affects risk
# ---------------------------------------------------------------------------

class TestAssetCriticalityAffectsRisk:
    def test_critical_asset_higher_than_low_asset(self):
        low_a  = _alert(severity="medium", asset_criticality="low")
        crit_a = _alert(severity="medium", asset_criticality="critical")
        low_inc  = _incident([low_a],  correlation_score=0.5)
        crit_inc = _incident([crit_a], correlation_score=0.5)
        low_r  = assess_risk(low_inc,  [low_a])
        crit_r = assess_risk(crit_inc, [crit_a])
        assert crit_r.risk_score > low_r.risk_score

    def test_criticality_ordering_is_monotonic(self):
        scores = []
        for crit in ("low", "medium", "high", "critical"):
            a = _alert(severity="medium", asset_criticality=crit)
            inc = _incident([a], correlation_score=0.5)
            scores.append(assess_risk(inc, [a]).risk_score)
        assert scores == sorted(scores)

    def test_criticality_component_values(self):
        for crit, expected in [("low", 25.0), ("medium", 50.0),
                                ("high", 75.0), ("critical", 100.0)]:
            a = _alert(asset_criticality=crit)
            assert _asset_criticality_component([a]) == expected


# ---------------------------------------------------------------------------
# Priority thresholds
# ---------------------------------------------------------------------------

class TestPriorityThresholds:
    def test_priority_below_40_is_low(self):
        assert _priority(0.0)   == RiskPriority.low
        assert _priority(10.0)  == RiskPriority.low
        assert _priority(39.99) == RiskPriority.low

    def test_priority_40_to_59_is_medium(self):
        assert _priority(40.0)  == RiskPriority.medium
        assert _priority(50.0)  == RiskPriority.medium
        assert _priority(59.99) == RiskPriority.medium

    def test_priority_60_to_79_is_high(self):
        assert _priority(60.0)  == RiskPriority.high
        assert _priority(70.0)  == RiskPriority.high
        assert _priority(79.99) == RiskPriority.high

    def test_priority_80_to_100_is_critical(self):
        assert _priority(80.0)  == RiskPriority.critical
        assert _priority(90.0)  == RiskPriority.critical
        assert _priority(100.0) == RiskPriority.critical

    def test_full_risk_assessment_has_correct_priority(self):
        """High severity + critical asset should produce at least High priority."""
        a = _alert(severity="critical", asset_criticality="critical")
        inc = _incident([a], correlation_score=0.9)
        result = assess_risk(inc, [a])
        assert result.priority in (RiskPriority.high, RiskPriority.critical)


# ---------------------------------------------------------------------------
# Correlation strength
# ---------------------------------------------------------------------------

class TestCorrelationStrength:
    def test_high_correlation_score_increases_risk(self):
        a = _alert(severity="medium", asset_criticality="medium")
        low_inc  = _incident([a], correlation_score=0.0)
        high_inc = _incident([a], correlation_score=1.0)
        low_r  = assess_risk(low_inc,  [a])
        high_r = assess_risk(high_inc, [a])
        assert high_r.risk_score > low_r.risk_score

    def test_correlation_component_maps_correctly(self):
        a = _alert()
        inc_half = _incident([a], correlation_score=0.5)
        assert _correlation_strength_component(inc_half) == pytest.approx(50.0)

    def test_zero_correlation_component(self):
        a = _alert()
        inc = _incident([a], correlation_score=0.0)
        assert _correlation_strength_component(inc) == 0.0


# ---------------------------------------------------------------------------
# Evidence strength
# ---------------------------------------------------------------------------

class TestEvidenceStrength:
    def test_more_alerts_increases_evidence_score(self):
        alerts_single = [_alert()]
        alerts_multi  = [_alert() for _ in range(5)]
        assert _evidence_strength_component(alerts_multi) > \
               _evidence_strength_component(alerts_single)

    def test_unique_iocs_increase_evidence_score(self):
        no_ioc   = [_alert(ioc=None)]
        with_ioc = [_alert(ioc="evil1.com"), _alert(ioc="evil2.com")]
        assert _evidence_strength_component(with_ioc) > \
               _evidence_strength_component(no_ioc)

    def test_unique_techniques_increase_evidence_score(self):
        no_tech   = [_alert(mitre_technique=None)]
        with_tech = [_alert(mitre_technique="T1059"), _alert(mitre_technique="T1003")]
        assert _evidence_strength_component(with_tech) > \
               _evidence_strength_component(no_tech)

    def test_empty_alert_list_returns_zero(self):
        assert _evidence_strength_component([]) == 0.0

    def test_evidence_capped_at_100(self):
        alerts = [
            _alert(ioc=f"ioc{i}.com", mitre_technique=f"T{1000+i}")
            for i in range(20)
        ]
        score = _evidence_strength_component(alerts)
        assert score <= 100.0


# ---------------------------------------------------------------------------
# Attack context
# ---------------------------------------------------------------------------

class TestAttackContext:
    def test_attack_keywords_in_description_raise_context(self):
        benign = _alert(description="Scheduled antivirus scan completed.")
        attack = _alert(description="Mimikatz credential dump detected with lateral movement.")
        benign_ctx = _attack_context_component([benign])
        attack_ctx = _attack_context_component([attack])
        assert attack_ctx > benign_ctx

    def test_mitre_technique_raises_context(self):
        no_tech   = [_alert(mitre_technique=None,    description="Normal activity.")]
        with_tech = [_alert(mitre_technique="T1059",  description="Normal activity.")]
        assert _attack_context_component(with_tech) > \
               _attack_context_component(no_tech)

    def test_empty_returns_zero(self):
        assert _attack_context_component([]) == 0.0

    def test_attack_context_capped_at_100(self):
        alerts = [
            _alert(mitre_technique=f"T{1000+i}",
                   description="exploit injection lateral exfil shell")
            for i in range(10)
        ]
        assert _attack_context_component(alerts) <= 100.0


# ---------------------------------------------------------------------------
# Explanation
# ---------------------------------------------------------------------------

class TestExplanation:
    def test_explanation_is_non_empty(self):
        a = _alert(severity="high", asset_criticality="high")
        inc = _incident([a])
        result = assess_risk(inc, [a])
        assert result.explanation.strip() != ""

    def test_explanation_contains_priority(self):
        a = _alert(severity="critical", asset_criticality="critical",
                   description="ransomware exfil shell payload")
        inc = _incident([a], correlation_score=1.0)
        result = assess_risk(inc, [a])
        assert result.priority.value in result.explanation

    def test_explanation_contains_alert_count(self):
        alerts = [_alert() for _ in range(3)]
        inc = _incident(alerts, correlation_score=0.6)
        result = assess_risk(inc, alerts)
        assert "3" in result.explanation

    def test_explanation_mentions_mitre_when_present(self):
        a = _alert(mitre_technique="T1059.001",
                   description="PowerShell encoded command.")
        inc = _incident([a])
        result = assess_risk(inc, [a])
        assert "t1059" in result.explanation.lower()

    def test_explanation_mentions_critical_asset(self):
        a = _alert(asset_criticality="critical",
                   description="Routine check.")
        inc = _incident([a])
        result = assess_risk(inc, [a])
        assert "critical" in result.explanation.lower()

    def test_explanation_mentions_ioc_when_present(self):
        a = _alert(ioc="badactor.org", description="C2 beacon detected.")
        inc = _incident([a])
        result = assess_risk(inc, [a])
        assert "IOC" in result.explanation or "ioc" in result.explanation.lower()


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_inputs_produce_same_output(self):
        a = _alert(severity="high", asset_criticality="high",
                   mitre_technique="T1078", ioc="c2.evil.io",
                   description="Credential dump lateral exfil.")
        inc = _incident([a], correlation_score=0.75)
        r1 = assess_risk(inc, [a])
        r2 = assess_risk(inc, [a])
        assert r1.risk_score   == r2.risk_score
        assert r1.priority     == r2.priority
        assert r1.explanation  == r2.explanation

    def test_order_of_alerts_does_not_change_score(self):
        a = _alert(severity="high",   asset_criticality="high",
                   alert_id="DET-A",  timestamp=_ts(0))
        b = _alert(severity="medium", asset_criticality="medium",
                   alert_id="DET-B",  timestamp=_ts(5))
        inc = _incident([a, b], correlation_score=0.6)
        r1 = assess_risk(inc, [a, b])
        r2 = assess_risk(inc, [b, a])
        assert r1.risk_score == r2.risk_score


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_single_alert_no_correlation(self):
        a = _alert(severity="medium", asset_criticality="medium",
                   description="Normal activity.")
        inc = _incident([a], correlation_score=0.0)
        result = assess_risk(inc, [a])
        assert isinstance(result, RiskAssessment)
        assert result.components.correlation_strength == 0.0

    def test_alerts_with_all_optional_fields_none(self):
        a = Alert(
            alert_id="EDGE-001",
            timestamp=_T0,
            source="EDR",
            alert_type="Generic",
            severity=SeverityLevel.low,
            asset_id="ASSET-001",
            asset_criticality=AssetCriticality.low,
            description="A bare-minimum alert with no optional fields.",
        )
        inc = _incident([a], correlation_score=0.0)
        result = assess_risk(inc, [a])
        assert result.risk_score >= 0.0

    def test_extra_alerts_not_in_incident_are_ignored(self):
        a = _alert(alert_id="MAIN-01", severity="high",
                   asset_criticality="high")
        extra = _alert(alert_id="EXTRA-01", severity="critical",
                       asset_criticality="critical")
        inc = _incident([a], correlation_score=0.5)
        # extra is passed in the alerts list but NOT in incident.alert_ids
        result_with_extra    = assess_risk(inc, [a, extra])
        result_without_extra = assess_risk(inc, [a])
        assert result_with_extra.risk_score == result_without_extra.risk_score

    def test_risk_assessment_incident_id_matches(self):
        a = _alert()
        inc = _incident([a], incident_id="INC-042")
        result = assess_risk(inc, [a])
        assert result.incident_id == "INC-042"
