"""
Evidence-grounded AI incident briefing service (Task 9).

Provides concise, evidence-grounded SOC analyst briefs using Groq API (gpt-oss-120b)
with a 100% deterministic fallback for when the API is unavailable, unconfigured,
or returns malformed output.

The deterministic security logic (Tasks 5-8) remains the sole source of truth.
AI does not compute risk scores, change priorities, or invent evidence.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Sequence

from app.models.alert import Alert
from app.models.brief import IncidentBrief
from app.models.triage import TriagedIncident

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 1024

SYSTEM_PROMPT = """You are a senior SOC analyst assistant providing concise, evidence-grounded incident briefings for Tier-1 analysts.

You must strictly adhere to the following rules:
1. Use ONLY the supplied incident evidence in the user message.
2. Do NOT invent facts, IP addresses, users, assets, timestamps, IOCs, techniques, tactics, or actions.
3. If evidence is insufficient for any aspect, explicitly state that evidence is insufficient.
4. Do NOT change, override, or recalculate the supplied risk score, priority, or MITRE mapping. Treat them as deterministic system output.
5. Do NOT claim certainty that the evidence does not support.
6. Keep the brief concise and operational for a Tier-1 SOC analyst:
   - summary: 1-3 sentences describing what occurred.
   - why_it_matters: 1-2 sentences explaining why the incident was prioritized based on the evidence.
   - key_evidence: 3-5 factual bullet points drawn from the supplied evidence.
   - mitre_summary: 1 concise item per relevant MITRE technique present in the evidence.
   - recommended_next_steps: 2-4 practical investigation/verification steps (e.g. review logs, inspect endpoint, check auth).
   - confidence: exactly one of "High", "Medium", or "Low".
7. Recommended next steps must be investigation and verification actions ONLY. Do NOT instruct automatic remediation, blocking, isolation, or deletion.
8. Output MUST be valid JSON conforming strictly to this schema:
{
  "incident_id": "string",
  "summary": "string",
  "why_it_matters": "string",
  "key_evidence": ["string"],
  "mitre_summary": ["string"],
  "recommended_next_steps": ["string"],
  "confidence": "High" | "Medium" | "Low"
}
"""


def build_briefing_payload(
    triaged_incident: TriagedIncident,
    incident_alerts: Sequence[Alert],
) -> dict[str, Any]:
    """
    Construct a deterministic, structured evidence payload from a triaged incident.

    Contains only the factual information necessary for an analyst brief.
    All lists are sorted to ensure deterministic JSON serialization.
    """
    # Deterministic collections from alerts
    assets = sorted({a.asset_id for a in incident_alerts if a.asset_id})
    criticalities = sorted({a.asset_criticality.value for a in incident_alerts})
    users = sorted({a.user for a in incident_alerts if a.user})
    source_ips = sorted({a.source_ip for a in incident_alerts if a.source_ip})
    dest_ips = sorted({a.destination_ip for a in incident_alerts if a.destination_ip})
    iocs = sorted({a.ioc for a in incident_alerts if a.ioc})
    alert_types = sorted({a.alert_type for a in incident_alerts})
    severities = sorted({a.severity.value for a in incident_alerts})

    # MITRE techniques from incident context (already sorted by technique_id asc)
    mitre_techniques = [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "alert_ids": sorted(t.alert_ids),
        }
        for t in triaged_incident.mitre_context.techniques
    ]

    # Correlation evidence
    correlation_evidence = [
        {
            "alert_a": edge.alert_a,
            "alert_b": edge.alert_b,
            "score": edge.score,
            "signals": sorted(edge.signals),
        }
        for edge in triaged_incident.correlation_evidence
    ]

    # Alert descriptions (chronological by alert timestamp, tiebreak by alert_id)
    sorted_alerts = sorted(incident_alerts, key=lambda a: (a.timestamp, a.alert_id))
    alert_descriptions = [
        {
            "alert_id": a.alert_id,
            "timestamp": a.timestamp.isoformat(),
            "source": a.source,
            "alert_type": a.alert_type,
            "severity": a.severity.value,
            "host": a.host,
            "user": a.user,
            "description": a.description,
        }
        for a in sorted_alerts
    ]

    return {
        "incident_id": triaged_incident.incident_id,
        "risk_score": triaged_incident.risk_score,
        "priority": triaged_incident.priority.value.capitalize(),
        "risk_explanation": triaged_incident.explanation,
        "start_time": triaged_incident.start_time.isoformat(),
        "end_time": triaged_incident.end_time.isoformat(),
        "alert_ids": sorted(triaged_incident.alert_ids),
        "alert_count": len(triaged_incident.alert_ids),
        "affected_assets": assets,
        "asset_criticality": criticalities,
        "users": users,
        "source_ips": source_ips,
        "destination_ips": dest_ips,
        "iocs": iocs,
        "alert_types": alert_types,
        "severities": severities,
        "mitre_techniques": mitre_techniques,
        "correlation_evidence": correlation_evidence,
        "alert_descriptions": alert_descriptions,
    }


def build_fallback_brief(
    triaged_incident: TriagedIncident,
    incident_alerts: Sequence[Alert],
) -> IncidentBrief:
    """
    Produce a deterministic template brief strictly grounded in actual incident evidence.

    Used when:
    - GROQ_API_KEY is not configured
    - Groq API is unreachable or times out
    - Model response is malformed or fails schema validation
    """
    priority_str = triaged_incident.priority.value.capitalize()
    n_alerts = len(triaged_incident.alert_ids)

    # Assets & Criticality
    assets = sorted({a.asset_id for a in incident_alerts if a.asset_id})
    asset_str = ", ".join(assets) if assets else "unspecified asset"
    criticalities = sorted({a.asset_criticality.value for a in incident_alerts})
    crit_str = f" ({', '.join(criticalities)})" if criticalities else ""

    # Summary (1-3 sentences)
    summary = (
        f"{priority_str}-priority incident involving {asset_str} "
        f"with {n_alerts} correlated alert{'s' if n_alerts != 1 else ''}."
    )

    # Why it matters (1-2 sentences)
    why_it_matters = (
        f"Risk score {triaged_incident.risk_score:.2f}/100: "
        f"{triaged_incident.explanation}"
    )

    # Key evidence (3-5 factual items drawn strictly from data)
    key_evidence: list[str] = [
        f"Target asset: {asset_str}{crit_str}",
        f"{n_alerts} correlated alert(s) spanning {triaged_incident.start_time.isoformat()} to {triaged_incident.end_time.isoformat()}",
    ]

    users = sorted({a.user for a in incident_alerts if a.user})
    if users:
        key_evidence.append(f"Involved user account(s): {', '.join(users)}")

    iocs = sorted({a.ioc for a in incident_alerts if a.ioc})
    if iocs:
        key_evidence.append(f"Observed IOC(s): {', '.join(iocs)}")

    if triaged_incident.mitre_context.techniques:
        tech_snippets = [
            f"{t.technique_id} ({t.name})"
            for t in triaged_incident.mitre_context.techniques
        ]
        key_evidence.append(f"Identified MITRE technique(s): {', '.join(tech_snippets[:3])}")
    elif len(key_evidence) < 3:
        severities = sorted({a.severity.value for a in incident_alerts})
        key_evidence.append(f"Observed alert severities: {', '.join(severities)}")

    # Ensure key_evidence has 3-5 items
    key_evidence = key_evidence[:5]

    # MITRE summary (1 item per relevant technique)
    mitre_summary = [
        f"{t.technique_id} — {t.name} — {t.tactic}"
        for t in triaged_incident.mitre_context.techniques
    ]

    # Recommended next steps (practical investigation / verification, NOT remediation)
    recommended_next_steps = [
        "Review chronological alert timeline and correlation chain around the incident window.",
    ]
    if users or assets:
        recommended_next_steps.append(
            "Validate whether observed user and host activity aligns with authorized operations."
        )
    if iocs:
        recommended_next_steps.append(
            f"Investigate endpoint and firewall logs for connections involving observed IOC(s): {', '.join(iocs)}."
        )
    if triaged_incident.mitre_context.techniques:
        recommended_next_steps.append(
            "Inspect command-line arguments, process trees, and artifacts associated with observed MITRE techniques."
        )

    # Cap next steps to 4 practical items
    recommended_next_steps = recommended_next_steps[:4]

    return IncidentBrief(
        incident_id=triaged_incident.incident_id,
        summary=summary,
        why_it_matters=why_it_matters,
        key_evidence=key_evidence,
        mitre_summary=mitre_summary,
        recommended_next_steps=recommended_next_steps,
        confidence="Medium",
    )


def get_groq_client(api_key: str | None = None) -> Any:
    """
    Safely initialize and return a Groq client if an API key is available.

    Returns None if GROQ_API_KEY is unset or blank.
    """
    key = api_key or os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        return None
    try:
        from groq import Groq
        return Groq(api_key=key)
    except Exception as exc:
        logger.warning("Failed to initialize Groq client: %s", exc)
        return None


def generate_incident_brief(
    triaged_incident: TriagedIncident,
    incident_alerts: Sequence[Alert],
    client: Any = None,
) -> IncidentBrief:
    """
    Generate an evidence-grounded incident brief for Tier-1 SOC analysts.

    Attempts generation via Groq API (openai/gpt-oss-120b). If the API key is
    missing, unreachable, times out, or returns invalid JSON/schema, seamlessly
    falls back to the deterministic evidence-grounded template brief.

    Parameters
    ----------
    triaged_incident : TriagedIncident
        The correlated, risk-assessed, and MITRE-enriched incident.
    incident_alerts : Sequence[Alert]
        The Alert objects supporting this incident.
    client : Any, optional
        Injected Groq client (primarily for testing and mock injection).

    Returns
    -------
    IncidentBrief
        Validated structured analyst briefing.
    """
    # 1. Build deterministic evidence payload
    payload = build_briefing_payload(triaged_incident, incident_alerts)

    # 2. Check for configured Groq client
    groq_client = client if client is not None else get_groq_client()
    if groq_client is None:
        return build_fallback_brief(triaged_incident, incident_alerts)

    # 3. Attempt LLM generation
    model_name = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
    user_content = json.dumps(payload, indent=2, sort_keys=True)

    try:
        completion = groq_client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=DEFAULT_TEMPERATURE,
            max_tokens=DEFAULT_MAX_TOKENS,
            response_format={"type": "json_object"},
        )

        response_text = completion.choices[0].message.content
        if not response_text:
            return build_fallback_brief(triaged_incident, incident_alerts)

        # 4. Validate output with Pydantic
        parsed_json = json.loads(response_text)
        # Ensure incident_id matches and record source
        parsed_json["incident_id"] = triaged_incident.incident_id
        parsed_json["generation_source"] = "groq"
        parsed_json["is_fallback"] = False
        return IncidentBrief.model_validate(parsed_json)

    except Exception as exc:
        logger.warning(
            "Groq generation failed for incident %s; falling back to deterministic template. Error: %s",
            triaged_incident.incident_id,
            type(exc).__name__,
        )
        return build_fallback_brief(triaged_incident, incident_alerts)
