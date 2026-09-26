"""
MITRE ATT&CK mapping and security context service (Task 8).

Provides a local, deterministic MITRE ATT&CK catalogue and context enrichment
for incidents based on technique IDs present in alerts.

This service does not make external HTTP requests, use LLMs, or recalculate
risk scores. It enriches incidents with security context only.
"""

from __future__ import annotations

from typing import Iterable

from app.models.alert import Alert
from app.models.mitre import (
    IncidentMITREContext,
    MITRETechnique,
    MITRETechniqueContext,
)

# ---------------------------------------------------------------------------
# Local MITRE ATT&CK Prototype Catalogue
# ---------------------------------------------------------------------------
# Contains deterministic mappings for the techniques used in the synthetic
# SOC dataset. Easily extensible with additional techniques.
# ---------------------------------------------------------------------------

MITRE_CATALOGUE: dict[str, MITRETechnique] = {
    "T1003.001": MITRETechnique(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic="Credential Access",
    ),
    "T1003.006": MITRETechnique(
        technique_id="T1003.006",
        name="OS Credential Dumping: DCSync",
        tactic="Credential Access",
    ),
    "T1021.002": MITRETechnique(
        technique_id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
    ),
    "T1021.006": MITRETechnique(
        technique_id="T1021.006",
        name="Remote Services: Windows Remote Management",
        tactic="Lateral Movement",
    ),
    "T1046": MITRETechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
    ),
    "T1048": MITRETechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
    ),
    "T1052.001": MITRETechnique(
        technique_id="T1052.001",
        name="Exfiltration Over Physical Medium: Exfiltration over USB",
        tactic="Exfiltration",
    ),
    "T1053.005": MITRETechnique(
        technique_id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic="Execution",
    ),
    "T1055": MITRETechnique(
        technique_id="T1055",
        name="Process Injection",
        tactic="Defense Evasion",
    ),
    "T1059.001": MITRETechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
    ),
    "T1059.004": MITRETechnique(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
    ),
    "T1071.001": MITRETechnique(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
    ),
    "T1074.001": MITRETechnique(
        technique_id="T1074.001",
        name="Data Staged: Local Data Staging",
        tactic="Collection",
    ),
    "T1078": MITRETechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion",
    ),
    "T1110.001": MITRETechnique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
    ),
    "T1110.004": MITRETechnique(
        technique_id="T1110.004",
        name="Brute Force: Password Spraying",
        tactic="Credential Access",
    ),
    "T1137.001": MITRETechnique(
        technique_id="T1137.001",
        name="Office Application Startup: Office Template Macros",
        tactic="Persistence",
    ),
    "T1190": MITRETechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
    ),
    "T1213": MITRETechnique(
        technique_id="T1213",
        name="Data from Information Repositories",
        tactic="Collection",
    ),
    "T1218": MITRETechnique(
        technique_id="T1218",
        name="System Binary Proxy Execution",
        tactic="Defense Evasion",
    ),
    "T1486": MITRETechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
    ),
    "T1505.003": MITRETechnique(
        technique_id="T1505.003",
        name="Server Software Component: Web Shell",
        tactic="Persistence",
    ),
    "T1558.001": MITRETechnique(
        technique_id="T1558.001",
        name="Steal or Forge Kerberos Tickets: Golden Ticket",
        tactic="Credential Access",
    ),
    "T1566.001": MITRETechnique(
        technique_id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
    ),
}

FALLBACK_NAME = "Unknown technique"
FALLBACK_TACTIC = "Unknown"


def get_technique(technique_id: str) -> MITRETechnique:
    """
    Look up a MITRE technique in the local catalogue.

    Returns the known MITRETechnique if present; otherwise returns a safe fallback
    preserving the original technique_id with 'Unknown technique' / 'Unknown'.
    """
    if technique_id in MITRE_CATALOGUE:
        return MITRE_CATALOGUE[technique_id]
    return MITRETechnique(
        technique_id=technique_id,
        name=FALLBACK_NAME,
        tactic=FALLBACK_TACTIC,
    )


def build_mitre_context(alerts: Iterable[Alert]) -> IncidentMITREContext:
    """
    Extract, group, resolve, and sort MITRE ATT&CK security context for a set of alerts.

    Logic:
    1. Inspect all associated alerts.
    2. Read each alert's mitre_technique field.
    3. Ignore missing/null or empty MITRE techniques.
    4. Group alerts by exact technique ID.
    5. Resolve each technique ID through the local catalogue (with safe fallback).
    6. Store supporting alert IDs deterministically sorted within each technique.
    7. Sort techniques deterministically by technique_id ascending.

    Returns
    -------
    IncidentMITREContext
        The enriched MITRE context with sorted techniques and technique count.
    """
    if not alerts:
        return IncidentMITREContext(techniques=[], technique_count=0)

    # Group alert IDs by exact technique ID
    tech_to_alerts: dict[str, set[str]] = {}
    for alert in alerts:
        tid = alert.mitre_technique
        if tid is None:
            continue
        tid = tid.strip()
        if not tid:
            continue
        if tid not in tech_to_alerts:
            tech_to_alerts[tid] = set()
        tech_to_alerts[tid].add(alert.alert_id)

    if not tech_to_alerts:
        return IncidentMITREContext(techniques=[], technique_count=0)

    # Build deterministic sorted technique contexts
    techniques: list[MITRETechniqueContext] = []
    for tid in sorted(tech_to_alerts.keys()):
        catalogue_entry = get_technique(tid)
        sorted_alert_ids = sorted(tech_to_alerts[tid])
        techniques.append(
            MITRETechniqueContext(
                technique_id=catalogue_entry.technique_id,
                name=catalogue_entry.name,
                tactic=catalogue_entry.tactic,
                alert_ids=sorted_alert_ids,
            )
        )

    return IncidentMITREContext(
        techniques=techniques,
        technique_count=len(techniques),
    )
