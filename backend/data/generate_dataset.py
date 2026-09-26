"""
Synthetic SOC alert dataset generator.

Usage:
    python backend/data/generate_dataset.py
    -- or from backend/data/ --
    python generate_dataset.py

Outputs:
    backend/data/synthetic_alerts.csv   (3,000 rows)
    backend/data/assets.csv             (asset inventory)
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SEED = 42
TOTAL_ALERTS = 3000
WINDOW_START = datetime(2026, 9, 25, 0, 0, 0, tzinfo=timezone.utc)   # 48-hour window
WINDOW_END   = datetime(2026, 9, 26, 23, 59, 59, tzinfo=timezone.utc)

OUTPUT_DIR = Path(__file__).parent
ALERTS_CSV = OUTPUT_DIR / "synthetic_alerts.csv"
ASSETS_CSV = OUTPUT_DIR / "assets.csv"

# ---------------------------------------------------------------------------
# Asset inventory
# ---------------------------------------------------------------------------

ASSETS = [
    # id,           hostname,         type,        criticality, department,       owner
    ("ASSET-001",  "DC-CORP-01",      "server",    "Critical",  "IT",             "sysadmin"),
    ("ASSET-002",  "DC-CORP-02",      "server",    "Critical",  "IT",             "sysadmin"),
    ("ASSET-003",  "FS-CORP-01",      "server",    "High",      "IT",             "sysadmin"),
    ("ASSET-004",  "ERP-SRV-01",      "server",    "Critical",  "Finance",        "erp_admin"),
    ("ASSET-005",  "DB-FIN-01",       "server",    "Critical",  "Finance",        "dba_team"),
    ("ASSET-006",  "WEB-DMZ-01",      "server",    "High",      "Engineering",    "webmaster"),
    ("ASSET-007",  "WEB-DMZ-02",      "server",    "High",      "Engineering",    "webmaster"),
    ("ASSET-008",  "MAIL-SRV-01",     "server",    "High",      "IT",             "sysadmin"),
    ("ASSET-009",  "BUILD-SRV-01",    "server",    "Medium",    "Engineering",    "devops"),
    ("ASSET-010",  "JUMP-SRV-01",     "server",    "High",      "IT",             "sysadmin"),
    ("ASSET-011",  "WS-FIN-001",      "workstation","High",     "Finance",        "alice.morgan"),
    ("ASSET-012",  "WS-FIN-002",      "workstation","High",     "Finance",        "bob.chen"),
    ("ASSET-013",  "WS-FIN-003",      "workstation","Medium",   "Finance",        "carol.west"),
    ("ASSET-014",  "WS-FIN-014",      "workstation","High",     "Finance",        "admin01"),
    ("ASSET-015",  "WS-ENG-001",      "workstation","Medium",   "Engineering",    "dave.kumar"),
    ("ASSET-016",  "WS-ENG-002",      "workstation","Medium",   "Engineering",    "eve.sharma"),
    ("ASSET-017",  "WS-ENG-003",      "workstation","Low",      "Engineering",    "frank.lee"),
    ("ASSET-018",  "WS-HR-001",       "workstation","Medium",   "HR",             "grace.patel"),
    ("ASSET-019",  "WS-HR-002",       "workstation","Low",      "HR",             "henry.xu"),
    ("ASSET-020",  "WS-EXEC-001",     "workstation","Critical",  "Executive",     "cfo"),
    ("ASSET-021",  "WS-EXEC-002",     "workstation","Critical",  "Executive",     "ceo"),
    ("ASSET-022",  "LAPTOP-IT-001",   "laptop",    "Medium",   "IT",             "it_support"),
    ("ASSET-023",  "LAPTOP-IT-002",   "laptop",    "Medium",   "IT",             "it_support"),
    ("ASSET-024",  "LAPTOP-FIN-001",  "laptop",    "High",     "Finance",        "alice.morgan"),
    ("ASSET-025",  "PRINTER-FIN-01",  "printer",   "Low",      "Finance",        "facilities"),
    ("ASSET-026",  "CAMERA-LBY-01",   "iot",       "Low",      "Facilities",     "facilities"),
    ("ASSET-027",  "VPN-GW-01",       "network",   "Critical",  "IT",             "netadmin"),
    ("ASSET-028",  "FW-CORP-01",      "network",   "Critical",  "IT",             "netadmin"),
    ("ASSET-029",  "SW-CORE-01",      "network",   "High",     "IT",             "netadmin"),
    ("ASSET-030",  "BACKUP-SRV-01",   "server",    "High",     "IT",             "sysadmin"),
]

ASSET_MAP = {a[0]: a for a in ASSETS}   # asset_id -> tuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand_ip_internal(rng: random.Random) -> str:
    return f"10.{rng.randint(0,10)}.{rng.randint(0,15)}.{rng.randint(1,254)}"

def rand_ip_external(rng: random.Random) -> str:
    first = rng.choice([45, 62, 91, 104, 185, 192, 198, 203, 212, 216])
    return f"{first}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"

def rand_ts(rng: random.Random, start: datetime, end: datetime) -> datetime:
    delta = int((end - start).total_seconds())
    return start + timedelta(seconds=rng.randint(0, delta))

def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def alert_id(idx: int) -> str:
    return f"ALT-{idx:05d}"

VALID_SEVERITIES       = ["low", "medium", "high", "critical"]
VALID_CRITICALITIES    = ["Low", "Medium", "High", "Critical"]

ENCODED_CMD_SAMPLES = [
    "cABvAHcAZQByAHMAaABlAGwAbAA=",
    "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "dwBnAGUAdAAgAGgAdAB0AHAAOgAvAC8A",
]
C2_DOMAINS = [
    "update-svc.net", "cdn-telemetry.io", "api-metrics.biz",
    "svc-refresh.org", "telemetry-hub.net",
]
LOLBINS = ["mshta.exe", "regsvr32.exe", "certutil.exe", "wmic.exe",
           "bitsadmin.exe", "rundll32.exe", "cscript.exe"]

# ---------------------------------------------------------------------------
# Benign / noise alert templates
# (alert_type, severity, source, description_template, mitre)
# ---------------------------------------------------------------------------

BENIGN_TEMPLATES = [
    ("Failed Login",        "low",    "SIEM",
     "User {user} failed to authenticate from {src_ip}.",
     None),
    ("Account Locked",      "low",    "AD",
     "Account {user} locked after repeated failures.",
     None),
    ("USB Device Connected","low",    "EDR",
     "USB storage device connected to {host}.",
     None),
    ("AV Scan Completed",   "low",    "AV",
     "Scheduled antivirus scan completed on {host}.",
     None),
    ("Patch Applied",       "low",    "SCCM",
     "Security patch KB{patch} applied to {host}.",
     None),
    ("VPN Login",           "low",    "VPN",
     "User {user} connected via VPN from {src_ip}.",
     None),
    ("RDP Session Opened",  "low",    "SIEM",
     "RDP session started on {host} by {user} from {src_ip}.",
     None),
    ("DNS Query Logged",    "low",    "DNS",
     "Routine DNS query for {domain} from {host}.",
     None),
    ("Firewall Rule Added", "medium", "FW",
     "New firewall rule added by {user} on {host}.",
     None),
    ("Service Restarted",   "low",    "SIEM",
     "Service {svc} restarted on {host}.",
     None),
    ("Login Success",       "low",    "AD",
     "Successful login by {user} on {host} from {src_ip}.",
     None),
    ("Script Block Logged", "medium", "EDR",
     "PowerShell script block logged on {host} by {user}.",
     "T1059.001"),
    ("HTTPS Traffic",       "low",    "PROXY",
     "Outbound HTTPS to {domain} from {host}.",
     None),
    ("Large File Transfer",  "medium","DLP",
     "User {user} transferred {mb}MB to {domain}.",
     None),
    ("Scheduled Task Created","medium","SIEM",
     "Scheduled task created by {user} on {host}.",
     "T1053.005"),
]

ADMIN_TEMPLATES = [
    ("Admin Tool Executed",  "low",   "EDR",
     "Admin tool {tool} executed by {user} on {host}.",
     None),
    ("Group Policy Updated", "low",   "AD",
     "GPO updated by {user}.",
     None),
    ("Backup Job Completed", "low",   "Backup",
     "Backup job completed for {host}.",
     None),
    ("Software Installed",   "low",   "SCCM",
     "Software {sw} installed on {host} by {user}.",
     None),
    ("Certificate Renewed",  "low",   "PKI",
     "TLS certificate renewed for {host}.",
     None),
]

# ---------------------------------------------------------------------------
# Attack scenario definitions
# ---------------------------------------------------------------------------

class Scenario:
    def __init__(self, scenario_id, name, asset_id, chain):
        self.scenario_id = scenario_id
        self.name = name
        self.asset_id = asset_id
        self.chain = chain   # list of step dicts

def build_scenarios():
    return [
        # ------------------------------------------------------------------
        # S-001: Credential stuffing → PowerShell → C2 on CRITICAL exec WS
        # ------------------------------------------------------------------
        Scenario("S-001", "Credential Stuffing to C2 on Executive Workstation",
                 "ASSET-021",
                 [
                    {"step": 1, "alert_type": "Failed Login",        "severity": "medium",
                     "source": "SIEM",   "mitre": "T1110.004",
                     "desc": "Multiple failed logins for user {user} from {src_ip} (password spray pattern)."},
                    {"step": 2, "alert_type": "Failed Login",        "severity": "medium",
                     "source": "SIEM",   "mitre": "T1110.004",
                     "desc": "Credential stuffing detected: {user} from {src_ip}, 47 attempts in 3 minutes."},
                    {"step": 3, "alert_type": "Successful Login After Failures", "severity": "high",
                     "source": "AD",     "mitre": "T1078",
                     "desc": "Account {user} logged in successfully after 47 prior failures from {src_ip}."},
                    {"step": 4, "alert_type": "PowerShell Execution",  "severity": "high",
                     "source": "EDR",    "mitre": "T1059.001",
                     "desc": "PowerShell launched with encoded payload on {host} by {user}."},
                    {"step": 5, "alert_type": "Suspicious Network Connection", "severity": "critical",
                     "source": "NDR",    "mitre": "T1071.001",
                     "desc": "Outbound HTTPS beacon to {dst_ip} ({ioc}) from {host} — possible C2."},
                    {"step": 6, "alert_type": "Data Staged for Exfiltration", "severity": "critical",
                     "source": "DLP",    "mitre": "T1074.001",
                     "desc": "Large archive created in TEMP by {user} on {host} (possible staging)."},
                 ]),

        # ------------------------------------------------------------------
        # S-002: LOLBin lateral movement via WMI on Finance server (CRITICAL)
        # ------------------------------------------------------------------
        Scenario("S-002", "WMI Lateral Movement to Finance DB",
                 "ASSET-005",
                 [
                    {"step": 1, "alert_type": "LOLBin Execution",      "severity": "medium",
                     "source": "EDR",    "mitre": "T1218",
                     "desc": "Living-off-the-land binary {lolbin} executed on {host} by {user}."},
                    {"step": 2, "alert_type": "Remote Service Access",  "severity": "high",
                     "source": "SIEM",   "mitre": "T1021.006",
                     "desc": "WMI remote execution observed from {src_ip} to {host}."},
                    {"step": 3, "alert_type": "Privilege Escalation Attempt", "severity": "high",
                     "source": "EDR",    "mitre": "T1055",
                     "desc": "Process injection detected on {host}; target: lsass.exe."},
                    {"step": 4, "alert_type": "Credential Dumping",    "severity": "critical",
                     "source": "EDR",    "mitre": "T1003.001",
                     "desc": "Mimikatz-like memory access to LSASS on {host} by {user}."},
                    {"step": 5, "alert_type": "Lateral Movement",      "severity": "critical",
                     "source": "SIEM",   "mitre": "T1021.002",
                     "desc": "SMB lateral movement from {src_ip} to DB-FIN-01 using harvested credentials."},
                 ]),

        # ------------------------------------------------------------------
        # S-003: Network recon → exploitation on web server
        # ------------------------------------------------------------------
        Scenario("S-003", "Port Scan to Web Server Exploitation",
                 "ASSET-006",
                 [
                    {"step": 1, "alert_type": "Network Scan Detected",  "severity": "medium",
                     "source": "IDS",    "mitre": "T1046",
                     "desc": "SYN scan from {src_ip} ({ioc}) targeting DMZ subnet, 1,200 ports in 90s."},
                    {"step": 2, "alert_type": "Network Scan Detected",  "severity": "medium",
                     "source": "IDS",    "mitre": "T1046",
                     "desc": "Continued port scan from {src_ip} targeting {host}, focus on ports 80/443/8080."},
                    {"step": 3, "alert_type": "Web Application Attack",  "severity": "high",
                     "source": "WAF",    "mitre": "T1190",
                     "desc": "SQL injection attempt detected on {host} from {src_ip}."},
                    {"step": 4, "alert_type": "Web Shell Detected",     "severity": "critical",
                     "source": "EDR",    "mitre": "T1505.003",
                     "desc": "Web shell written to /var/www/html/upload/ on {host} from {src_ip}."},
                    {"step": 5, "alert_type": "Command Execution via Web Shell", "severity": "critical",
                     "source": "EDR",    "mitre": "T1059.004",
                     "desc": "Remote command executed via web shell on {host}; attacker IP: {src_ip}."},
                 ]),

        # ------------------------------------------------------------------
        # S-004: Phishing → macro → persistence on Finance workstation
        # ------------------------------------------------------------------
        Scenario("S-004", "Phishing Email to Macro Persistence",
                 "ASSET-011",
                 [
                    {"step": 1, "alert_type": "Suspicious Email Attachment", "severity": "medium",
                     "source": "Email",  "mitre": "T1566.001",
                     "desc": "Phishing email with malicious macro attachment received by {user} on {host}."},
                    {"step": 2, "alert_type": "Macro Execution",        "severity": "high",
                     "source": "EDR",    "mitre": "T1137.001",
                     "desc": "Office macro executed on {host} by {user} spawning cmd.exe."},
                    {"step": 3, "alert_type": "Scheduled Task Created",  "severity": "high",
                     "source": "EDR",    "mitre": "T1053.005",
                     "desc": "Persistence scheduled task 'WindowsUpdateHelper' created on {host}."},
                    {"step": 4, "alert_type": "C2 Beacon",              "severity": "critical",
                     "source": "NDR",    "mitre": "T1071.001",
                     "desc": "Periodic beacon to {dst_ip} ({ioc}) from {host} — C2 pattern (30s interval)."},
                 ]),

        # ------------------------------------------------------------------
        # S-005: Insider data exfiltration on HR workstation
        # ------------------------------------------------------------------
        Scenario("S-005", "Insider Threat Data Exfiltration",
                 "ASSET-018",
                 [
                    {"step": 1, "alert_type": "Abnormal Data Access",   "severity": "medium",
                     "source": "DLP",    "mitre": "T1213",
                     "desc": "User {user} accessed 340 HR records outside normal hours on {host}."},
                    {"step": 2, "alert_type": "Large File Transfer",    "severity": "high",
                     "source": "DLP",    "mitre": "T1048",
                     "desc": "User {user} uploaded 2.4GB archive to external cloud storage from {host}."},
                    {"step": 3, "alert_type": "USB Data Transfer",      "severity": "high",
                     "source": "EDR",    "mitre": "T1052.001",
                     "desc": "Large file copy to USB drive by {user} on {host}."},
                 ]),

        # ------------------------------------------------------------------
        # S-006: VPN brute-force → DC compromise (CRITICAL infra)
        # ------------------------------------------------------------------
        Scenario("S-006", "VPN Brute Force to Domain Controller Compromise",
                 "ASSET-001",
                 [
                    {"step": 1, "alert_type": "VPN Brute Force",        "severity": "high",
                     "source": "VPN",    "mitre": "T1110.001",
                     "desc": "Brute-force attempt on VPN from {src_ip}: 200+ auth failures in 5 minutes."},
                    {"step": 2, "alert_type": "VPN Login Success",      "severity": "high",
                     "source": "VPN",    "mitre": "T1078",
                     "desc": "VPN authentication succeeded for {user} after 200+ failures from {src_ip}."},
                    {"step": 3, "alert_type": "DCSync Attack",          "severity": "critical",
                     "source": "EDR",    "mitre": "T1003.006",
                     "desc": "DCSync replication request detected from non-DC host {host} by {user}."},
                    {"step": 4, "alert_type": "Golden Ticket Activity",  "severity": "critical",
                     "source": "SIEM",   "mitre": "T1558.001",
                     "desc": "Kerberos ticket anomaly detected on DC-CORP-01 — possible Golden Ticket."},
                    {"step": 5, "alert_type": "Ransomware Precursor",   "severity": "critical",
                     "source": "EDR",    "mitre": "T1486",
                     "desc": "Volume shadow copy deletion detected on {host} — ransomware precursor activity."},
                 ]),
    ]

# ---------------------------------------------------------------------------
# Row builder helpers
# ---------------------------------------------------------------------------

def benign_row(rng, idx, assets):
    asset = rng.choice(assets)
    asset_id, hostname, _, criticality, _, _ = asset
    tmpl = rng.choice(BENIGN_TEMPLATES + ADMIN_TEMPLATES)
    alert_type, sev, source, desc_tmpl, mitre = tmpl
    user = rng.choice(["alice.morgan","bob.chen","carol.west","dave.kumar",
                        "eve.sharma","frank.lee","grace.patel","henry.xu",
                        "it_support","sysadmin"])
    src_ip = rand_ip_internal(rng)
    domain = rng.choice(["microsoft.com","office365.com","updates.windows.com",
                         "teams.microsoft.com","sharepoint.com"])
    patch  = rng.randint(1000000, 9999999)
    svc    = rng.choice(["wuauserv","spooler","EventLog","Netlogon"])
    tool   = rng.choice(["psexec.exe","regedit.exe","mmc.exe","diskpart.exe"])
    sw     = rng.choice(["Adobe Reader 24","7-Zip 23","VLC 3.0","Notepad++ 8"])
    mb     = rng.randint(5, 500)

    desc = desc_tmpl.format(user=user, host=hostname, src_ip=src_ip,
                             domain=domain, patch=patch, svc=svc,
                             tool=tool, sw=sw, mb=mb)
    ts = rand_ts(rng, WINDOW_START, WINDOW_END)

    return {
        "alert_id":          alert_id(idx),
        "timestamp":         fmt_ts(ts),
        "source":            source,
        "alert_type":        alert_type,
        "severity":          sev,
        "source_ip":         src_ip,
        "destination_ip":    "",
        "user":              user,
        "host":              hostname,
        "asset_id":          asset_id,
        "asset_criticality": criticality,
        "ioc":               "",
        "description":       desc,
        "mitre_technique":   mitre or "",
        "scenario_id":       "",
        "is_benign":         "true",
    }


def scenario_row(rng, idx, scenario, step_def, base_ts):
    asset  = ASSET_MAP[scenario.asset_id]
    asset_id_, hostname, _, criticality, _, _ = asset

    user    = rng.choice(["alice.morgan","bob.chen","admin01","sysadmin",
                           "ceo","cfo","eve.sharma","carol.west"])
    src_ip  = rand_ip_external(rng) if step_def.get("step", 1) == 1 else rand_ip_internal(rng)
    dst_ip  = rand_ip_external(rng)
    lolbin  = rng.choice(LOLBINS)
    ioc_val = rng.choice(C2_DOMAINS) if "C2" in step_def["alert_type"] or "Beacon" in step_def["alert_type"] \
              or "Suspicious Network" in step_def["alert_type"] \
              or "Network Scan" in step_def["alert_type"] else ""

    desc = step_def["desc"].format(
        user=user, host=hostname, src_ip=src_ip,
        dst_ip=dst_ip, ioc=ioc_val or dst_ip,
        lolbin=lolbin,
    )

    # Timestamps within the scenario advance linearly
    jitter  = timedelta(minutes=rng.randint(1, 15) * step_def["step"])
    ts      = base_ts + jitter

    return {
        "alert_id":          alert_id(idx),
        "timestamp":         fmt_ts(ts),
        "source":            step_def["source"],
        "alert_type":        step_def["alert_type"],
        "severity":          step_def["severity"],
        "source_ip":         src_ip,
        "destination_ip":    dst_ip,
        "user":              user,
        "host":              hostname,
        "asset_id":          asset_id_,
        "asset_criticality": criticality,
        "ioc":               ioc_val,
        "description":       desc,
        "mitre_technique":   step_def["mitre"],
        "scenario_id":       scenario.scenario_id,
        "is_benign":         "false",
    }


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate(seed: int = SEED, total: int = TOTAL_ALERTS) -> list[dict]:
    rng = random.Random(seed)
    scenarios = build_scenarios()

    rows: list[dict] = []
    idx = 1

    # --- Scenario alert blocks -------------------------------------------
    # Each scenario repeats several times at different windows to create
    # realistic cluster density; we spread them throughout the 48-hour window.
    scenario_rows: list[dict] = []

    for scenario in scenarios:
        # Each scenario fires 3–5 times (independent incidents or retries)
        repetitions = rng.randint(3, 5)
        for _ in range(repetitions):
            base_ts = rand_ts(rng, WINDOW_START,
                              WINDOW_END - timedelta(hours=2))
            for step_def in scenario.chain:
                if idx > total:
                    break
                row = scenario_row(rng, idx, scenario, step_def, base_ts)
                scenario_rows.append(row)
                idx += 1

    # --- Fill remainder with benign / noise alerts -----------------------
    benign_rows: list[dict] = []
    while idx <= total:
        row = benign_row(rng, idx, ASSETS)
        benign_rows.append(row)
        idx += 1

    # Interleave benign and scenario alerts randomly (by timestamp shuffle)
    rows = scenario_rows + benign_rows
    rows.sort(key=lambda r: r["timestamp"])

    # Re-assign alert_ids in chronological order
    for i, row in enumerate(rows, start=1):
        row["alert_id"] = alert_id(i)

    return rows


def write_alerts(rows: list[dict], path: Path) -> None:
    fieldnames = [
        "alert_id", "timestamp", "source", "alert_type", "severity",
        "source_ip", "destination_ip", "user", "host", "asset_id",
        "asset_criticality", "ioc", "description", "mitre_technique",
        "scenario_id", "is_benign",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_assets(path: Path) -> None:
    fieldnames = ["asset_id", "hostname", "asset_type",
                  "criticality", "department", "owner"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for asset in ASSETS:
            writer.writerow(dict(zip(fieldnames, asset)))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Generating {TOTAL_ALERTS} synthetic SOC alerts (seed={SEED})...")
    rows = generate()
    write_alerts(rows, ALERTS_CSV)
    write_assets(ASSETS_CSV)

    # Verification summary
    scenario_count = sum(1 for r in rows if r["scenario_id"])
    benign_count   = sum(1 for r in rows if r["is_benign"] == "true")
    unique_scenarios = len({r["scenario_id"] for r in rows if r["scenario_id"]})

    print(f"  alerts written       : {len(rows)}")
    print(f"  scenario-linked      : {scenario_count}")
    print(f"  benign / noise       : {benign_count}")
    print(f"  unique scenarios     : {unique_scenarios}")
    print(f"  assets written       : {len(ASSETS)}")
    print(f"  output: {ALERTS_CSV}")
    print(f"  output: {ASSETS_CSV}")
    print("Done.")
