# Frontend API Contract

This document provides a complete integration contract for the frontend to consume the backend SOC Alert Triage API. All endpoints are hosted under the root domain (e.g. `http://localhost:8000`).

## 1. Health
### `GET /api/health`
- **Description**: Verifies the API server is up and running.
- **Request Body**: None
- **Query Parameters**: None
- **Authentication**: None
- **Response Schema**: 
  ```json
  { "status": "ok" }
  ```

---

## 2. Metrics & Dashboard
### `GET /api/metrics/overview`
- **Description**: Top-level summary metrics for SOC dashboard cards.
- **Request Body**: None
- **Query Parameters**: None
- **Authentication**: None
- **Response Schema** (`DashboardMetricsResponse`):
  ```json
  {
    "alerts_ingested": 3000,
    "total_incidents": 2477,
    "critical_incidents": 150,
    "high_incidents": 450,
    "medium_incidents": 1000,
    "low_incidents": 877,
    "average_risk": 45.5,
    "triaged_count": 50,
    "average_mttt_seconds": 120.5,
    "median_mttt_seconds": 95.0,
    "mttt_baseline": "Baseline source description"
  }
  ```

---

## 3. Incident Queue
### `GET /api/incidents`
- **Description**: Retrieve a paginated list of triaged incidents.
- **Request Body**: None
- **Query Parameters**:
  - `priority` (string, optional): Filter by priority (e.g., "P1", "P2").
  - `limit` (integer, optional): Pagination limit (minimum 1).
  - `offset` (integer, optional): Pagination offset (default: 0).
- **Pagination Behavior**: Offset-based pagination.
- **Authentication**: None
- **Response Schema** (`list[IncidentSummaryResponse]`):
  ```json
  [
    {
      "incident_id": "INC-001",
      "priority": "P1",
      "risk_score": 85.5,
      "risk_explanation": "Severity +30.0 | Criticality +25.5 | Evidence +10.0 | MITRE +20.0",
      "start_time": "2026-09-25T00:07:29Z",
      "end_time": "2026-09-25T01:12:00Z",
      "alert_count": 5,
      "affected_assets": ["ASSET-014", "ASSET-020"],
      "asset_criticality": ["critical", "high"],
      "users": ["admin01", "cfo"],
      "mitre_techniques": ["T1059.001 - Execution", "T1110.004 - Credential Access"],
      "correlation_evidence_summary": "3 correlated pair(s) (host, user)",
      "has_brief": true,
      "analyst_action": "CONFIRM"
    }
  ]
  ```

---

## 4. Incident Detail
### `GET /api/incidents/{incident_id}`
- **Description**: Retrieve the full detail of a specific incident, including correlation context and alert timeline.
- **Request Body**: None
- **Query Parameters**: None
- **Authentication**: None
- **Error Response**: `404 Not Found` if `incident_id` does not exist.
- **Response Schema** (`IncidentDetailResponse`):
  ```json
  {
    "incident_id": "INC-001",
    "priority": "P1",
    "risk_score": 85.5,
    "risk_explanation": "Severity +30.0 | Criticality +25.5",
    "severity_score": 30.0,
    "asset_criticality_score": 25.5,
    "correlation_strength_score": 0.0,
    "evidence_strength_score": 10.0,
    "attack_context_score": 20.0,
    "start_time": "2026-09-25T00:07:29Z",
    "end_time": "2026-09-25T01:12:00Z",
    "alert_count": 2,
    "alert_ids": ["ALT-00001", "ALT-00002"],
    "timeline": [
      {
        "alert_id": "ALT-00001",
        "timestamp": "2026-09-25T00:07:29Z",
        "source": "EDR",
        "alert_type": "Failed Login",
        "severity": "medium",
        "host": "WS-EXEC-001",
        "user": "cfo",
        "source_ip": "203.5.29.238",
        "destination_ip": "192.225.253.213",
        "asset_id": "ASSET-020",
        "asset_criticality": "critical",
        "ioc": null,
        "description": "Multiple failed login attempts detected.",
        "mitre_technique": "T1110.004"
      }
    ],
    "affected_assets": ["ASSET-014", "ASSET-020"],
    "asset_criticality": ["critical", "high"],
    "users": ["admin01", "cfo"],
    "source_ips": ["203.5.29.238", "10.0.1.50"],
    "destination_ips": ["192.225.253.213"],
    "iocs": [],
    "correlation_score": 0.85,
    "correlation_evidence": [
      {
        "alert_a": "ALT-00001",
        "alert_b": "ALT-00002",
        "score": 0.85,
        "signals": ["user", "time"],
        "explanation": "Matched on heuristic"
      }
    ],
    "mitre_context": {
      "techniques": [
        {
          "technique_id": "T1110.004",
          "name": "Unknown",
          "tactic": "Credential Access",
          "alert_ids": [],
          "reason": "Mapped from alert",
          "source": "alert_field",
          "in_catalogue": true
        }
      ],
      "tactics_roll_up": ["Credential Access"]
    },
    "brief": {
      "incident_id": "INC-001",
      "summary": "AI summary of the attack...",
      "why_it_matters": "Attack vector details...",
      "key_evidence": ["Evidence 1", "Evidence 2"],
      "mitre_summary": [],
      "recommended_next_steps": ["Block IP", "Isolate Host"],
      "confidence": "Medium",
      "generation_source": "llama3-8b-8192",
      "is_fallback": false
    },
    "analyst_action": {
      "incident_id": "INC-001",
      "action": "CONFIRM",
      "timestamp": "2026-10-07T00:00:00Z",
      "note": "Analyst remarks",
      "triage_time_seconds": null
    }
  }
  ```

---

## 5. AI Incident Briefings
### `POST /api/incidents/{incident_id}/brief`
- **Description**: Force generation (or regeneration) of an AI Incident Brief using the LLM.
- **Request Body**: None
- **Query Parameters**: None
- **Authentication**: None
- **Error Response**: `404 Not Found` if `incident_id` does not exist.
- **Response Schema** (`IncidentBriefResponse`): Same as the `brief` property in the Incident Detail.

---

## 6. Analyst Decisions
### `POST /api/incidents/{incident_id}/action`
- **Description**: Record a manual human analyst decision for an incident (e.g. `investigate`, `escalate`, `dismiss`, `resolve`).
- **Request Body** (`AnalystActionRequest`):
  ```json
  {
    "action": "investigate",
    "note": "Looks suspicious, digging deeper.",
    "timestamp": "2026-10-07T00:00:00Z"
  }
  ```
- **Query Parameters**: None
- **Authentication**: None
- **Response Schema**:
  ```json
  {
    "status": "success",
    "action": "CONFIRM"
  }
  ```

*(Note: There is also `POST /api/analyst/decision?incident_id=...` which achieves the same outcome, but the URL path format above is canonical for the frontend)*

### `GET /api/analyst/incidents/{incident_id}/decisions`
- **Description**: Get the audit trail of all manual decisions on a specific incident.
- **Request Body**: None
- **Query Parameters**: None
- **Authentication**: None
- **Response Schema**:
  ```json
  [
    {
      "action": "CONFIRM",
      "note": "Looks suspicious",
      "timestamp": "2026-10-07T00:00:00Z"
    }
  ]
  ```

---

## 7. Raw Alerts
### `POST /api/alerts/ingest`
- **Description**: Batch ingest raw SOC alerts into the platform.
- **Request Body** (`IngestRequest`):
  ```json
  {
    "alerts": [
      { "alert_id": "ALT-00001", "timestamp": "...", "source": "EDR", ... }
    ]
  }
  ```
- **Response Schema** (`IngestResponse`):
  ```json
  {
    "total_received": 1,
    "accepted": 1,
    "rejected": 0,
    "validation_errors": []
  }
  ```

---

## 8. Triage Pipeline Runs
### `POST /api/triage/run`
- **Description**: Run the end-to-end backend pipeline (ingestion, correlation, risk, AI briefs).
- **Request Body** (`RunTriageRequest`):
  ```json
  {
    "source": "dataset",
    "reset": true
  }
  ```
- **Response Schema**:
  ```json
  {
    "status": "success",
    "alerts_processed": 3000,
    "incidents_created": 2477,
    "timings": {
      "ingest": 1.304,
      "correlate": 2.336,
      "risk_and_mitre": 6.643,
      "briefings": 2.749
    },
    "total_seconds": 13.231
  }
  ```
