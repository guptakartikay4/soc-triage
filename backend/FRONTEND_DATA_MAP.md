# Frontend Data Map

This document maps the primary UI components to their respective backend API endpoints and JSON response fields. It ensures the frontend UI matches the exact state schema of the backend pipeline.

## 1. Dashboard (Top-Level Summary Cards)
**Endpoint**: `GET /api/metrics/overview`

| UI Metric | Endpoint Field |
| :--- | :--- |
| **Total Alerts Ingested** | `alerts_ingested` |
| **Total Incidents** | `total_incidents` |
| **P1 Incidents (Critical)** | `critical_incidents` |
| **P2 Incidents (High)** | `high_incidents` |
| **P3/P4 Incidents (Medium/Low)** | `medium_incidents` / `low_incidents` |
| **Average Risk Score** | `average_risk` |
| **Mean/Median MTTT** | `average_mttt_seconds` / `median_mttt_seconds` |
| **Triaged Incident Count**| `triaged_count` |

## 2. Incident Queue (List View)
**Endpoint**: `GET /api/incidents` (Array of `IncidentSummaryResponse`)

| UI Column/Field | Endpoint Field |
| :--- | :--- |
| **Incident ID** | `incident_id` |
| **Priority Level** | `priority` |
| **Risk Score** | `risk_score` |
| **Primary Assets** | `affected_assets` (Rendered as tags) |
| **Asset Criticality** | `asset_criticality` |
| **Alert Count** | `alert_count` |
| **Start/End Time** | `start_time` / `end_time` |
| **MITRE Tactics/Techniques**| `mitre_techniques` (Rendered as tags or icons) |
| **Analyst Status** | `analyst_action` (e.g. if `CONFIRM`, mark as Investigating) |
| **AI Brief Available** | `has_brief` (Boolean toggle for UI badging) |

## 3. Incident Detail (Investigation Panel)
**Endpoint**: `GET /api/incidents/{incident_id}` (`IncidentDetailResponse`)

| UI Section | Endpoint Field |
| :--- | :--- |
| **Incident Header** | `incident_id`, `priority`, `risk_score` |
| **Risk Contributions** | `severity_score`, `asset_criticality_score`, `evidence_strength_score`, `attack_context_score` |
| **Risk Explanation** | `risk_explanation` (Human-readable string) |
| **Alert Timeline (List)** | `timeline` (Array of `AlertDetailItem` showing `timestamp`, `source`, `alert_type`, `severity`, `description`) |
| **Correlation Evidence** | `correlation_evidence` (Array showing `score`, `signals`, and `explanation` linking alerts) |
| **MITRE Attack Chain** | `mitre_context.tactics_roll_up` and `mitre_context.techniques` |
| **Affected Entities** | `users`, `source_ips`, `destination_ips`, `affected_assets` |
| **AI Incident Briefing** | `brief` (Object containing `summary`, `why_it_matters`, `key_evidence`, `recommended_next_steps`) |
| **Briefing Metadata** | `brief.generation_source`, `brief.is_fallback`, `brief.confidence` |
| **Previous Analyst Action**| `analyst_action` (Object showing `action`, `note`, `timestamp`) |

## 4. Pipeline Metrics (Benchmark/Status)
**Endpoint**: `POST /api/triage/run`

| UI Metric | Endpoint Field |
| :--- | :--- |
| **Pipeline Runtime** | `total_seconds` |
| **Alert Reduction** | `alerts_processed` vs `incidents_created` |
| **Stage Timings** | `timings.ingest`, `timings.correlate`, `timings.risk_and_mitre`, `timings.briefings` |
