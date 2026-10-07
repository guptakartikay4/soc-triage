export interface DashboardMetricsResponse {
  alerts_ingested: number;
  total_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  average_risk: number;
  triaged_count: number;
  average_mttt_seconds: number | null;
  median_mttt_seconds: number | null;
  mttt_baseline: string;
}

export interface IncidentSummaryResponse {
  incident_id: string;
  priority: string;
  risk_score: number;
  risk_explanation: string;
  start_time: string;
  end_time: string;
  alert_count: number;
  affected_assets: string[];
  asset_criticality: string[];
  users: string[];
  mitre_techniques: string[];
  correlation_evidence_summary: string;
  has_brief: boolean;
  analyst_action: string | null;
}

export interface AlertDetailItem {
  alert_id: string;
  timestamp: string;
  source: string;
  alert_type: string;
  severity: string;
  host: string | null;
  user: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  asset_id: string;
  asset_criticality: string;
  ioc: string | null;
  description: string;
  mitre_technique: string | null;
}

export interface CorrelationEdge {
  alert_a: string;
  alert_b: string;
  score: number;
  signals: string[];
  explanation: string;
}

export interface MITRETechniqueContext {
  technique_id: string;
  name: string;
  tactic: string;
  alert_ids: string[];
  reason: string;
  source: string;
  in_catalogue: boolean;
}

export interface IncidentMITREContext {
  techniques?: MITRETechniqueContext[] | null;
  tactics_roll_up?: string[] | null;
}

export interface IncidentBriefResponse {
  incident_id: string;
  summary: string;
  why_it_matters: string;
  key_evidence: string[];
  mitre_summary: string[];
  recommended_next_steps: string[];
  confidence: string;
  generation_source: string;
  is_fallback: boolean;
}

export interface AnalystActionRecord {
  incident_id: string;
  action: string;
  timestamp: string;
  note: string | null;
  triage_time_seconds: number | null;
}

export interface IncidentDetailResponse {
  incident_id: string;
  priority: string;
  risk_score: number;
  risk_explanation: string;
  severity_score: number;
  asset_criticality_score: number;
  correlation_strength_score: number;
  evidence_strength_score: number;
  attack_context_score: number;
  start_time: string;
  end_time: string;
  alert_count: number;
  alert_ids: string[];
  timeline: AlertDetailItem[];
  affected_assets: string[];
  asset_criticality: string[];
  users: string[];
  source_ips: string[];
  destination_ips: string[];
  iocs: string[];
  correlation_score: number;
  correlation_evidence?: CorrelationEdge[] | null;
  mitre_context?: IncidentMITREContext | null;
  brief?: IncidentBriefResponse | null;
  analyst_action?: AnalystActionRecord | null;
}

export interface TriageRunResponse {
  status: string;
  alerts_processed: number;
  incidents_created: number;
  timings: {
    ingest: number;
    correlate: number;
    risk_and_mitre: number;
    briefings: number;
  };
  total_seconds: number;
}
