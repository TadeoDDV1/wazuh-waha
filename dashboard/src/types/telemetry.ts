// Types para el payload de telemetría del relay

export interface TelemetryKPIs {
  total_received: number;
  total_sent: number;
  total_deduped: number;
  total_waha_errors: number;
  alerts_last_60s: number;
  lat_avg_ms: number | null;
  lat_p95_ms: number | null;
}

export interface TopRuleEntry {
  rule_id: string;
  count: number;
}

export interface TopAgentEntry {
  agent: string;
  count: number;
}

export interface TopModuleEntry {
  module_id: string;
  count: number;
}

export interface LiveAlertEntry {
  ts: number;                // unix timestamp float
  rule_id: string;
  level: number;
  agent_id: string;
  agent_name: string;
  description: string;
  decision: 'sent' | 'deduped' | 'format_error' | 'waha_error';
  module_id: string;
  alert_timestamp: string;
  latency_ms?: number;
  summary_es?: string;
  plain_severity?: string;
  remediation_action?: string;
}

/* ── Enriquecimiento determinista ───────────────────────────────────────── */

export interface EnrichmentAsset {
  agent_id: string;
  name: string;
  os?: string | null;
  ip?: string | null;
  criticality: 'low' | 'medium' | 'high' | 'critical';
  owner?: string | null;
  location?: string | null;
  tags: string[];
}

export interface EnrichmentNetwork {
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  service?: string | null;
  direction?: string | null;
  hostname?: string | null;
  asn?: string | null;
  country?: string | null;
  city?: string | null;
  site_category?: string | null;
  is_private?: boolean | null;
}

export interface EnrichmentRisk {
  technical_severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  plain_severity: string;
  business_impact: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  kill_chain_phase?: string | null;
  sla?: string | null;
}

export interface EnrichmentTranslation {
  description_es: string;
  full_log_es: string;
  summary_es?: string | null;
  method: 'catalog' | 'regex' | 'template' | 'raw';
  confidence: number;
}

export interface EnrichmentRemediation {
  order: number;
  action: string;
  why: string;
  command?: string | null;
  reference?: string | null;
  risk: 'low' | 'medium' | 'high';
}

export interface EnrichmentIoc {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'user' | 'process' | 'file';
  value: string;
  defanged?: string | null;
  confidence: number;
}

export interface Enrichment {
  asset?: EnrichmentAsset | null;
  network?: EnrichmentNetwork | null;
  risk: EnrichmentRisk;
  translations: EnrichmentTranslation;
  remediation: EnrichmentRemediation[];
  iocs: EnrichmentIoc[];
  sources: string[];
  confidence: number;
  elapsed_ms: number;
  degraded: boolean;
  errors: string[];
}

export interface TelemetrySnapshot {
  ts: number;                 // unix timestamp del snapshot
  uptime_sec: number;
  kpis: TelemetryKPIs;
  histogram: number[];        // 60 valores, 1 por segundo (rolling)
  alerts_live: LiveAlertEntry[];
  top_rules: TopRuleEntry[];
  top_agents: TopAgentEntry[];
  top_modules: TopModuleEntry[];
}

export interface TrafficEvent {
  id: string;
  timestamp: string;
  rule_id: string;
  level: number;
  description: string;
  agent_id: string;
  agent_name: string;
  src_ip?: string;
  src_port?: string;
  src_user?: string;
  dst_user?: string;
  command?: string;
  location?: string;
  mitre_ids?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  full_log?: string;
  groups?: string[];
  source?: string;
  raw_json?: Record<string, unknown> | null;
  enrichment?: Enrichment;
  schema_version?: string;
  catalog_version?: string;
}

export interface TrafficSourceInfo {
  mode: string;
  resolved: string;
  is_leader: boolean;
  journal: string;
  buffer_size: number;
  pid: number;
}

