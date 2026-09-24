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
}

export interface TrafficSourceInfo {
  mode: string;
  resolved: string;
  is_leader: boolean;
  journal: string;
  buffer_size: number;
  pid: number;
}

