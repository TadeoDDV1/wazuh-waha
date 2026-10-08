export interface Component {
  id: string;
  name: string;
  category: string;
  icon: string;
  description: string;
  status_type: string;
  toggleable: boolean;
  actions: string[];
  unit?: string;
  config_key?: string;
  rule_group?: string;
  current_state?: boolean | null;
  health?: 'healthy' | 'warning' | 'error' | 'disabled' | 'unknown';
  detail?: string;
  wazuh_connected?: boolean;
  wazuh_status?: string;
}

export interface WazuhOverview {
  connected: boolean;
  error?: string;
  manager_api: {
    connected: boolean;
    status: string;
    version?: string;
  };
  fim: {
    connected: boolean;
    status: string;
    monitored_files?: number;
  };
  sca: {
    connected: boolean;
    status: string;
    policies_count?: number;
    score?: number | null;
  };
  vuln: {
    connected: boolean;
    status: string;
  };
  mitre: {
    connected: boolean;
    status: string;
    tactics_count?: number;
    techniques_count?: number;
  };
}

export interface CategoryLabel {
  [key: string]: string;
}

export interface StatusResponse {
  host: string;
  timestamp: string;
  uptime_sec: number;
  local_ip: string;
  wazuh_services?: WazuhOverview;
  components: Component[];
}

export interface FormConfig {
  wazuh_server_ip: string;
  wazuh_server_ip_fallback?: string;
  auto_reconcile?: boolean;
  wazuh_manager_api_port?: number;
  wazuh_manager_api_user?: string;
  wazuh_manager_api_pass_set?: boolean;
  wazuh_manager_api_verify_tls?: boolean;
  admin_phone: string;
  whatsapp_enabled?: boolean;
  email_alerts_enabled?: boolean;
  waha_host?: string;
  waha_session?: string;
  waha_api_key_set?: boolean;
  waha_log_level?: string;
  waha_hook_url?: string;
  waha_recovery_cooldown_sec?: number;
  waha_recovery_max_wait_sec?: number;
  waha_watchdog_interval_sec?: number;
  email_provider: string;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_from: string;
  admin_email: string;
  smtp_tls: boolean;
  smtp_pass_set: boolean;
  hyvor_base_url: string;
  hyvor_from: string;
  hyvor_api_key_set: boolean;
  ollama_enabled?: boolean;
  ollama_host?: string;
  ollama_model?: string;
  ollama_timeout?: number;
  telegram_enabled?: boolean;
  telegram_bot_token_set?: boolean;
  telegram_chat_id?: string;
  telegram_min_level?: number;
  relay_port?: number;
  relay_dedup_ttl?: number;
  relay_min_level_unknown?: number;
  relay_workers?: number;
}

export interface ConfigResponse {
  env: Record<string, string>;
  settings: {
    relay_api_key_configured: boolean;
    email_provider: string;
    ollama_enabled: boolean;
    waha_host: string;
    waha_session: string;
    relay_workers: number;
    relay_port: number;
    relay_min_level_unknown: number;
    relay_dedup_ttl: number;
  };
  form: FormConfig;
  wazuh_rule_groups?: Record<string, boolean>;
}

export interface ToggleAction {
  target: string;
  enabled: boolean;
}

export interface ActionRequest {
  target: string;
  action: string;
}

export interface ApiResponse {
  ok: boolean;
  result: string;
  target?: string;
  enabled?: boolean;
  action?: string;
  note?: string;
  restart_recommended?: boolean;
}

export interface RecentAlert {
  ts: number;
  rule_id: string;
  level: number;
  agent_id: string;
  agent_name: string;
  description: string;
  alert_timestamp: string;
  worker_id?: string;
  decision?: string;
  result?: string;
  msg_len?: number;
  msg_preview?: string;
  waha_id?: string;
  total_ms?: number;
  error?: string;
}

export interface NetworkPortService {
  port: number;
  service: string;
  desc: string;
  open: boolean;
}

export interface NetworkSummary {
  ok: boolean;
  manager_host: string;
  total_agents: number;
  active_agents: number;
  agents: any[];
  services_ports: NetworkPortService[];
  timestamp: number;
}

export interface AgentNetworkEvent {
  type: 'network_traffic' | 'agent_heartbeat' | 'stream_tick' | 'connected';
  subtype?: string;
  id?: string;
  timestamp?: string;
  agent_id?: string;
  agent_name?: string;
  agent_ip?: string;
  src_ip?: string;
  src_port?: string;
  dst_ip?: string;
  dst_port?: string;
  protocol?: string;
  rule_id?: string;
  level?: number;
  description?: string;
  status?: string;
  bytes?: number;
  latency_ms?: number;
  rx_packets?: number;
  tx_packets?: number;
  connection_socket?: string;
  os?: string;
  version?: string;
  msg?: string;
}

