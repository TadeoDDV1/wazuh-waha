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
}

export interface CategoryLabel {
  [key: string]: string;
}

export interface StatusResponse {
  host: string;
  timestamp: string;
  uptime_sec: number;
  local_ip: string;
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
