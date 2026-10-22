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
  type: 'network_traffic' | 'network_event' | 'agent_heartbeat' | 'stream_tick' | 'connected' | 'site_activity';
  subtype?: string;
  site_name?: string;
  domain?: string;
  category?: string;
  category_label?: string;
  is_web?: boolean;
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
  process?: string;
  full_log?: string;
  os?: string;
  version?: string;
  msg?: string;
}

export interface AgentSocket {
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  process: string;
  pid?: number;
  state: string;
  tx_packets?: number;
  rx_packets?: number;
  remote_hostname?: string;
  site_name?: string;
  domain?: string;
  category?: string;
  category_label?: string;
  is_web?: boolean;
  icon?: string;
  agent_id?: string;
  agent_name?: string;
  agent_ip?: string;
}

export interface AgentSiteActivity {
  site_name: string;
  domain: string;
  remote_ip: string;
  remote_port: number;
  protocol: string;
  process: string;
  pid?: number;
  category: string;
  category_label: string;
  is_web: boolean;
  state: string;
  state_label: string;
  agent_id: string;
  agent_name: string;
  agent_ip?: string;
  last_seen: string;
}

export interface LanDeviceStatus {
  agent_id: string;
  agent_name: string;
  ip: string;
  status: string;
  os?: string;
  interface_name?: string;
  mac?: string;
  rx_mb?: number;
  tx_mb?: number;
  active_sites_count?: number;
  synced?: boolean;
}

export interface NetworkSitesSummary {
  ok: boolean;
  agent_id?: string;
  total_sites: number;
  web_sites_count: number;
  active_connections_count: number;
  sites: AgentSiteActivity[];
  by_category: Record<string, number>;
  lan_devices: LanDeviceStatus[];
  timestamp: number;
}

export interface AgentNetInterface {
  name: string;
  state: string;
  mac?: string;
  mtu?: number;
  type?: string;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  tx_errors?: number;
  rx_errors?: number;
  tx_drops?: number;
  rx_drops?: number;
  ipv4?: string;
  ipv4_addresses?: string[];
  ipv6?: string;
  ipv6_addresses?: string[];
  agent_id?: string;
  agent_name?: string;
}

export interface AgentProcess {
  pid: number;
  name: string;
  cmd?: string;
  euser?: string;
  state?: string;
  agent_id?: string;
}

export interface AgentWazuhDetection {
  id: string;
  timestamp: string;
  rule_id: string;
  level: number;
  level_es: string;
  description: string;
  agent_id: string;
  agent_name: string;
  srcip?: string;
  srcport?: string;
  dstuser?: string;
  full_log?: string;
  full_log_es?: string;
}

export interface AgentTrafficDetails {
  ok: boolean;
  agent_id: string;
  agent_info?: {
    id: string;
    name: string;
    ip: string;
    status: string;
    os?: any;
    version?: string;
    lastKeepAlive?: string;
  };
  kpis: {
    total_sockets: number;
    listening_sockets: number;
    established_connections: number;
    total_sites?: number;
    web_sites_active?: number;
    active_interfaces: number;
    total_rx_mb: number;
    total_tx_mb: number;
    total_wazuh_alerts: number;
  };
  ports: AgentSocket[];
  sites_activity?: AgentSiteActivity[];
  ifaces: AgentNetInterface[];
  processes: AgentProcess[];
  wazuh_detections: AgentWazuhDetection[];
  timestamp: number;
}

export interface AgentHardware {
  cpu_name: string;
  cpu_cores: number;
  cpu_mhz: number;
  ram_total_mb: number;
  ram_free_mb: number;
  ram_used_mb: number;
  ram_usage_percent: number;
  board_serial?: string;
}

export interface AgentOS {
  name: string;
  platform: string;
  version: string;
  kernel: string;
  architecture: string;
  hostname: string;
}

export interface AgentSCACheck {
  id: number | string;
  title: string;
  rationale?: string;
  remediation?: string;
}

export interface AgentSCA {
  name: string;
  policy_id: string;
  score: number;
  pass: number;
  fail: number;
  total_checks: number;
  failed_checks: AgentSCACheck[];
}

export interface AgentFIMFile {
  file: string;
  size?: number;
  perm?: string;
  uname?: string;
  date?: string;
  md5?: string;
}

export interface AgentFIM {
  total_monitored: number;
  recent_files: AgentFIMFile[];
}

export interface AgentPackage {
  name: string;
  version: string;
  vendor?: string;
  description?: string;
}

export interface AgentSoftware {
  total_packages: number;
  sample_packages: AgentPackage[];
}

export interface AgentFullProfile {
  ok: boolean;
  agent_id: string;
  name: string;
  ip: string;
  status: string;
  version: string;
  last_keep_alive: string;
  hardware: AgentHardware;
  os: AgentOS;
  network: {
    interfaces: AgentNetInterface[];
    total_rx_mb: number;
    total_tx_mb: number;
  };
  sca: AgentSCA;
  fim: AgentFIM;
  software: AgentSoftware;
  processes: {
    total_count: number;
    top_processes: AgentProcess[];
  };
  active_sites: AgentSiteActivity[];
  recent_detections: AgentWazuhDetection[];
  timestamp: number;
}



