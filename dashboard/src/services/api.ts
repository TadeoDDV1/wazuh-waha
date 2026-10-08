import axios from 'axios';
import type { StatusResponse, ConfigResponse, ToggleAction, ActionRequest, ApiResponse, AgentTrafficDetails } from '../types/dashboard';
import { notifyAuthExpired } from './authService';

// Mismo origen SIEMPRE (nginx en prod, proxy de vite en dev): la cookie
// de sesión BFF solo fluye en same-origin y así no se necesita CORS en dev.
const API_URL = '';
// Sin API key en el bundle: la autenticación es por cookie de sesión (BFF).
// El interceptor avisa a la UI cuando el relay responde 401 (sesión expirada).

const api = axios.create({
  baseURL: `${API_URL}/api/v1/dashboard`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err?.response?.status === 401 && !err?.config?.url?.includes('/auth/')) {
      notifyAuthExpired();
    }
    return Promise.reject(err);
  },
);

export const dashboardService = {
  getLogs: async (lines = 100): Promise<{ok: boolean, logs: string}> => {
    const response = await api.get('/logs', { params: { lines } });
    return response.data;
  },

  getStatus: async (): Promise<StatusResponse> => {
    const response = await api.get<StatusResponse>('/status');
    return response.data;
  },

  getConfig: async (): Promise<ConfigResponse> => {
    const response = await api.get<ConfigResponse>('/config');
    return response.data;
  },

  toggleComponent: async (action: ToggleAction): Promise<ApiResponse> => {
    const response = await api.post<ApiResponse>('/toggle', action);
    return response.data || { ok: false, result: 'Unknown error' };
  },

  performAction: async (action: ActionRequest): Promise<ApiResponse> => {
    const response = await api.post<ApiResponse>('/action', action);
    return response.data || { ok: false, result: 'Unknown error' };
  },

  updateConfig: async (key: string, value: string): Promise<ApiResponse & { warnings?: string[] }> => {
    const response = await api.post('/config/update', { key, value });
    return response.data || { ok: false, result: 'Unknown error' };
  },

  updateConfigBatch: async (settings: Record<string, string>): Promise<ApiResponse & { updated_count?: number; updated_keys?: string[]; warnings?: string[] }> => {
    const response = await api.post('/config/batch', { settings });
    return response.data || { ok: false, result: 'Unknown error' };
  },

  testEmail: async (dest?: string): Promise<{ ok: boolean; detail: string }> => {
    const response = await api.post('/test-email', dest ? { dest } : {});
    return response.data || { ok: false, detail: 'Unknown error' };
  },

  testWhatsApp: async (): Promise<{ ok: boolean; detail: string }> => {
    const response = await api.post('/test-whatsapp');
    return response.data || { ok: false, detail: 'Unknown error' };
  },

  testWazuh: async (): Promise<{ ok: boolean; agent_port_ok: boolean; api_port_ok: boolean; detail: string }> => {
    const response = await api.post('/test-wazuh');
    return response.data || { ok: false, agent_port_ok: false, api_port_ok: false, detail: 'Unknown error' };
  },

  getWazuhAgents: async (): Promise<any> => {
    const response = await api.get('/wazuh/agents');
    return response.data;
  },

  addWazuhAgent: async (name: string, ip: string = 'any'): Promise<any> => {
    const response = await api.post('/wazuh/agents', { name, ip });
    return response.data;
  },

  deleteWazuhAgent: async (agentId: string): Promise<any> => {
    const response = await api.delete(`/wazuh/agents/${agentId}`);
    return response.data;
  },

  getWazuhVulnerabilities: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/vulnerabilities', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhFim: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/fim', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhSca: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/sca', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhMitre: async (): Promise<any> => {
    const response = await api.get('/wazuh/mitre');
    return response.data;
  },

  getWazuhOverview: async (): Promise<any> => {
    const response = await api.get('/wazuh/overview');
    return response.data;
  },

  getWazuhRootcheck: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/rootcheck', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhSyscollector: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/syscollector', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhRecommendations: async (agentId: string = '000'): Promise<any> => {
    const response = await api.get('/wazuh/recommendations', { params: { agent_id: agentId } });
    return response.data;
  },

  getWazuhModules: async (): Promise<any> => {
    const response = await api.get('/wazuh/modules');
    return response.data;
  },

  toggleWazuhModule: async (scope: string, module: string, enabled: boolean): Promise<any> => {
    const response = await api.post('/wazuh/modules/toggle', { scope, module, enabled });
    return response.data;
  },

  bulkToggleWazuhModules: async (scope: string, enabled: boolean): Promise<any> => {
    const response = await api.post('/wazuh/modules/bulk', { scope, enabled });
    return response.data;
  },

  applyWazuhModulesConfig: async (scope: string, modules: Record<string, boolean>): Promise<any> => {
    const response = await api.post('/wazuh/modules/apply', { scope, modules });
    return response.data;
  },

  wahaSessionAction: async (action: 'create' | 'start' | 'stop' | 'logout'): Promise<ApiResponse> => {
    const response = await api.post('/waha/session', { action });
    return response.data || { ok: false, result: 'Unknown error' };
  },

  getQrBlob: async (): Promise<Blob | null> => {
    const response = await api.get('/waha/qr', { responseType: 'blob' });
    if (response.status === 200) return response.data as Blob;
    return null;
  },

  getRecentAlerts: async () => {
    try {
      const response = await axios.get(`${API_URL}/debug/recent`, {
        withCredentials: true,
      });
      return response.data || [];
    } catch {
      return [];
    }
  },

  getTelegramStatus: async (): Promise<any> => {
    const response = await api.get('/telegram/status');
    return response.data;
  },

  pairTelegram: async (): Promise<any> => {
    const response = await api.post('/telegram/pair');
    return response.data;
  },

  testTelegram: async (): Promise<any> => {
    const response = await api.post('/telegram/test');
    return response.data;
  },

  updateNotificationChannels: async (channels: {
    whatsapp_enabled?: boolean;
    telegram_enabled?: boolean;
    email_alerts_enabled?: boolean;
  }): Promise<{ ok: boolean; channels: any }> => {
    const response = await api.post('/notifications/channels', channels);
    return response.data;
  },

  getNetworkSummary: async (): Promise<any> => {
    const response = await axios.get('/api/v1/telemetry/network/summary', { withCredentials: true });
    return response.data;
  },

  probeNetwork: async (): Promise<any> => {
    const response = await axios.post('/api/v1/telemetry/network/probe', {}, { withCredentials: true });
    return response.data;
  },

  getAgentTrafficDetails: async (agentId: string): Promise<AgentTrafficDetails> => {
    const response = await axios.get(`/api/v1/telemetry/agents/${agentId}/traffic`, { withCredentials: true });
    return response.data;
  },
};

export function buildNetworkStreamUrl(): string {
  return '/api/v1/telemetry/network/stream';
}

