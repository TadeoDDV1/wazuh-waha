import axios from 'axios';
import type { StatusResponse, ConfigResponse, ToggleAction, ActionRequest, ApiResponse } from '../types/dashboard';

const API_URL = import.meta.env.VITE_API_URL !== undefined
  ? import.meta.env.VITE_API_URL
  : (import.meta.env.DEV ? 'http://localhost:8765' : '');
const RELAY_API_KEY = import.meta.env.VITE_RELAY_API_KEY || '';

const api = axios.create({
  baseURL: `${API_URL}/api/v1/dashboard`,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  if (RELAY_API_KEY) {
    config.headers['X-Api-Key'] = RELAY_API_KEY;
  }
  return config;
});

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

  testEmail: async (): Promise<{ ok: boolean; detail: string }> => {
    const response = await api.post('/test-email');
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

  getWazuhVulnerabilities: async (): Promise<any> => {
    const response = await api.get('/wazuh/vulnerabilities');
    return response.data;
  },

  getWazuhFim: async (): Promise<any> => {
    const response = await api.get('/wazuh/fim');
    return response.data;
  },

  getWazuhSca: async (): Promise<any> => {
    const response = await api.get('/wazuh/sca');
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
        headers: RELAY_API_KEY ? { 'X-Api-Key': RELAY_API_KEY } : {},
      });
      return response.data || [];
    } catch {
      return [];
    }
  },
};
