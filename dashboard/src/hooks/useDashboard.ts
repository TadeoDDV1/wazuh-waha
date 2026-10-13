import { useState, useCallback, useEffect } from 'react';
import { dashboardService } from '../services/api';
import type { StatusResponse, ConfigResponse, Component, RecentAlert } from '../types/dashboard';

export const useDashboard = () => {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<RecentAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // UI state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'healthy' | 'warning_error' | 'disabled'>('all');
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(10_000); // 10s default
  const [showSettings, setShowSettings] = useState<boolean>(false);
  const [showRecentAlerts, setShowRecentAlerts] = useState<boolean>(false);

  // Vistas principales: Dashboard SOC, Terminal de Tráfico (Alertas), Terminal de Red & Agentes, Reportes Forenses
  type ActiveView = 'dashboard' | 'traffic' | 'network_agents' | 'reports';
  const [activeView, setActiveView] = useState<ActiveView>('dashboard');

  const showTrafficTerminal = activeView === 'traffic';
  const setShowTrafficTerminal = useCallback((show: boolean) => {
    setActiveView(show ? 'traffic' : 'dashboard');
  }, []);

  const showNetworkTerminal = activeView === 'network_agents';
  const setShowNetworkTerminal = useCallback((show: boolean) => {
    setActiveView(show ? 'network_agents' : 'dashboard');
  }, []);

  // Fetch status, config and recent alerts
  const fetchData = useCallback(async (isBackground = false) => {
    if (!isBackground) setRefreshing(true);
    setError(null);
    try {
      const [statusResponse, configResponse, alertsResponse] = await Promise.all([
        dashboardService.getStatus(),
        dashboardService.getConfig().catch(() => null),
        dashboardService.getRecentAlerts().catch(() => []),
      ]);
      setStatus(statusResponse);
      if (configResponse) setConfig(configResponse);
      if (Array.isArray(alertsResponse)) setRecentAlerts(alertsResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al conectar con el relay');
      console.error('Failed to fetch dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Auto-refresh interval
  useEffect(() => {
    if (autoRefreshInterval <= 0) return;
    const interval = setInterval(() => {
      fetchData(true);
    }, autoRefreshInterval);
    return () => clearInterval(interval);
  }, [autoRefreshInterval, fetchData]);

  // Toggle a component
  const toggleComponent = useCallback(async (target: string, enabled: boolean) => {
    try {
      const result = await dashboardService.toggleComponent({ target, enabled });
      if (result.ok && status) {
        // Update the specific component's state optimistically
        setStatus({
          ...status,
          components: status.components.map((c: Component) =>
            c.id === target
              ? {
                  ...c,
                  current_state: enabled,
                  health: enabled ? (c.health === 'disabled' ? 'healthy' : c.health) : 'disabled',
                  detail: enabled ? 'activo (notificaciones habilitadas)' : 'silenciado (alertas filtradas)',
                }
              : c
          ),
        });
        // Refresh after a short delay so server-side state propagates
        setTimeout(() => { fetchData(true); }, 1200);
      }
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
      throw err;
    }
  }, [status, fetchData]);

  // Perform an action on a component
  const performAction = useCallback(async (target: string, action: string) => {
    try {
      const result = await dashboardService.performAction({ target, action });
      if (result.ok) {
        await fetchData(true);
      }
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al ejecutar acción');
      throw err;
    }
  }, [fetchData]);

  // Refresh data manually
  const refresh = useCallback(() => {
    fetchData(false);
  }, [fetchData]);

  return {
    status,
    config,
    recentAlerts,
    loading,
    refreshing,
    error,
    searchQuery,
    setSearchQuery,
    activeTab,
    setActiveTab,
    statusFilter,
    setStatusFilter,
    autoRefreshInterval,
    setAutoRefreshInterval,
    showSettings,
    setShowSettings,
    showRecentAlerts,
    setShowRecentAlerts,
    activeView,
    setActiveView,
    showTrafficTerminal,
    setShowTrafficTerminal,
    showNetworkTerminal,
    setShowNetworkTerminal,
    fetchData,
    toggleComponent,
    performAction,
    refresh,
  };
};

