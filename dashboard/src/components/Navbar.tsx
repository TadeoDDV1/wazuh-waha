import React from 'react';
import '../App.css';
import { useDashboardContext } from '../context/DashboardContext';
import {
  ShieldAlert,
  Activity,
  RefreshCw,
  Settings as SettingsIcon,
  Search,
  X,
  Bell,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  PowerOff,
  Server,
  Radio,
  Clock,
} from 'lucide-react';

function formatUptime(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export const Navbar: React.FC = () => {
  const {
    status,
    recentAlerts,
    refreshing,
    searchQuery,
    setSearchQuery,
    statusFilter,
    setStatusFilter,
    autoRefreshInterval,
    setAutoRefreshInterval,
    setShowSettings,
    setShowRecentAlerts,
    refresh,
  } = useDashboardContext();

  const components = status?.components || [];
  
  // Calculate counts
  const totalCount = components.length;
  const healthyCount = components.filter((c) => c.health === 'healthy').length;
  const warningCount = components.filter((c) => c.health === 'warning').length;
  const errorCount = components.filter((c) => c.health === 'error').length;
  const disabledCount = components.filter((c) => c.health === 'disabled').length;

  return (
    <header className="cyber-navbar">
      <div className="navbar-container">
        {/* Top bar: Brand + Host Info + Main Actions */}
        <div className="navbar-top">
          <div className="brand-section">
            <div className="brand-logo-badge">
              <ShieldAlert size={24} />
            </div>
            <div className="brand-titles">
              <div className="brand-title">
                WAZUH <span style={{ color: 'var(--cyan-accent)' }}>·</span> WAHA
                <span className="brand-badge">SOC Relay</span>
              </div>
              <div className="brand-subtitle">
                Centro de Control y Despacho de Seguridad
              </div>
            </div>
          </div>

          {/* System metadata chips */}
          {status && (
            <div className="system-meta-strip">
              <div className="meta-chip">
                <Server size={13} style={{ color: 'var(--cyan-accent)' }} />
                <span>Host:</span>
                <strong>{status.host}</strong>
              </div>
              <div className="meta-chip">
                <Radio size={13} style={{ color: 'var(--wazuh-blue)' }} />
                <span>IP:</span>
                <strong>{status.local_ip}</strong>
              </div>
              <div className="meta-chip">
                <Clock size={13} style={{ color: 'var(--green-healthy)' }} />
                <span>Uptime:</span>
                <strong>{formatUptime(status.uptime_sec)}</strong>
              </div>
            </div>
          )}

          {/* Actions & controls */}
          <div className="navbar-actions">
            {/* Auto refresh dropdown */}
            <select
              className="auto-refresh-select"
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              title="Intervalo de actualización automática"
            >
              <option value={0}>Auto-refresh: Off</option>
              <option value={5000}>Auto-refresh: 5s</option>
              <option value={10000}>Auto-refresh: 10s</option>
              <option value={30000}>Auto-refresh: 30s</option>
            </select>

            {/* Manual refresh */}
            <button
              className="nav-btn primary"
              onClick={refresh}
              disabled={refreshing}
              title="Refrescar datos ahora"
            >
              <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
              <span>{refreshing ? 'Actualizando...' : 'Refrescar'}</span>
            </button>

            {/* Recent alerts trigger */}
            <button
              className="nav-btn"
              onClick={() => setShowRecentAlerts(true)}
              title="Ver alertas recientes recibidas por el relay"
            >
              <Bell size={15} style={{ color: recentAlerts.length > 0 ? 'var(--cyan-accent)' : 'inherit' }} />
              <span>Alertas ({recentAlerts.length})</span>
            </button>

            {/* Settings button */}
            <button
              className="nav-btn"
              onClick={() => setShowSettings(true)}
              title="Configuración de variables y notificaciones"
            >
              <SettingsIcon size={15} />
              <span>Configuración</span>
            </button>
          </div>
        </div>

        {/* Bottom bar: Health summary pills + Search input */}
        <div className="navbar-bottom">
          <div className="health-summary-badges">
            <button
              className={`summary-pill all ${statusFilter === 'all' ? 'active' : ''}`}
              onClick={() => setStatusFilter('all')}
              title="Mostrar todos los componentes"
            >
              <Activity size={13} />
              <span>Total: {totalCount}</span>
            </button>

            <button
              className={`summary-pill healthy ${statusFilter === 'healthy' ? 'active' : ''}`}
              onClick={() => setStatusFilter(statusFilter === 'healthy' ? 'all' : 'healthy')}
              title="Filtrar componentes saludables"
            >
              <CheckCircle2 size={13} />
              <span>Operativos: {healthyCount}</span>
            </button>

            {warningCount > 0 && (
              <button
                className={`summary-pill warning ${statusFilter === 'warning_error' ? 'active' : ''}`}
                onClick={() => setStatusFilter(statusFilter === 'warning_error' ? 'all' : 'warning_error')}
                title="Filtrar advertencias"
              >
                <AlertTriangle size={13} />
                <span>Advertencias: {warningCount}</span>
              </button>
            )}

            {errorCount > 0 && (
              <button
                className={`summary-pill error ${statusFilter === 'warning_error' ? 'active' : ''}`}
                onClick={() => setStatusFilter(statusFilter === 'warning_error' ? 'all' : 'warning_error')}
                title="Filtrar errores"
              >
                <XCircle size={13} />
                <span>Errores: {errorCount}</span>
              </button>
            )}

            <button
              className={`summary-pill disabled ${statusFilter === 'disabled' ? 'active' : ''}`}
              onClick={() => setStatusFilter(statusFilter === 'disabled' ? 'all' : 'disabled')}
              title="Filtrar componentes o reglas silenciadas"
            >
              <PowerOff size={13} />
              <span>Silenciados: {disabledCount}</span>
            </button>
          </div>

          {/* Search bar */}
          <div className="search-box-wrapper">
            <Search size={15} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Buscar módulo, regla o servicio..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                className="search-clear-btn"
                onClick={() => setSearchQuery('')}
                title="Limpiar búsqueda"
              >
                <X size={14} />
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
