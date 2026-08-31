import React from 'react';
import './RecentAlertsDrawer.css';
import { useDashboardContext } from '../context/DashboardContext';
import { Bell, X, ShieldAlert, Clock, User, CheckCircle2, AlertCircle } from 'lucide-react';

export const RecentAlertsDrawer: React.FC = () => {
  const { recentAlerts, showRecentAlerts, setShowRecentAlerts } = useDashboardContext();

  if (!showRecentAlerts) return null;

  const formatTs = (ts: number | string) => {
    if (!ts) return '';
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const getLevelBadge = (level: number) => {
    if (level >= 10) return <span className="alert-level-badge high">LVL {level}</span>;
    if (level >= 7) return <span className="alert-level-badge med">LVL {level}</span>;
    return <span className="alert-level-badge low">LVL {level}</span>;
  };

  return (
    <div className="recent-drawer-overlay" onClick={() => setShowRecentAlerts(false)}>
      <div className="recent-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div className="drawer-title-group">
            <Bell size={18} style={{ color: 'var(--cyan-accent)' }} />
            <h2 className="drawer-title">Alertas Recientes</h2>
            <span className="drawer-count-badge">{recentAlerts.length} recibidas</span>
          </div>
          <button
            className="drawer-close-btn"
            onClick={() => setShowRecentAlerts(false)}
            title="Cerrar panel de alertas"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {recentAlerts.length === 0 ? (
            <div className="empty-alerts-state">
              <ShieldAlert size={36} style={{ opacity: 0.4 }} />
              <p>No se han registrado alertas en este arranque del relay.</p>
            </div>
          ) : (
            recentAlerts.map((alert, idx) => (
              <div key={idx} className="alert-item-card">
                <div className="alert-card-top">
                  <div className="alert-rule-chip">
                    <span>Regla {alert.rule_id}</span>
                    {getLevelBadge(alert.level)}
                  </div>
                  <span className="alert-decision-badge">
                    {alert.result === 'sent' ? (
                      <CheckCircle2 size={12} style={{ color: 'var(--green-healthy)' }} />
                    ) : (
                      <AlertCircle size={12} style={{ color: 'var(--yellow-warning)' }} />
                    )}
                    <span>{alert.result || alert.decision || 'ok'}</span>
                  </span>
                </div>

                <div className="alert-card-desc">{alert.description}</div>

                <div className="alert-card-meta">
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    <Clock size={12} />
                    {formatTs(alert.ts)}
                  </span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    <User size={12} />
                    {alert.agent_name || 'Agente'} (ID: {alert.agent_id})
                  </span>
                  {alert.total_ms && <span>{alert.total_ms}ms</span>}
                </div>

                {alert.msg_preview && (
                  <div className="alert-card-preview">
                    {alert.msg_preview}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default RecentAlertsDrawer;
