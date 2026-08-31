import React, { useState, useEffect } from 'react';
import { dashboardService } from '../services/api';
import { useDashboardContext } from '../context/DashboardContext';
import './SettingsSection.css';

export const WazuhGroupsCard: React.FC = () => {
  const { config, loading, refresh } = useDashboardContext();
  const [groups, setGroups] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (config?.wazuh_rule_groups) {
      setGroups(config.wazuh_rule_groups as Record<string, boolean>);
    }
  }, [config]);

  const handleToggle = async (groupName: string, enabled: boolean) => {
    setGroups((prev) => ({ ...prev, [groupName]: enabled }));
    setSaving(true);
    try {
      await dashboardService.updateConfig(`rule_group:${groupName}`, enabled ? 'true' : 'false');
      await refresh();
    } catch (e) {
      console.error(e);
      setGroups((prev) => ({ ...prev, [groupName]: !enabled }));
    } finally {
      setSaving(false);
    }
  };

  const GROUP_LABELS: Record<string, string> = {
    authentication_success: '🔐 Autenticación y Logins',
    fim: '📁 Integridad de Archivos (FIM)',
    vulnerability_detector: '🛡️ Vulnerabilidades',
    network_threats: '🌐 Amenazas de Red',
    active_response: '⚡ Active Response',
    suid: '⚠️ Binarios SUID',
    sca: '📋 Configuración Segura (SCA)',
    rootcheck: '🕵️ Rootcheck',
    syscollector: '💻 Syscollector'
  };

  if (loading && !config) return <div>Cargando filtros...</div>;

  return (
    <div className="card" style={{ marginBottom: '20px', background: 'var(--bg-card)', border: '1px solid var(--border-card)' }}>
      <div className="card-header">
        <div className="card-title-row">
          <h3 style={{ color: 'var(--text-primary)' }}>Filtros de Alertas Wazuh</h3>
        </div>
      </div>
      <div className="card-content">
        <p style={{ marginBottom: '15px', color: 'var(--text-secondary)', fontSize: '14px' }}>
          Activa o desactiva las notificaciones de WhatsApp para los siguientes grupos de alertas. 
          Al desactivar un grupo, las alertas seguirán generándose en Wazuh, pero el relay las ignorará.
        </p>
        
        <div className="settings-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '15px' }}>
          {Object.entries(GROUP_LABELS).map(([key, label]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px', backgroundColor: 'var(--bg-card-hover)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>{label}</span>
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={groups[key] ?? true}
                  onChange={(e) => handleToggle(key, e.target.checked)}
                  disabled={saving}
                />
                <span className="slider"></span>
              </label>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
