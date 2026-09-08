import React, { useState } from 'react';
import './ComponentCard.css';
import type { Component } from '../types/dashboard';
import { useDashboardContext } from '../context/DashboardContext';
import { toast } from 'sonner';
import { RotateCw, Play, Square, Loader2 } from 'lucide-react';
import { CATEGORY_LABELS } from '../utils/constants';

interface Props {
  component: Component;
}

export const ComponentCard: React.FC<Props> = ({ component }) => {
  const { toggleComponent, performAction } = useDashboardContext();
  const [isToggling, setIsToggling] = useState(false);
  const [isActing, setIsActing] = useState<string | null>(null);

  const health = component.health || 'unknown';
  const isActive = component.current_state ?? false;

  const handleToggle = async (enabled: boolean) => {
    setIsToggling(true);
    try {
      const result = await toggleComponent(component.id, enabled);
      if (result.ok) {
        toast.success(result.result || `${component.name}: ${enabled ? 'Activado' : 'Silenciado'}`);
      } else {
        toast.error(`Error: ${result.result || 'No se pudo cambiar el estado'}`);
      }
    } catch (error) {
      toast.error(`Fallo al alternar ${component.name}`);
    } finally {
      setIsToggling(false);
    }
  };

  const handleAction = async (action: string) => {
    setIsActing(action);
    try {
      const result = await performAction(component.id, action);
      if (result.ok) {
        toast.success(result.result || `Acción '${action}' ejecutada en ${component.name}`);
      } else {
        toast.error(`Error: ${result.result || 'Fallo en la acción'}`);
      }
    } catch (error) {
      toast.error(`Error al ejecutar '${action}' en ${component.name}`);
    } finally {
      setIsActing(null);
    }
  };

  const getActionIcon = (act: string) => {
    if (isActing === act) return <Loader2 size={13} className="animate-spin" />;
    if (act.includes('restart')) return <RotateCw size={13} />;
    if (act.includes('start')) return <Play size={13} />;
    if (act.includes('stop')) return <Square size={13} />;
    return null;
  };

  return (
    <div className={`component-card status-${health}`}>
      {/* Header */}
      <div className="card-header">
        <div className="card-title-group">
          <div className="card-icon-wrapper">
            <span>{component.icon || '🛡️'}</span>
          </div>
          <div className="card-name-block">
            <h3 className="card-name">{component.name}</h3>
            <span className="card-category-tag">
              {CATEGORY_LABELS[component.category] || component.category}
            </span>
          </div>
        </div>

        {/* Status Badge & Wazuh Mark */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '5px' }}>
          <div className={`status-badge-chip ${health}`}>
            <span className="status-dot" />
            <span>{health}</span>
          </div>
          {component.wazuh_status && (
            <span
              style={{
                fontSize: '10px',
                fontWeight: 600,
                padding: '2px 7px',
                borderRadius: '6px',
                backgroundColor: component.wazuh_connected ? 'rgba(46, 204, 113, 0.15)' : 'rgba(231, 76, 60, 0.15)',
                color: component.wazuh_connected ? 'var(--green-healthy)' : 'var(--red-error)',
                border: `1px solid ${component.wazuh_connected ? 'rgba(46, 204, 113, 0.3)' : 'rgba(231, 76, 60, 0.3)'}`,
                whiteSpace: 'nowrap',
              }}
            >
              {component.wazuh_connected ? '🟢 Wazuh: Levantado' : '🔴 Wazuh: Desconectado'}
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="card-body">
        <p className="card-description">{component.description}</p>
        {component.detail && (
          <div className="card-detail-pill" title={component.detail}>
            <span>{component.detail}</span>
          </div>
        )}
      </div>

      {/* Footer / Controls */}
      <div className="card-footer">
        {component.toggleable ? (
          <div className="toggle-block">
            <label className="cyber-switch" title={isActive ? 'Desactivar / Silenciar' : 'Activar'}>
              <input
                type="checkbox"
                checked={isActive}
                disabled={isToggling}
                onChange={(e) => handleToggle(e.target.checked)}
              />
              <span className="cyber-slider" />
            </label>
            <span className="toggle-label-text">
              {isToggling ? 'Guardando...' : isActive ? 'Activo' : 'Silenciado'}
            </span>
          </div>
        ) : (
          <div />
        )}

        {/* Actions */}
        {component.actions && component.actions.length > 0 && (
          <div className="card-actions">
            {component.actions.map((act) => (
              <button
                key={act}
                className="card-action-btn"
                disabled={isActing !== null || health === 'unknown'}
                onClick={() => handleAction(act)}
                title={`Ejecutar ${act}`}
              >
                {getActionIcon(act)}
                <span>{act}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ComponentCard;

