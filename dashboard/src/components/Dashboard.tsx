import React from 'react';
import './Dashboard.css';
import { useDashboardContext } from '../context/DashboardContext';
import { WazuhServicesCard } from './WazuhServicesCard';
import { WazuhAgentsCard } from './WazuhAgentsCard';
import { WazuhModulesControlCard } from './WazuhModulesControlCard';
import { WhatsappCard } from './WhatsappCard';
import {
  Loader2,
  AlertCircle,
} from 'lucide-react';

export const Dashboard: React.FC = () => {
  const {
    status,
    loading,
    error,
    refresh,
  } = useDashboardContext();

  if (loading && !status) {
    return (
      <main className="dashboard-main">
        <div className="dashboard-state-card">
          <Loader2 size={36} className="animate-spin" style={{ color: 'var(--cyan-accent)' }} />
          <h3>Cargando Centro de Control Wazuh-WAHA...</h3>
          <p>Consultando estado de daemons, sesiones y módulos de seguridad.</p>
        </div>
      </main>
    );
  }

  if (error && !status) {
    return (
      <main className="dashboard-main">
        <div className="dashboard-state-card error">
          <AlertCircle size={36} style={{ color: 'var(--red-error)' }} />
          <h3>Error de Conexión con el Relay</h3>
          <p>{error}</p>
          <button className="reset-filter-btn" onClick={refresh}>
            Reintentar Conexión
          </button>
        </div>
      </main>
    );
  }

  const wahaComponent = status?.components?.find((c) => c.id === 'waha_session');

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '10px 0 40px' }}>
      {/* ── 1. Resumen de Conexión Wazuh ── */}
      <WazuhServicesCard />

      {/* ── 2. Agentes Conectados y Despliegue de Nuevos Agentes ── */}
      <WazuhAgentsCard />

      {/* ── 3. Módulos de Wazuh Integrados con Reglas y Datos en Vivo ── */}
      <WazuhModulesControlCard />

      {/* ── 3. Pasarela y Sesión de WhatsApp (WAHA) con Código QR ── */}
      {wahaComponent && (
        <div style={{ margin: '0 24px 30px' }}>
          <div style={{ marginBottom: '14px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>📱</span> Sesión y Gateway de WhatsApp (WAHA)
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              Inicia o detén la sesión de WhatsApp, o genera el código QR para vincular el dispositivo que enviará las alertas.
            </p>
          </div>
          <div style={{ maxWidth: '650px' }}>
            <WhatsappCard component={wahaComponent} />
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;

