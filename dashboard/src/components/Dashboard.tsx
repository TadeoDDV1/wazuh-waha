import React from 'react';
import './Dashboard.css';
import { useDashboardContext } from '../context/DashboardContext';
import { WazuhServicesCard } from './WazuhServicesCard';
import { WazuhAgentsCard } from './WazuhAgentsCard';
import { WazuhModulesControlCard } from './WazuhModulesControlCard';
import { WhatsappCard } from './WhatsappCard';
import { TelegramCard } from './TelegramCard';
import { NotificationChannelsCard } from './NotificationChannelsCard';
import { TelemetryGlobalCard } from './TelemetryGlobalCard';
import { ReportsCard } from './ReportsCard';
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
      {/* ── 0. Telemetría en Vivo — Tráfico del Pipeline ── */}
      <TelemetryGlobalCard />

      {/* ── 1. Resumen de Conexión Wazuh ── */}
      <WazuhServicesCard />

      {/* ── 2. Agentes Conectados y Despliegue de Nuevos Agentes ── */}
      <WazuhAgentsCard />

      {/* ── 3. Módulos de Wazuh Integrados con Reglas y Datos en Vivo ── */}
      <WazuhModulesControlCard />

      {/* ── 4. Selección de Canales de Notificación (WhatsApp, Telegram, Correo) ── */}
      <div style={{ margin: '0 24px 30px' }}>
        <NotificationChannelsCard />
      </div>

      {/* ── 5. Pasarelas de Mensajería: Vinculación WhatsApp y Telegram ── */}
      <div style={{ margin: '0 24px 30px' }}>
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>📡</span> Pasarelas de Mensajería y Vinculación de Dispositivos
          </h3>
          <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
            Vincula el código QR de WhatsApp (WAHA) o sincroniza el Bot de Telegram (@BotFather) para despachar alertas y recibir comandos del SOC.
          </p>
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
            gap: '20px',
            alignItems: 'start',
          }}
        >
          {wahaComponent && <WhatsappCard component={wahaComponent} />}
          <TelegramCard />
        </div>
      </div>

      {/* ── 6. Reportes de Actividad por Agente (PDF) ── */}
      <div style={{ margin: '0 24px 30px' }}>
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>📄</span> Reportes de Actividad y Auditoría
          </h3>
          <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
            Generá reportes PDF descargables con la ficha forense completa de cada agente Wazuh: hardware, sistema operativo, red, seguridad (SCA/FIM), software, procesos y detecciones.
          </p>
        </div>
        <ReportsCard />
      </div>
    </div>
  );
};

export default Dashboard;

