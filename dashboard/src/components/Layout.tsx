import React from 'react';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { DashboardProvider } from '../context/DashboardContext';
import Navbar from './Navbar';
import Dashboard from './Dashboard';
import RecentAlertsDrawer from './RecentAlertsDrawer';
import SettingsSection from './SettingsSection';
import LiveTrafficTerminal from './LiveTrafficTerminal';
import NetworkAgentsTerminal from './NetworkAgentsTerminal';
import { ReportsCard } from './ReportsCard';
import { WazuhAgentsCard } from './WazuhAgentsCard';
import LoginScreen from './LoginScreen';
import { Toaster } from 'sonner';
import { useDashboardContext } from '../context/DashboardContext';
import { Loader2 } from 'lucide-react';
import './Layout.css';

const LayoutContent: React.FC = () => {
  const {
    showSettings,
    showTrafficTerminal,
    setShowTrafficTerminal,
    showNetworkTerminal,
    setShowNetworkTerminal,
    activeView,
  } = useDashboardContext();

  return (
    <div className="app-layout">
      <Navbar />
      <main className="app-main">
        {showNetworkTerminal ? (
          <NetworkAgentsTerminal
            isOpen
            onClose={() => setShowNetworkTerminal(false)}
            asPanel
          />
        ) : showTrafficTerminal ? (
          <LiveTrafficTerminal
            isOpen
            onClose={() => setShowTrafficTerminal(false)}
            asPanel
          />
        ) : activeView === 'reports' ? (
          <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '24px 24px 50px' }}>
            <div style={{ marginBottom: '20px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '24px' }}>📄</span> Generador de Reportes de Actividad Forense y Auditoría
              </h2>
              <p style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                Genera y descarga fichas forenses ejecutivas en PDF para cualquier agente registrado en el Wazuh Manager. Incluye telemetría de hardware, sistema operativo, sockets y puertos activos, evaluación de cumplimiento CIS (SCA), paquetes instalados e integridad de archivos (FIM).
              </p>
            </div>
            <ReportsCard />
          </div>
        ) : activeView === 'deploy' ? (
          <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '24px 24px 50px' }}>
            <div style={{ marginBottom: '20px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '24px' }}>⚡</span> Asistente y Generador de Comandos de Despliegue de Agentes
              </h2>
              <p style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                Genera de inmediato el comando de instalación para cualquier sistema operativo (Linux Ubuntu/Debian, Arch Linux, RHEL/CentOS, Windows o macOS). Al ejecutarlo en el endpoint, se conectará al Wazuh Manager y enviará telemetría de red.
              </p>
            </div>
            <WazuhAgentsCard initialWizardOpen={true} />
          </div>
        ) : (
          <Dashboard />
        )}
      </main>
      <RecentAlertsDrawer />
      {showSettings && <SettingsSection />}
      <Toaster
        theme="dark"
        position="bottom-right"
        richColors
        closeButton
      />
    </div>
  );
};

/**
 * Autenticación primero: hasta que no hay sesión no se monta
 * DashboardProvider (evita que dispare llamadas a la API con 401).
 */
const AuthGate: React.FC = () => {
  const { status } = useAuth();

  if (status === 'checking') {
    return (
      <div className="auth-loading">
        <Loader2 size={28} className="auth-loading-spin" />
        <span>Verificando sesión…</span>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return <LoginScreen />;
  }

  return (
    <DashboardProvider>
      <LayoutContent />
    </DashboardProvider>
  );
};

export const Layout: React.FC = () => {
  return (
    <AuthProvider>
      <AuthGate />
    </AuthProvider>
  );
};

export default Layout;
