import React from 'react';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { DashboardProvider } from '../context/DashboardContext';
import Navbar from './Navbar';
import Dashboard from './Dashboard';
import RecentAlertsDrawer from './RecentAlertsDrawer';
import SettingsSection from './SettingsSection';
import LiveTrafficTerminal from './LiveTrafficTerminal';
import NetworkAgentsTerminal from './NetworkAgentsTerminal';
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
