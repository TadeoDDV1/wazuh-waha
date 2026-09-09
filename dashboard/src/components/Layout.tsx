import React from 'react';
import { DashboardProvider } from '../context/DashboardContext';
import Navbar from './Navbar';
import Dashboard from './Dashboard';
import RecentAlertsDrawer from './RecentAlertsDrawer';
import SettingsSection from './SettingsSection';
import { Toaster } from 'sonner';
import { useDashboardContext } from '../context/DashboardContext';
import './Layout.css';

const LayoutContent: React.FC = () => {
  const { showSettings } = useDashboardContext();
  return (
    <div className="app-layout">
      <Navbar />
      <main className="app-main">
        <Dashboard />
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

export const Layout: React.FC = () => {
  return (
    <DashboardProvider>
      <LayoutContent />
    </DashboardProvider>
  );
};

export default Layout;

