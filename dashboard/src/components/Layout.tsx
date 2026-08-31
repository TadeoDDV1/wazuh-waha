import React from 'react';
import { DashboardProvider } from '../context/DashboardContext';
import Navbar from './Navbar';
import Dashboard from './Dashboard';
import RecentAlertsDrawer from './RecentAlertsDrawer';
import SettingsSection from './SettingsSection';
import { Toaster } from 'sonner';
import './Layout.css';

const LayoutContent: React.FC = () => {
  return (
    <div className="app-layout">
      <Navbar />
      <main className="app-main">
        <Dashboard />
      </main>
      <RecentAlertsDrawer />
      <SettingsSection />
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

