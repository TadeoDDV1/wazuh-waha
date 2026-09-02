import React from 'react';
import './CategoryNav.css';
import { useDashboardContext } from '../context/DashboardContext';
import { CATEGORY_ORDER, CATEGORY_LABELS } from '../utils/constants';
import {
  Layers,
  ShieldAlert,
  FileCheck2,
  Bug,
  ClipboardList,
  MessageSquare,
  Activity,
  BellRing,
  Landmark,
} from 'lucide-react';

const TAB_ICONS: Record<string, React.ReactNode> = {
  all: <Layers size={16} />,
  sec_ops: <ShieldAlert size={16} />,
  integrity: <FileCheck2 size={16} />,
  threat_detection: <Bug size={16} />,
  auditing_policy: <ClipboardList size={16} />,
  whatsapp_gateway: <MessageSquare size={16} />,
  watchdogs: <Activity size={16} />,
  notifications: <BellRing size={16} />,
  compliance: <Landmark size={16} />,
};

export const CategoryNav: React.FC = () => {
  const { status, activeTab, setActiveTab } = useDashboardContext();
  const components = status?.components || [];

  // Component count by category
  const counts: Record<string, number> = {
    all: components.length,
  };
  components.forEach((c) => {
    counts[c.category] = (counts[c.category] || 0) + 1;
  });

  return (
    <nav className="category-nav-wrapper" aria-label="Categorías de seguridad">
      <div className="category-nav-container">
        {/* Tab 'Todos' */}
        <button
          className={`category-tab ${activeTab === 'all' ? 'active' : ''}`}
          onClick={() => setActiveTab('all')}
        >
          {TAB_ICONS.all}
          <span>Todos los Módulos</span>
          <span className="category-tab-badge">{counts.all || 0}</span>
        </button>

        {/* Wazuh categories in exact order */}
        {CATEGORY_ORDER.map((catKey) => {
          const count = counts[catKey] || 0;
          if (count === 0) return null;

          return (
            <button
              key={catKey}
              className={`category-tab ${activeTab === catKey ? 'active' : ''}`}
              onClick={() => setActiveTab(catKey)}
            >
              {TAB_ICONS[catKey] || <Layers size={16} />}
              <span>{CATEGORY_LABELS[catKey] || catKey}</span>
              <span className="category-tab-badge">{count}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
};

export default CategoryNav;
