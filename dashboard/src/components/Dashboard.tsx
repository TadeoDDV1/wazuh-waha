import React from 'react';
import './Dashboard.css';
import { useDashboardContext } from '../context/DashboardContext';
import ComponentCard from './ComponentCard';
import WhatsappCard from './WhatsappCard';
import { WazuhGroupsCard } from './WazuhGroupsCard';
import { WazuhAgentsCard } from './WazuhAgentsCard';
import { WazuhServicesCard } from './WazuhServicesCard';
import CategoryNav from './CategoryNav';
import type { Component } from '../types/dashboard';
import {
  CATEGORY_ORDER,
  CATEGORY_LABELS,
  CATEGORY_DESCRIPTIONS,
} from '../utils/constants';
import {
  ShieldAlert,
  Loader2,
  AlertCircle,
  SearchX,
  FileCheck2,
  Bug,
  ClipboardList,
  MessageSquare,
  Activity,
  BellRing,
  Layers,
  Landmark,
} from 'lucide-react';

const CATEGORY_ICONS_MAP: Record<string, React.ReactNode> = {
  sec_ops: <ShieldAlert size={18} style={{ color: 'var(--cyan-accent)' }} />,
  integrity: <FileCheck2 size={18} style={{ color: 'var(--wazuh-blue)' }} />,
  threat_detection: <Bug size={18} style={{ color: 'var(--red-error)' }} />,
  auditing_policy: <ClipboardList size={18} style={{ color: 'var(--yellow-warning)' }} />,
  whatsapp_gateway: <MessageSquare size={18} style={{ color: 'var(--green-healthy)' }} />,
  watchdogs: <Activity size={18} style={{ color: 'var(--cyan-accent)' }} />,
  notifications: <BellRing size={18} style={{ color: 'var(--wazuh-blue)' }} />,
  compliance: <Landmark size={18} style={{ color: 'var(--yellow-warning)' }} />,
};

export const Dashboard: React.FC = () => {
  const {
    status,
    loading,
    error,
    searchQuery,
    setSearchQuery,
    activeTab,
    statusFilter,
    setStatusFilter,
    refresh,
  } = useDashboardContext();

  if (loading && !status) {
    return (
      <main className="dashboard-main">
        <div className="dashboard-state-card">
          <Loader2 size={36} className="animate-spin" style={{ color: 'var(--cyan-accent)' }} />
          <h3>Cargando Centro de Control Wazuh-WAHA...</h3>
          <p>Consultando estado de daemons, sesiones y grupos de reglas.</p>
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

  const allComponents = status?.components || [];

  // Filter by search query
  const searchFiltered = allComponents.filter((c) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      (c.rule_group && c.rule_group.toLowerCase().includes(q)) ||
      (c.detail && c.detail.toLowerCase().includes(q)) ||
      (c.unit && c.unit.toLowerCase().includes(q)) ||
      (c.category && c.category.toLowerCase().includes(q))
    );
  });

  // Filter by status filter pill
  const statusFiltered = searchFiltered.filter((c) => {
    if (statusFilter === 'all') return true;
    if (statusFilter === 'healthy') return c.health === 'healthy';
    if (statusFilter === 'warning_error') return c.health === 'warning' || c.health === 'error';
    if (statusFilter === 'disabled') return c.health === 'disabled' || c.current_state === false;
    return true;
  });

  // Group by category
  const groupedComponents: Record<string, Component[]> = {};
  statusFiltered.forEach((c) => {
    if (!groupedComponents[c.category]) {
      groupedComponents[c.category] = [];
    }
    groupedComponents[c.category].push(c);
  });

  // Determine categories to render
  const categoriesToRender =
    activeTab === 'all'
      ? CATEGORY_ORDER.filter((cat) => groupedComponents[cat] && groupedComponents[cat].length > 0)
      : [activeTab].filter((cat) => groupedComponents[cat] && groupedComponents[cat].length > 0);

  // Total matching count
  const totalRendered = statusFiltered.length;

  return (
    <>
      <WazuhServicesCard />
      <WazuhGroupsCard />
      <WazuhAgentsCard />


      <CategoryNav />

      <main className="dashboard-main">
        {totalRendered === 0 ? (
          <div className="empty-filter-state">
            <SearchX size={40} style={{ opacity: 0.5 }} />
            <h3>No se encontraron componentes</h3>
            <p>
              {searchQuery
                ? `No hay módulos que coincidan con la búsqueda "${searchQuery}".`
                : 'No hay componentes con el filtro de estado seleccionado.'}
            </p>
            <button
              className="reset-filter-btn"
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
              }}
            >
              Restablecer Filtros
            </button>
          </div>
        ) : (
          categoriesToRender.map((catKey) => {
            const list = groupedComponents[catKey] || [];
            if (list.length === 0) return null;

            return (
              <section key={catKey} className="category-section" id={`sec-${catKey}`}>
                {/* Category Header */}
                <div className="category-header">
                  <div className="category-title-block">
                    <h2 className="category-title">
                      {CATEGORY_ICONS_MAP[catKey] || <Layers size={18} />}
                      <span>{CATEGORY_LABELS[catKey] || catKey}</span>
                    </h2>
                    {CATEGORY_DESCRIPTIONS[catKey] && (
                      <p className="category-desc">{CATEGORY_DESCRIPTIONS[catKey]}</p>
                    )}
                  </div>
                  <span className="category-count-badge">{list.length} módulos</span>
                </div>

                {/* Grid */}
                <div className="component-grid">
                  {list.map((component) =>
                    component.id === 'waha_session' ? (
                      <WhatsappCard key={component.id} component={component} />
                    ) : (
                      <ComponentCard key={component.id} component={component} />
                    )
                  )}
                </div>
              </section>
            );
          })
        )}
      </main>
    </>
  );
};

export default Dashboard;

