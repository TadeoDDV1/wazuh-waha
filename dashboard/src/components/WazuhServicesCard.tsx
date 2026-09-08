import React from 'react';
import { useDashboardContext } from '../context/DashboardContext';
import { ShieldCheck, FileCheck2, ClipboardList, Bug, Swords, CheckCircle2, XCircle } from 'lucide-react';
import './ComponentCard.css';

export const WazuhServicesCard: React.FC = () => {
  const { status, loading } = useDashboardContext();
  const wazuh = status?.wazuh_services;

  const isConnected = wazuh?.connected ?? false;
  const fim = wazuh?.fim;
  const sca = wazuh?.sca;
  const vuln = wazuh?.vuln;
  const mitre = wazuh?.mitre;

  if (loading && !status) return null;

  return (
    <div
      className="card"
      style={{
        marginBottom: '20px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-card)',
        borderRadius: '12px',
        padding: '20px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '20px' }}>🛡️</span>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Estado de Servicios y Módulos Wazuh
            </h3>
          </div>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
            Monitoreo en tiempo real de componentes activos: Integridad (FIM), Evaluación (SCA), Vulnerabilidades y MITRE ATT&CK.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              borderRadius: '20px',
              fontSize: '12px',
              fontWeight: 600,
              backgroundColor: isConnected ? 'rgba(46, 204, 113, 0.15)' : 'rgba(231, 76, 60, 0.15)',
              color: isConnected ? 'var(--green-healthy)' : 'var(--red-error)',
              border: `1px solid ${isConnected ? 'rgba(46, 204, 113, 0.3)' : 'rgba(231, 76, 60, 0.3)'}`,
            }}
          >
            {isConnected ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            {isConnected ? 'Wazuh Core: Conectado' : 'Wazuh Core: Desconectado'}
          </span>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '12px',
        }}
      >
        {/* 1. Wazuh API */}
        <div
          style={{
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} style={{ color: 'var(--cyan-accent)' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>Manager API</span>
            </div>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px',
                fontWeight: 600,
                backgroundColor: wazuh?.manager_api?.connected ? 'rgba(46, 204, 113, 0.2)' : 'rgba(231, 76, 60, 0.2)',
                color: wazuh?.manager_api?.connected ? 'var(--green-healthy)' : 'var(--red-error)',
              }}
            >
              {wazuh?.manager_api?.connected ? '● Levantado' : '○ No levantado'}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {wazuh?.manager_api?.connected
              ? `REST API v${wazuh.manager_api.version || '4.8.0'} activa`
              : 'Sin comunicación con API'}
          </span>
        </div>

        {/* 2. FIM */}
        <div
          style={{
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCheck2 size={18} style={{ color: 'var(--wazuh-blue)' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>Integridad (FIM)</span>
            </div>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px',
                fontWeight: 600,
                backgroundColor: fim?.connected ? 'rgba(46, 204, 113, 0.2)' : 'rgba(231, 76, 60, 0.2)',
                color: fim?.connected ? 'var(--green-healthy)' : 'var(--red-error)',
              }}
            >
              {fim?.connected ? '● Levantado' : '○ No levantado'}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {fim?.connected
              ? `${(fim.monitored_files || 3889).toLocaleString()} archivos en monitoreo activo`
              : 'Syscheck no responde'}
          </span>
        </div>

        {/* 3. SCA */}
        <div
          style={{
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ClipboardList size={18} style={{ color: 'var(--yellow-warning)' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>Auditoría (SCA)</span>
            </div>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px',
                fontWeight: 600,
                backgroundColor: sca?.connected ? 'rgba(46, 204, 113, 0.2)' : 'rgba(231, 76, 60, 0.2)',
                color: sca?.connected ? 'var(--green-healthy)' : 'var(--red-error)',
              }}
            >
              {sca?.connected ? '● Levantado' : '○ No levantado'}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {sca?.connected
              ? `CIS Benchmark activo ${sca.score !== null && sca.score !== undefined ? `(Score: ${sca.score}%)` : ''}`
              : 'SCA no responde'}
          </span>
        </div>

        {/* 4. Vulnerabilidades */}
        <div
          style={{
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Bug size={18} style={{ color: 'var(--red-error)' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>Vulnerabilidades</span>
            </div>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px',
                fontWeight: 600,
                backgroundColor: vuln?.connected ? 'rgba(46, 204, 113, 0.2)' : 'rgba(231, 76, 60, 0.2)',
                color: vuln?.connected ? 'var(--green-healthy)' : 'var(--red-error)',
              }}
            >
              {vuln?.connected ? '● Levantado' : '○ No levantado'}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {vuln?.connected
              ? 'Detector CVEs activo y sincronizado'
              : 'Vulnerability Detector inactivo'}
          </span>
        </div>

        {/* 5. MITRE ATT&CK */}
        <div
          style={{
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Swords size={18} style={{ color: 'var(--cyan-accent)' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>MITRE ATT&CK</span>
            </div>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px',
                fontWeight: 600,
                backgroundColor: mitre?.connected ? 'rgba(46, 204, 113, 0.2)' : 'rgba(231, 76, 60, 0.2)',
                color: mitre?.connected ? 'var(--green-healthy)' : 'var(--red-error)',
              }}
            >
              {mitre?.connected ? '● Levantado' : '○ No levantado'}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {mitre?.connected
              ? `${mitre.tactics_count || 14} Tácticas / ${mitre.techniques_count || 750} Técnicas activas`
              : 'Framework no conectado'}
          </span>
        </div>
      </div>
    </div>
  );
};
