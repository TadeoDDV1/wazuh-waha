import React, { useState, useEffect } from 'react';
import { dashboardService } from '../services/api';
import { useDashboardContext } from '../context/DashboardContext';
import './SettingsSection.css';

interface Agent {
  id: string;
  name: string;
  ip: string;
  status: string;
  version: string;
}

export const WazuhAgentsCard: React.FC = () => {
  const { config } = useDashboardContext();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Deployment Wizard State
  const [showWizard, setShowWizard] = useState(false);
  const [targetOs, setTargetOs] = useState('deb');
  const [agentName, setAgentName] = useState('');
  const [agentIp, setAgentIp] = useState('');
  const [managerIp, setManagerIp] = useState('');
  const [copied, setCopied] = useState(false);

  // Initialize manager IP when config loads
  useEffect(() => {
    if (config?.form?.wazuh_server_ip && !managerIp) {
      setManagerIp(config.form.wazuh_server_ip);
    }
  }, [config, managerIp]);

  const fetchAgents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardService.getWazuhAgents();
      if (data.error) {
        setError(data.error);
      } else {
        setAgents(data.agents || []);
      }
    } catch (e: any) {
      setError(e.message || 'Failed to fetch agents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, []);

  const getInstallCommand = () => {
    const ip = managerIp || '192.168.1.72';
    const nameStr = agentName.trim() ? `WAZUH_AGENT_NAME="${agentName.trim()}" ` : '';
    const agentIpStr = agentIp.trim() ? `WAZUH_AGENT_IP="${agentIp.trim()}" ` : '';
    
    switch (targetOs) {
      case 'deb':
        return `curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb\nsudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}dpkg -i ./wazuh-agent.deb\nsudo systemctl daemon-reload\nsudo systemctl enable wazuh-agent\nsudo systemctl start wazuh-agent`;
      case 'rpm':
        return `sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}yum install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.8.0-1.x86_64.rpm\nsudo systemctl daemon-reload\nsudo systemctl enable wazuh-agent\nsudo systemctl start wazuh-agent`;
      case 'windows':
        return `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile \${env:tmp}\\wazuh-agent.msi\nmsiexec.exe /i \${env:tmp}\\wazuh-agent.msi /q WAZUH_MANAGER="${ip}" WAZUH_REGISTRATION_SERVER="${ip}" ${agentName.trim() ? `WAZUH_AGENT_NAME="${agentName.trim()}" ` : ''}${agentIp.trim() ? `WAZUH_AGENT_IP="${agentIp.trim()}" ` : ''}\nNET START Wazuh`;
      case 'macos':
        return `curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/mac/wazuh-agent-4.8.0-1.pkg\nsudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}installer -pkg wazuh-agent.pkg -target /\nsudo /Library/Ossec/bin/wazuh-control start`;
      default:
        return '';
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getInstallCommand());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="card" style={{ marginTop: '20px', background: 'var(--bg-card)', border: '1px solid var(--border-card)' }}>
      <div className="card-header">
        <div className="card-title-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <h3 style={{ color: 'var(--text-primary)' }}>🖥️ Agentes Wazuh Conectados</h3>
          <div>
            <button 
              onClick={() => setShowWizard(!showWizard)} 
              style={{ padding: '6px 12px', borderRadius: '4px', border: 'none', background: 'var(--wazuh-blue)', color: 'white', cursor: 'pointer', marginRight: '10px', fontWeight: '500' }}
            >
              {showWizard ? 'Cerrar Asistente' : '➕ Añadir Agente'}
            </button>
            <button 
              onClick={fetchAgents} 
              disabled={loading}
              style={{ padding: '6px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-card-hover)', color: 'var(--text-primary)', cursor: 'pointer' }}
            >
              {loading ? 'Cargando...' : 'Actualizar'}
            </button>
          </div>
        </div>
      </div>
      <div className="card-content">
        {showWizard && (
          <div style={{ marginBottom: '20px', padding: '20px', background: 'var(--bg-card-hover)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <h4 style={{ margin: '0 0 15px 0', color: 'var(--cyan-accent)' }}>Asistente de Despliegue de Agente</h4>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '15px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', marginBottom: '5px', color: 'var(--text-primary)' }}>Sistema Operativo Destino</label>
                <select 
                  className="field-input" 
                  value={targetOs} 
                  onChange={(e) => setTargetOs(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-card)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)' }}
                >
                  <option value="deb">Linux (Debian/Ubuntu/APT)</option>
                  <option value="rpm">Linux (CentOS/RHEL/YUM)</option>
                  <option value="windows">Windows (PowerShell)</option>
                  <option value="macos">macOS (Intel/Apple Silicon)</option>
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', marginBottom: '5px', color: 'var(--text-primary)' }}>Nombre del Agente (Opcional)</label>
                <input 
                  type="text" 
                  className="field-input" 
                  placeholder="Ej. Servidor-BD-01" 
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-card)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)' }}
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '20px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', marginBottom: '5px', color: 'var(--text-primary)' }}>IP del Wazuh Manager</label>
                <input 
                  type="text" 
                  className="field-input" 
                  placeholder="Ej. 192.168.1.72" 
                  value={managerIp}
                  onChange={(e) => setManagerIp(e.target.value)}
                  style={{ width: '100%', borderColor: 'var(--cyan-accent)', background: 'var(--bg-card)', color: 'var(--text-primary)' }}
                />
                <small style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>IP a la que se conectará el agente.</small>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', marginBottom: '5px', color: 'var(--text-primary)' }}>IP del Agente (Recomendado)</label>
                <input 
                  type="text" 
                  className="field-input" 
                  placeholder="Ej. 192.168.1.100" 
                  value={agentIp}
                  onChange={(e) => setAgentIp(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-card)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)' }}
                />
                <small style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>Fija la IP con la que se registrará el agente en el Manager.</small>
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '5px' }}>
                <label style={{ fontSize: '13px', fontWeight: 'bold', color: 'var(--text-primary)' }}>Comando de Instalación</label>
                <button 
                  onClick={handleCopy}
                  style={{ fontSize: '12px', padding: '4px 8px', background: copied ? 'var(--green-healthy)' : 'var(--bg-card)', color: copied ? 'white' : 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: '4px', cursor: 'pointer' }}
                >
                  {copied ? '¡Copiado!' : 'Copiar comando'}
                </button>
              </div>
              <pre style={{ margin: 0, padding: '15px', background: 'var(--bg-card)', color: 'var(--text-primary)', borderRadius: '6px', fontSize: '13px', overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border-subtle)' }}>
                {getInstallCommand()}
              </pre>
            </div>
          </div>
        )}

        {error ? (
          <div style={{ color: 'var(--red-error)', padding: '10px', background: 'var(--red-glow)', borderRadius: '4px' }}>
            {error}
          </div>
        ) : agents.length === 0 && !loading ? (
          <p style={{ color: 'var(--text-secondary)' }}>No se encontraron agentes conectados o no hay conexión con la API de Wazuh.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px', fontSize: '14px', color: 'var(--text-primary)' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '10px' }}>ID</th>
                  <th style={{ padding: '10px' }}>Nombre</th>
                  <th style={{ padding: '10px' }}>IP</th>
                  <th style={{ padding: '10px' }}>Versión</th>
                  <th style={{ padding: '10px' }}>Estado</th>
                </tr>
              </thead>
              <tbody>
                {agents.map(a => (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border-card)' }}>
                    <td style={{ padding: '10px' }}>{a.id}</td>
                    <td style={{ padding: '10px', fontWeight: '500', color: 'var(--cyan-accent)' }}>{a.name}</td>
                    <td style={{ padding: '10px', color: 'var(--text-secondary)' }}>{a.ip || '-'}</td>
                    <td style={{ padding: '10px', color: 'var(--text-secondary)' }}>{a.version}</td>
                    <td style={{ padding: '10px' }}>
                      <span style={{ 
                        padding: '3px 8px', 
                        borderRadius: '12px', 
                        fontSize: '12px',
                        background: a.status === 'active' ? 'var(--green-glow)' : 'var(--red-glow)',
                        color: a.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)',
                        border: `1px solid ${a.status === 'active' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                      }}>
                        {a.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
