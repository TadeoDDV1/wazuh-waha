import React, { useState, useEffect } from 'react';
import { dashboardService } from '../services/api';
import { useDashboardContext } from '../context/DashboardContext';
import {
  Server,
  PlusCircle,
  XCircle,
  RotateCw,
  Copy,
  Check,
  Terminal,
  ShieldCheck,
  Trash2,
  Monitor,
  Loader2,
} from 'lucide-react';
import { toast } from 'sonner';
import { copyToClipboard } from '../utils/clipboard';

interface Agent {
  id: string;
  name: string;
  ip?: string;
  status: string;
  version?: string;
  os?: {
    name?: string;
    version?: string;
    arch?: string;
  };
  dateAdd?: string;
  lastKeepAlive?: string;
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
  const [managerIp, setManagerIp] = useState('192.168.122.142');
  const [copied, setCopied] = useState(false);
  const [isRegisteringApi, setIsRegisteringApi] = useState(false);
  const [registeredKey, setRegisteredKey] = useState<string | null>(null);

  // Initialize manager IP when config loads
  useEffect(() => {
    if (config?.form?.wazuh_server_ip) {
      setManagerIp(config.form.wazuh_server_ip);
    } else if (typeof window !== 'undefined' && window.location.hostname && window.location.hostname !== 'localhost') {
      setManagerIp(window.location.hostname);
    }
  }, [config]);

  const fetchAgents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardService.getWazuhAgents();
      if (data?.error) {
        setError(data.error);
      } else {
        setAgents(data?.agents || []);
      }
    } catch (e: any) {
      setError(e.message || 'Error al consultar lista de agentes');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, []);

  const getInstallCommand = () => {
    const ip = managerIp.trim() || '192.168.122.142';
    const nameStr = agentName.trim() ? `WAZUH_AGENT_NAME="${agentName.trim()}" ` : '';
    const agentIpStr = agentIp.trim() ? `WAZUH_AGENT_IP="${agentIp.trim()}" ` : '';

    switch (targetOs) {
      case 'deb':
        return `# 1. Descargar e instalar agente Wazuh (Ubuntu/Debian)
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'arch':
        return `# 1. Instalar agente en Arch Linux (AUR / Pacman)
yay -S wazuh-agent --noconfirm || paru -S wazuh-agent --noconfirm
# 2. Registrar con el Manager y arrancar servicio
sudo /var/ossec/bin/agent-auth -m "${ip}" ${agentName.trim() ? `-A "${agentName.trim()}"` : ''}
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'rpm':
        return `# 1. Descargar e instalar agente Wazuh (RHEL/CentOS/Rocky/Fedora)
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}yum install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'windows':
        return `# Ejecutar en PowerShell como Administrador
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi -OutFile \${env:tmp}\\wazuh-agent.msi
msiexec.exe /i \${env:tmp}\\wazuh-agent.msi /q WAZUH_MANAGER="${ip}" WAZUH_REGISTRATION_SERVER="${ip}" ${nameStr}${agentIpStr}
NET START Wazuh`;

      case 'macos':
        return `# 1. Descargar e instalar paquete macOS
curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/mac/wazuh-agent-4.9.0-1.pkg
sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}installer -pkg wazuh-agent.pkg -target /
sudo /Library/Ossec/bin/wazuh-control start`;

      default:
        return '';
    }
  };

  const handleCopy = async () => {
    const text = getInstallCommand();
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      toast.success('Comando de instalación copiado al portapapeles');
      setTimeout(() => setCopied(false), 2500);
    } else {
      toast.error('No se pudo copiar el comando. Por favor selecciónalo manualmente.');
    }
  };

  const handleRegisterViaApi = async () => {
    if (!agentName.trim()) {
      toast.error('Ingresa un nombre para el nuevo agente');
      return;
    }
    setIsRegisteringApi(true);
    try {
      const res = await dashboardService.addWazuhAgent(agentName.trim(), agentIp.trim() || 'any');
      if (res && res.ok && res.agent) {
        setRegisteredKey(res.agent.key || res.agent.id || 'Registrado con éxito');
        toast.success(`Agente '${agentName}' registrado exitosamente en el Manager con ID ${res.agent.id}`);
        fetchAgents();
      } else {
        toast.error(res?.error || 'Error al registrar agente vía API');
      }
    } catch (err: any) {
      toast.error(err.message || 'Fallo de conexión al registrar agente');
    } finally {
      setIsRegisteringApi(false);
    }
  };

  const handleDeleteAgent = async (agentId: string, agentName: string) => {
    if (agentId === '000') {
      toast.error('No se puede eliminar el agente 000 (Wazuh Manager local)');
      return;
    }
    if (!window.confirm(`¿Estás seguro de eliminar el agente ${agentId} (${agentName}) de Wazuh?`)) {
      return;
    }
    try {
      const res = await dashboardService.deleteWazuhAgent(agentId);
      if (res && res.ok) {
        toast.success(`Agente ${agentId} eliminado exitosamente`);
        fetchAgents();
      } else {
        toast.error(res?.error || 'Error al eliminar agente');
      }
    } catch (err: any) {
      toast.error(err.message || 'Error eliminando agente');
    }
  };

  const activeAgentsCount = agents.filter((a) => a.status === 'active').length;

  return (
    <div
      className="notranslate"
      translate="no"
      style={{
        margin: '0 24px 28px',
        background: 'var(--bg-card)',
        borderRadius: '14px',
        border: '1px solid var(--border-subtle)',
        padding: '22px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
        position: 'relative',
        transition: 'all 0.3s ease',
      }}
    >
      {/* ── Header ── */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '16px',
          marginBottom: '20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              padding: '12px',
              borderRadius: '12px',
              background: 'rgba(52, 152, 219, 0.15)',
              color: 'var(--cyan-accent)',
              display: 'flex',
            }}
          >
            <Server size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                <span>Agentes Wazuh Registrados</span>
              </h2>
              <span
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  padding: '3px 10px',
                  borderRadius: '12px',
                  background: activeAgentsCount > 0 ? 'rgba(46, 204, 113, 0.15)' : 'rgba(231, 76, 60, 0.15)',
                  color: activeAgentsCount > 0 ? 'var(--green-healthy)' : 'var(--red-error)',
                  border: `1px solid ${activeAgentsCount > 0 ? 'rgba(46, 204, 113, 0.3)' : 'rgba(231, 76, 60, 0.3)'}`,
                }}
              >
                <span>{activeAgentsCount} de {agents.length} Activos</span>
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
              <span>Monitorea tus endpoints conectados y utiliza el asistente para desplegar nuevos agentes en Linux, Windows o macOS.</span>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => setShowWizard((prev) => !prev)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '8px',
              border: 'none',
              background: showWizard ? 'var(--bg-card-hover)' : 'var(--cyan-accent)',
              color: showWizard ? 'var(--text-primary)' : '#000',
              cursor: 'pointer',
              fontWeight: 700,
              fontSize: '12px',
              boxShadow: showWizard ? 'none' : '0 0 15px rgba(0, 229, 255, 0.35)',
              transition: 'all 0.2s ease',
            }}
          >
            {showWizard ? <XCircle size={14} /> : <PlusCircle size={14} />}
            <span>{showWizard ? 'Cerrar Asistente' : '➕ Añadir / Desplegar Agente'}</span>
          </button>

          <button
            type="button"
            onClick={fetchAgents}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'var(--bg-card-hover)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '7px 12px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <RotateCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Actualizar</span>
          </button>
        </div>
      </div>

      {/* ── Asistente de Despliegue de Agente ── */}
      {showWizard && (
        <div
          style={{
            marginBottom: '24px',
            padding: '20px',
            background: 'var(--bg-surface)',
            borderRadius: '12px',
            border: '1px solid rgba(0, 229, 255, 0.3)',
            boxShadow: '0 0 20px rgba(0, 229, 255, 0.1)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={18} style={{ color: 'var(--cyan-accent)' }} />
              <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--cyan-accent)' }}>
                <span>Asistente de Despliegue e Instalación de Agentes</span>
              </h4>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              <span>Wazuh Agent 4.9+ · Inscripción Automática</span>
            </span>
          </div>

          {/* Form Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>Sistema Operativo del Endpoint</span>
              </label>
              <select
                value={targetOs}
                onChange={(e) => setTargetOs(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '7px 10px',
                  fontSize: '12px',
                }}
              >
                <option value="deb">🐧 Linux (Debian / Ubuntu / Kali / Mint)</option>
                <option value="arch">🏔️ Linux (Arch Linux / Manjaro / EndeavourOS)</option>
                <option value="rpm">🎩 Linux (RHEL / CentOS / Rocky / Fedora)</option>
                <option value="windows">🪟 Windows (PowerShell Administrador)</option>
                <option value="macos">🍎 macOS (Intel / Apple Silicon)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>Nombre del Agente (Opcional)</span>
              </label>
              <input
                type="text"
                placeholder="Ej. server-produccion-02"
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '7px 10px',
                  fontSize: '12px',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>IP del Wazuh Manager</span>
              </label>
              <input
                type="text"
                placeholder="Ej. 192.168.122.142"
                value={managerIp}
                onChange={(e) => setManagerIp(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--cyan-accent)',
                  borderRadius: '6px',
                  padding: '7px 10px',
                  fontSize: '12px',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>IP Fija del Agente (Opcional)</span>
              </label>
              <input
                type="text"
                placeholder="Ej. any o 192.168.1.150"
                value={agentIp}
                onChange={(e) => setAgentIp(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '7px 10px',
                  fontSize: '12px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>

          {/* Quick Pre-register button */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              <span>Consejo: El agente se registrará automáticamente en el Manager al ejecutar el comando con <code>WAZUH_MANAGER="{managerIp}"</code>.</span>
            </span>

            <button
              type="button"
              onClick={handleRegisterViaApi}
              disabled={isRegisteringApi || !agentName.trim()}
              style={{
                background: 'rgba(52, 152, 219, 0.15)',
                color: 'var(--cyan-accent)',
                border: '1px solid rgba(52, 152, 219, 0.3)',
                borderRadius: '6px',
                padding: '5px 12px',
                fontSize: '11px',
                fontWeight: 600,
                cursor: agentName.trim() ? 'pointer' : 'not-allowed',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title="Registra previamente el nombre en el Manager vía API REST"
            >
              {isRegisteringApi ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
              <span>Pre-registrar Agente en Manager</span>
            </button>
          </div>

          {registeredKey && (
            <div style={{ background: 'rgba(46, 204, 113, 0.1)', border: '1px solid rgba(46, 204, 113, 0.3)', borderRadius: '6px', padding: '8px 12px', marginBottom: '12px', fontSize: '11px' }}>
              <span style={{ color: 'var(--green-healthy)', fontWeight: 600 }}>✓ Agente pre-registrado en Manager API. Clave generada: </span>
              <code style={{ color: 'var(--cyan-accent)', wordBreak: 'break-all' }}>{registeredKey}</code>
            </div>
          )}

          {/* Generated Command Box */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Terminal size={13} />
                <span>Comando de Instalación en una sola línea</span>
              </label>
              <button
                type="button"
                onClick={handleCopy}
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '5px 12px',
                  background: copied ? 'var(--green-healthy)' : 'var(--bg-card)',
                  color: copied ? '#000' : 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                <span>{copied ? '¡Copiado!' : 'Copiar comando'}</span>
              </button>
            </div>
            <pre
              style={{
                margin: 0,
                padding: '14px 16px',
                background: '#0d1117',
                color: '#58a6ff',
                borderRadius: '8px',
                fontSize: '12px',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                fontFamily: 'monospace',
                border: '1px solid rgba(255,255,255,0.08)',
                lineHeight: 1.5,
              }}
            >
              <span>{getInstallCommand()}</span>
            </pre>
          </div>
        </div>
      )}

      {/* ── Error Banner ── */}
      {error && (
        <div
          style={{
            color: 'var(--red-error)',
            padding: '12px 16px',
            background: 'rgba(231, 76, 60, 0.1)',
            borderRadius: '8px',
            border: '1px solid rgba(231, 76, 60, 0.3)',
            marginBottom: '16px',
            fontSize: '13px',
          }}
        >
          <span>{error}</span>
        </div>
      )}

      {/* ── Agents Table ── */}
      {loading && !agents.length ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '30px', gap: '10px', color: 'var(--text-secondary)' }}>
          <Loader2 size={20} className="animate-spin" />
          <span>Consultando agentes en Wazuh Manager API...</span>
        </div>
      ) : agents.length === 0 ? (
        <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '10px 0' }}>
          <span>No se encontraron agentes conectados o no hay conexión con la API de Wazuh.</span>
        </p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>ID</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Nombre</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>IP Endpoint</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Sistema Operativo</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Versión Agente</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Estado</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600, textAlign: 'right' }}><span>Acciones</span></th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const isActive = a.status === 'active';
                const osLabel = a.os?.name ? `${a.os.name} ${a.os.version || ''}`.trim() : (a.id === '000' ? 'Ubuntu (Manager)' : 'Linux / Unix');
                return (
                  <tr key={a.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '10px 12px' }}>
                      <code style={{ background: 'rgba(52, 152, 219, 0.12)', color: 'var(--cyan-accent)', padding: '2px 6px', borderRadius: '4px', fontWeight: 700, fontSize: '11px' }}>
                        <span>{a.id}</span>
                      </code>
                    </td>
                    <td style={{ padding: '10px 12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Monitor size={14} style={{ color: 'var(--cyan-accent)' }} />
                        <span>{a.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                      <span>{a.ip || 'any'}</span>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                      <span>{osLabel}</span>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                      <span>{a.version || 'Wazuh 4.9.0'}</span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '3px 10px',
                          borderRadius: '12px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: isActive ? 'rgba(46, 204, 113, 0.15)' : 'rgba(231, 76, 60, 0.15)',
                          color: isActive ? 'var(--green-healthy)' : 'var(--red-error)',
                          border: `1px solid ${isActive ? 'rgba(46, 204, 113, 0.3)' : 'rgba(231, 76, 60, 0.3)'}`,
                        }}
                      >
                        <span
                          style={{
                            width: '6px',
                            height: '6px',
                            borderRadius: '50%',
                            background: isActive ? 'var(--green-healthy)' : 'var(--red-error)',
                            display: 'inline-block',
                          }}
                        />
                        <span>{isActive ? 'Activo' : 'Desconectado'}</span>
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                      {a.id !== '000' && (
                        <button
                          type="button"
                          onClick={() => handleDeleteAgent(a.id, a.name)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--text-muted)',
                            cursor: 'pointer',
                            padding: '4px',
                            borderRadius: '4px',
                            transition: 'color 0.2s',
                          }}
                          title={`Eliminar agente ${a.id} del Manager`}
                          onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--red-error)')}
                          onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
                        >
                          <Trash2 size={15} />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default WazuhAgentsCard;
