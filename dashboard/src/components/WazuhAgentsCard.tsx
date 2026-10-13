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
  FileText,
  Network,
  Globe,
  Activity,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Radio,
} from 'lucide-react';
import { toast } from 'sonner';
import { copyToClipboard } from '../utils/clipboard';
import type { AgentTrafficDetails } from '../types/dashboard';

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
  traffic?: {
    total_sockets: number;
    established: number;
    interfaces_count: number;
    rx_mb: number;
    tx_mb: number;
  };
}

interface WazuhAgentsCardProps {
  initialWizardOpen?: boolean;
}

export const WazuhAgentsCard: React.FC<WazuhAgentsCardProps> = ({
  initialWizardOpen = true,
}) => {
  const { config, setActiveView } = useDashboardContext();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Deployment Wizard State
  const [showWizard, setShowWizard] = useState(initialWizardOpen);
  const [targetOs, setTargetOs] = useState('deb');
  const [agentName, setAgentName] = useState('');
  const [agentIp, setAgentIp] = useState('');
  const [managerIp, setManagerIp] = useState('192.168.122.142');
  const [copied, setCopied] = useState(false);
  const [isRegisteringApi, setIsRegisteringApi] = useState(false);
  const [registeredKey, setRegisteredKey] = useState<string | null>(null);
  const [downloadingReportId, setDownloadingReportId] = useState<string | null>(null);

  // Inline Traffic Inspection State
  const [expandedAgentId, setExpandedAgentId] = useState<string | null>(null);
  const [agentTraffic, setAgentTraffic] = useState<Record<string, AgentTrafficDetails>>({});
  const [loadingTrafficFor, setLoadingTrafficFor] = useState<string | null>(null);

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

  const toggleAgentTraffic = async (agentId: string) => {
    if (expandedAgentId === agentId) {
      setExpandedAgentId(null);
      return;
    }
    setExpandedAgentId(agentId);
    if (!agentTraffic[agentId]) {
      setLoadingTrafficFor(agentId);
      try {
        const details = await dashboardService.getAgentTrafficDetails(agentId);
        setAgentTraffic((prev) => ({ ...prev, [agentId]: details }));
      } catch (err) {
        console.error(`Error al cargar tráfico del agente ${agentId}:`, err);
        toast.error(`No se pudo cargar la telemetría de tráfico del agente ${agentId}`);
      } finally {
        setLoadingTrafficFor(null);
      }
    }
  };

  const getInstallCommand = () => {
    const ip = managerIp.trim() || '192.168.122.142';
    const nameStr = agentName.trim() ? `WAZUH_AGENT_NAME="${agentName.trim()}" ` : '';
    const agentIpStr = agentIp.trim() ? `WAZUH_AGENT_IP="${agentIp.trim()}" ` : '';

    switch (targetOs) {
      case 'deb':
        return `# 1. Descargar e instalar agente Wazuh v4.9 (Ubuntu / Debian / Kali / Linux Mint)
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'arch':
        return `# 1. Instalar agente en Arch Linux / Manjaro / EndeavourOS (AUR)
yay -S wazuh-agent --noconfirm || paru -S wazuh-agent --noconfirm
# 2. Registrar con el Wazuh Manager (${ip}) y arrancar servicio
sudo /var/ossec/bin/agent-auth -m "${ip}" ${agentName.trim() ? `-A "${agentName.trim()}"` : ''}
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'rpm':
        return `# 1. Importar claves e instalar agente Wazuh (RHEL / CentOS / Rocky Linux / Fedora)
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo WAZUH_MANAGER="${ip}" ${nameStr}${agentIpStr}yum install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent`;

      case 'windows':
        return `# Ejecutar en PowerShell como Administrador (Windows Server / Windows 10 / 11)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi -OutFile \${env:tmp}\\wazuh-agent.msi
msiexec.exe /i \${env:tmp}\\wazuh-agent.msi /q WAZUH_MANAGER="${ip}" WAZUH_REGISTRATION_SERVER="${ip}" ${nameStr}${agentIpStr}
NET START Wazuh`;

      case 'macos':
        return `# 1. Descargar e instalar paquete macOS (Intel y Apple Silicon)
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

  const handleDownloadReport = async (agentId: string, agentName: string) => {
    setDownloadingReportId(agentId);
    try {
      toast.info(`Generando reporte PDF para [${agentId}] ${agentName}...`);
      const blob = await dashboardService.getAgentReportBlob(agentId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const now = new Date();
      const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
      const safeName = agentName ? `_${agentName.replace(/[^a-zA-Z0-9_-]/g, '_')}` : '';
      a.download = `reporte_agente_${agentId}${safeName}_${ts}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Reporte PDF de ${agentName} [${agentId}] descargado exitosamente`);
    } catch (err: any) {
      console.error('Error descargando reporte:', err);
      toast.error(`Error al generar reporte PDF del agente ${agentId}`);
    } finally {
      setDownloadingReportId(null);
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
                <span>Agentes Wazuh Registrados & Telemetría de Red</span>
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
              <span>Monitorea el tráfico de tus endpoints conectados y genera comandos listos para instalar agentes en Linux, Windows o macOS.</span>
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
              background: showWizard ? 'var(--bg-card-hover)' : 'linear-gradient(135deg, #00e5ff, #3b82f6)',
              color: showWizard ? 'var(--text-primary)' : '#000',
              cursor: 'pointer',
              fontWeight: 700,
              fontSize: '12px',
              boxShadow: showWizard ? 'none' : '0 0 15px rgba(0, 229, 255, 0.35)',
              transition: 'all 0.2s ease',
            }}
          >
            {showWizard ? <XCircle size={14} /> : <PlusCircle size={14} />}
            <span>{showWizard ? 'Ocultar Generador' : '⚡ Generador de Comandos'}</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveView('network_agents')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(16, 185, 129, 0.15)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              borderRadius: '8px',
              padding: '7px 12px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
            title="Abrir Terminal de Red & Agentes completa"
          >
            <Network size={14} />
            <span>Terminal Red (LIVE)</span>
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

      {/* ── Generador de Comandos de Instalación (Asistente Prominente) ── */}
      {showWizard && (
        <div
          style={{
            marginBottom: '24px',
            padding: '22px',
            background: 'linear-gradient(180deg, rgba(13, 20, 36, 0.95), rgba(10, 15, 29, 0.98))',
            borderRadius: '12px',
            border: '1px solid rgba(0, 229, 255, 0.35)',
            boxShadow: '0 0 25px rgba(0, 229, 255, 0.12)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ background: 'rgba(0, 229, 255, 0.15)', padding: '6px', borderRadius: '8px' }}>
                <Terminal size={20} style={{ color: 'var(--cyan-accent)' }} />
              </div>
              <div>
                <h4 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--cyan-accent)' }}>
                  <span>Generador de Comandos para Nuevos Agentes Wazuh</span>
                </h4>
                <p style={{ margin: '2px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Selecciona el sistema operativo del endpoint, personaliza el nombre y copia el comando para pegarlo en la terminal del nuevo equipo.
                </p>
              </div>
            </div>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.06)', padding: '4px 10px', borderRadius: '6px' }}>
              <span>Wazuh v4.9 · Registro Automático en Puerto 1514</span>
            </span>
          </div>

          {/* OS Selector Tabs */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
            {[
              { id: 'deb', label: '🐧 Ubuntu / Debian', desc: 'apt / dpkg' },
              { id: 'arch', label: '🏔️ Arch Linux', desc: 'pacman / yay' },
              { id: 'rpm', label: '🎩 RHEL / CentOS / Rocky', desc: 'yum / dnf' },
              { id: 'windows', label: '🪟 Windows', desc: 'PowerShell Admin' },
              { id: 'macos', label: '🍎 macOS', desc: 'pkg / terminal' },
            ].map((os) => {
              const isSelected = targetOs === os.id;
              return (
                <button
                  key={os.id}
                  type="button"
                  onClick={() => setTargetOs(os.id)}
                  style={{
                    padding: '8px 14px',
                    borderRadius: '8px',
                    border: isSelected ? '1px solid var(--cyan-accent)' : '1px solid var(--border-subtle)',
                    background: isSelected ? 'rgba(0, 229, 255, 0.15)' : 'var(--bg-card)',
                    color: isSelected ? 'var(--cyan-accent)' : 'var(--text-secondary)',
                    fontWeight: isSelected ? 700 : 500,
                    fontSize: '12px',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    gap: '2px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <span>{os.label}</span>
                  <span style={{ fontSize: '10px', opacity: 0.7 }}>{os.desc}</span>
                </button>
              );
            })}
          </div>

          {/* Parameters Form Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>IP / Host del Wazuh Manager</span>
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
                  padding: '8px 10px',
                  fontSize: '12px',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>
                <span>Nombre del Agente (Opcional)</span>
              </label>
              <input
                type="text"
                placeholder="Ej. pc-oficina-01 o srv-db"
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '8px 10px',
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
                placeholder="Ej. any o 192.168.1.50"
                value={agentIp}
                onChange={(e) => setAgentIp(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '8px 10px',
                  fontSize: '12px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>

          {/* Quick Pre-register Button */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              <span>Consejo: Al ejecutar el comando generado en el nuevo equipo, el daemon se registrará automáticamente en el Manager.</span>
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
              <span>Pre-registrar Agente en Manager (Opcional)</span>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Terminal size={14} style={{ color: 'var(--cyan-accent)' }} />
                <span>Comando de Instalación (Copiar y pegar en el nuevo equipo):</span>
              </label>
              <button
                type="button"
                onClick={handleCopy}
                style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  padding: '6px 16px',
                  background: copied ? 'var(--green-healthy)' : 'var(--cyan-accent)',
                  color: '#000',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: '0 0 12px rgba(0, 229, 255, 0.4)',
                  transition: 'all 0.15s ease',
                }}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? '¡Comando Copiado!' : '📋 Copiar Comando de Instalación'}</span>
              </button>
            </div>
            <pre
              style={{
                margin: 0,
                padding: '16px',
                background: '#0a0d14',
                color: '#58a6ff',
                borderRadius: '8px',
                fontSize: '12px',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                fontFamily: 'monospace',
                border: '1px solid rgba(0, 229, 255, 0.25)',
                lineHeight: 1.6,
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
          <span>Consultando agentes y sockets de red en Wazuh Manager...</span>
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
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>📡 Tráfico de Red</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Estado</span></th>
                <th style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontWeight: 600, textAlign: 'right' }}><span>Acciones</span></th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const isActive = a.status === 'active';
                const osLabel = a.os?.name ? `${a.os.name} ${a.os.version || ''}`.trim() : (a.id === '000' ? 'Ubuntu (Manager)' : 'Linux / Unix');
                const isExpanded = expandedAgentId === a.id;
                const details = agentTraffic[a.id];
                const tr = a.traffic;

                return (
                  <React.Fragment key={a.id}>
                    <tr
                      style={{
                        borderBottom: isExpanded ? 'none' : '1px solid rgba(255,255,255,0.04)',
                        background: isExpanded ? 'rgba(0, 229, 255, 0.04)' : 'transparent',
                        transition: 'background 0.2s',
                      }}
                    >
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
                      <td style={{ padding: '10px 12px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span
                              style={{
                                fontSize: '11px',
                                fontWeight: 600,
                                padding: '2px 7px',
                                borderRadius: '4px',
                                background: tr && tr.total_sockets > 0 ? 'rgba(0, 229, 255, 0.12)' : 'rgba(255, 255, 255, 0.06)',
                                color: tr && tr.total_sockets > 0 ? 'var(--cyan-accent)' : 'var(--text-secondary)',
                                border: '1px solid rgba(0, 229, 255, 0.25)',
                              }}
                            >
                              📡 {tr ? `${tr.total_sockets} sockets` : 'Sockets activos'}
                            </span>
                            {tr && tr.established > 0 && (
                              <span
                                style={{
                                  fontSize: '11px',
                                  fontWeight: 600,
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  background: 'rgba(46, 204, 113, 0.12)',
                                  color: 'var(--green-healthy)',
                                }}
                              >
                                {tr.established} activas
                              </span>
                            )}
                          </div>
                          {tr && (tr.rx_mb > 0 || tr.tx_mb > 0) && (
                            <span style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                              ↓ {tr.rx_mb} MB · ↑ {tr.tx_mb} MB
                            </span>
                          )}
                        </div>
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
                        {/* Ver Tráfico en vivo / Inspeccionar */}
                        <button
                          type="button"
                          onClick={() => toggleAgentTraffic(a.id)}
                          style={{
                            background: isExpanded ? 'rgba(0, 229, 255, 0.25)' : 'rgba(0, 229, 255, 0.1)',
                            border: '1px solid rgba(0, 229, 255, 0.3)',
                            color: 'var(--cyan-accent)',
                            cursor: 'pointer',
                            padding: '4px 9px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            marginRight: '6px',
                            transition: 'all 0.15s',
                          }}
                          title="Inspeccionar sockets y sitios de red en vivo"
                        >
                          {loadingTrafficFor === a.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <Activity size={12} />
                          )}
                          <span>{isExpanded ? 'Ocultar' : '🔍 Tráfico'}</span>
                          {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                        </button>

                        {/* Terminal directa */}
                        <button
                          type="button"
                          onClick={() => setActiveView('network_agents')}
                          style={{
                            background: 'rgba(16, 185, 129, 0.1)',
                            border: '1px solid rgba(16, 185, 129, 0.3)',
                            color: '#34d399',
                            cursor: 'pointer',
                            padding: '4px 8px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            marginRight: '6px',
                          }}
                          title="Abrir este agente en la Terminal de Red interactiva"
                        >
                          <Network size={12} />
                          <span>Terminal</span>
                        </button>

                        {/* Reporte PDF */}
                        <button
                          type="button"
                          onClick={() => handleDownloadReport(a.id, a.name)}
                          disabled={downloadingReportId === a.id}
                          style={{
                            background: 'rgba(168, 85, 247, 0.15)',
                            border: '1px solid rgba(168, 85, 247, 0.35)',
                            color: '#c084fc',
                            cursor: downloadingReportId === a.id ? 'wait' : 'pointer',
                            padding: '4px 8px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            marginRight: '6px',
                            transition: 'all 0.2s',
                          }}
                          title={`Generar y descargar ficha forense PDF del agente ${a.id}`}
                        >
                          {downloadingReportId === a.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <FileText size={12} />
                          )}
                          <span>PDF</span>
                        </button>

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
                              verticalAlign: 'middle',
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

                    {/* Inline Drawer de Tráfico y Conexiones del Agente */}
                    {isExpanded && (
                      <tr style={{ background: 'rgba(13, 20, 36, 0.65)', borderBottom: '1px solid var(--border-subtle)' }}>
                        <td colSpan={7} style={{ padding: '16px 20px' }}>
                          {loadingTrafficFor === a.id ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--cyan-accent)', padding: '12px 0' }}>
                              <Loader2 size={16} className="animate-spin" />
                              <span>Cargando sockets activos y destinos de red del agente [{a.id}] {a.name}...</span>
                            </div>
                          ) : details ? (
                            <div>
                              {/* KPI Bar */}
                              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '14px', alignItems: 'center' }}>
                                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <Radio size={14} style={{ color: 'var(--green-healthy)' }} />
                                  <span>Tráfico en Vivo de [{a.id}] {a.name}:</span>
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--cyan-accent)', background: 'rgba(0, 229, 255, 0.1)', padding: '3px 8px', borderRadius: '4px' }}>
                                  Total Sockets: <strong>{details.kpis?.total_sockets ?? details.ports?.length ?? 0}</strong>
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--green-healthy)', background: 'rgba(46, 204, 113, 0.1)', padding: '3px 8px', borderRadius: '4px' }}>
                                  Conexiones Establecidas: <strong>{details.kpis?.established_connections ?? 0}</strong>
                                </div>
                                <div style={{ fontSize: '11px', color: '#c084fc', background: 'rgba(168, 85, 247, 0.1)', padding: '3px 8px', borderRadius: '4px' }}>
                                  Sitios & Destinos: <strong>{details.sites_activity?.length ?? 0}</strong>
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                  Ancho de Banda: <strong>{details.kpis?.total_rx_mb ?? 0} MB RX / {details.kpis?.total_tx_mb ?? 0} MB TX</strong>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => setActiveView('network_agents')}
                                  style={{
                                    marginLeft: 'auto',
                                    fontSize: '11px',
                                    fontWeight: 600,
                                    background: 'none',
                                    border: '1px solid rgba(0, 229, 255, 0.3)',
                                    color: 'var(--cyan-accent)',
                                    padding: '3px 8px',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                  }}
                                >
                                  <span>Ver en Terminal Completa</span>
                                  <ExternalLink size={11} />
                                </button>
                              </div>

                              {/* Active Sites / Destinations Chips */}
                              <div style={{ marginBottom: '12px' }}>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                                  Sitios Web y Destinos de Red Detectados:
                                </div>
                                {details.sites_activity && details.sites_activity.length > 0 ? (
                                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '8px' }}>
                                    {details.sites_activity.slice(0, 8).map((site, sIdx) => (
                                      <div
                                        key={sIdx}
                                        style={{
                                          background: 'rgba(0, 0, 0, 0.4)',
                                          border: '1px solid rgba(255, 255, 255, 0.08)',
                                          borderRadius: '6px',
                                          padding: '7px 10px',
                                          display: 'flex',
                                          alignItems: 'center',
                                          justifyContent: 'space-between',
                                          gap: '8px',
                                        }}
                                      >
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                                          <Globe size={13} style={{ color: site.is_web ? 'var(--cyan-accent)' : '#a855f7', flexShrink: 0 }} />
                                          <div style={{ overflow: 'hidden' }}>
                                            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                                              {site.site_name}
                                            </div>
                                            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                                              {site.remote_ip}:{site.remote_port} · {site.process || 'app'}
                                            </div>
                                          </div>
                                        </div>
                                        <span
                                          style={{
                                            fontSize: '9px',
                                            fontWeight: 700,
                                            padding: '2px 6px',
                                            borderRadius: '4px',
                                            background: site.state === 'recent' ? 'rgba(255, 255, 255, 0.08)' : 'rgba(46, 204, 113, 0.15)',
                                            color: site.state === 'recent' ? 'var(--text-secondary)' : 'var(--green-healthy)',
                                            flexShrink: 0,
                                          }}
                                        >
                                          {site.state_label || site.state}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                                    No hay conexiones web externas registradas en este momento.
                                  </div>
                                )}
                              </div>

                              {/* Sockets Preview */}
                              <div>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                                  Puertos y Sockets en Escucha / Activos:
                                </div>
                                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                  {(details.ports || [])
                                    .filter((p) => p.local_port > 0)
                                    .slice(0, 14)
                                    .map((p, pIdx) => (
                                      <span
                                        key={pIdx}
                                        style={{
                                          fontSize: '10px',
                                          fontFamily: 'monospace',
                                          background: 'rgba(255, 255, 255, 0.05)',
                                          border: '1px solid rgba(255, 255, 255, 0.08)',
                                          borderRadius: '4px',
                                          padding: '2px 7px',
                                          color: p.state === 'listening' ? '#fbbf24' : 'var(--cyan-accent)',
                                        }}
                                        title={`${p.protocol} ${p.local_ip}:${p.local_port} -> ${p.remote_ip}:${p.remote_port} (${p.process})`}
                                      >
                                        {p.protocol} :{p.local_port} ({p.process || 'sys'})
                                      </span>
                                    ))}
                                </div>
                              </div>
                            </div>
                          ) : (
                            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                              No hay datos de telemetría de red disponibles para este agente.
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
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
