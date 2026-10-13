import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './LiveTrafficTerminal.css';
import { dashboardService, buildNetworkStreamUrl } from '../services/api';
import type {
  AgentNetworkEvent,
  NetworkSummary,
  AgentTrafficDetails,
  AgentSocket,
  AgentNetInterface,
  AgentWazuhDetection,
  AgentSiteActivity,
  NetworkSitesSummary,
  AgentFullProfile,
} from '../types/dashboard';
import {
  Network,
  Radio,
  Server,
  Play,
  Pause,
  Trash2,
  Copy,
  Check,
  Search,
  Maximize2,
  Minimize2,
  Loader2,
  Zap,
  X,
  Activity,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  Filter,
  CheckCircle2,
  Globe,
  Wifi,
  Laptop,
  Layers,
  MessageSquare,
  Database,
  Terminal as TerminalIcon,
  Video,
  Cpu,
  HardDrive,
  ShieldCheck,
  FileCheck,
  FileText,
  Package,
} from 'lucide-react';
import { toast } from 'sonner';

interface NetworkAgentsTerminalProps {
  isOpen?: boolean;
  onClose?: () => void;
  asPanel?: boolean;
}

const MAX_EVENTS = 600;

export const NetworkAgentsTerminal: React.FC<NetworkAgentsTerminalProps> = ({
  onClose,
  asPanel = true,
}) => {
  // Estado general
  const [events, setEvents] = useState<AgentNetworkEvent[]>([]);
  const [summary, setSummary] = useState<NetworkSummary | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('all');
  const [activeSubView, setActiveSubView] = useState<'sites' | 'live_stream' | 'sockets' | 'interfaces' | 'detections' | 'forensics'>('sites');

  // Ficha Forense y Auditoría profunda
  const [fullProfile, setFullProfile] = useState<AgentFullProfile | null>(null);
  const [loadingProfile, setLoadingProfile] = useState<boolean>(false);
  const [downloadingPdf, setDownloadingPdf] = useState<boolean>(false);
  const [profileTargetAgentId, setProfileTargetAgentId] = useState<string>('000');
  const [packageSearch, setPackageSearch] = useState<string>('');
  const [processSearch, setProcessSearch] = useState<string>('');

  // Telemetría detallada del agente seleccionado
  const [agentDetails, setAgentDetails] = useState<AgentTrafficDetails | null>(null);
  const [loadingDetails, setLoadingDetails] = useState<boolean>(false);

  // Inventario de sitios y actividad web
  const [sitesSummary, setSitesSummary] = useState<NetworkSitesSummary | null>(null);
  const [loadingSites, setLoadingSites] = useState<boolean>(false);
  const [siteCategoryFilter, setSiteCategoryFilter] = useState<string>('all');
  const [siteStateFilter, setSiteStateFilter] = useState<string>('all');
  const [siteSearchQuery, setSiteSearchQuery] = useState<string>('');

  // Estados de stream en vivo
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  const [probing, setProbando] = useState<boolean>(false);
  const [maximized, setMaximized] = useState<boolean>(false);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const terminalLogsRef = useRef<HTMLDivElement>(null);
  const sseRef = useRef<EventSource | null>(null);
  const pausedEventsRef = useRef<AgentNetworkEvent[]>([]);
  const isPausedRef = useRef<boolean>(false);

  const togglePause = useCallback(() => {
    setIsPaused((prev) => {
      const next = !prev;
      isPausedRef.current = next;
      if (!next && pausedEventsRef.current.length > 0) {
        // Al reanudar: volcar los eventos acumulados durante la pausa
        const buffered = pausedEventsRef.current;
        pausedEventsRef.current = [];
        setEvents((cur) => {
          const merged = [...buffered, ...cur];
          return merged.length > MAX_EVENTS ? merged.slice(0, MAX_EVENTS) : merged;
        });
      }
      return next;
    });
  }, []);

  // Helper para traducir errores HTTP a mensajes claros
  const describeError = (err: unknown, ctx: string): string => {
    const anyErr = err as { response?: { status?: number }; message?: string };
    const status = anyErr?.response?.status;
    if (status === 401) return `${ctx}: sesión expirada o no autorizada (401). Volvé a iniciar sesión.`;
    if (status === 403) return `${ctx}: permiso denegado (403). Se requiere sesión con permisos completos.`;
    if (status === 429) return `${ctx}: demasiadas solicitudes (429). Esperá unos segundos.`;
    if (status && status >= 500) return `${ctx}: error del servidor (${status}). Reintenta en unos segundos.`;
    if (anyErr?.message?.includes('Network Error')) return `${ctx}: sin conexión con el relay. Verificá que esté activo.`;
    return `${ctx}: ${anyErr?.message || 'error desconocido'}`;
  };

  // 1. Cargar resumen general de red y agentes
  const fetchSummary = useCallback(async () => {
    try {
      const data = await dashboardService.getNetworkSummary();
      setSummary(data);
      setFetchError((prev) => (prev?.startsWith('Resumen') ? null : prev));
    } catch (err) {
      console.error('Error fetching network summary:', err);
      setFetchError(describeError(err, 'Resumen de red'));
    }
  }, []);

  // 2. Cargar telemetría detallada del agente seleccionado
  const fetchAgentDetails = useCallback(async (agentId: string) => {
    setLoadingDetails(true);
    try {
      const details = await dashboardService.getAgentTrafficDetails(agentId);
      setAgentDetails(details);
      setFetchError((prev) => (prev?.startsWith('Telemetría') ? null : prev));
    } catch (err) {
      console.error(`Error fetching traffic details for agent ${agentId}:`, err);
      setFetchError(describeError(err, 'Telemetría del agente'));
    } finally {
      setLoadingDetails(false);
    }
  }, []);

  // 3. Cargar sitios web y destinos de red
  const fetchSites = useCallback(async (agentId: string) => {
    setLoadingSites(true);
    try {
      const data = await dashboardService.getNetworkSites(agentId);
      setSitesSummary(data);
      setFetchError((prev) => (prev?.startsWith('Sitios') ? null : prev));
    } catch (err) {
      console.error(`Error fetching sites for agent ${agentId}:`, err);
      setFetchError(describeError(err, 'Sitios de red'));
    } finally {
      setLoadingSites(false);
    }
  }, []);

  // 3b. Cargar ficha forense y telemetría profunda del agente
  const fetchFullProfile = useCallback(async (targetAgentId: string) => {
    setLoadingProfile(true);
    try {
      const data = await dashboardService.getAgentFullProfile(targetAgentId);
      setFullProfile(data);
    } catch (err) {
      console.error(`Error fetching full profile for agent ${targetAgentId}:`, err);
    } finally {
      setLoadingProfile(false);
    }
  }, []);

  const handleDownloadAgentPdf = async (agentId: string, agentName: string) => {
    setDownloadingPdf(true);
    try {
      toast.info(`Generando reporte forense PDF para agente [${agentId}] ${agentName}...`);
      const blob = await dashboardService.getAgentReportBlob(agentId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const now = new Date();
      const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
      a.download = `reporte_forense_agente_${agentId}_${ts}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Reporte forense del agente [${agentId}] descargado exitosamente`);
    } catch (err: any) {
      console.error('Error al descargar reporte forense:', err);
      toast.error(`Error al generar reporte PDF del agente ${agentId}`);
    } finally {
      setDownloadingPdf(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  useEffect(() => {
    if (selectedAgentId !== 'all') {
      setProfileTargetAgentId(selectedAgentId);
    }
  }, [selectedAgentId]);

  useEffect(() => {
    fetchAgentDetails(selectedAgentId);
    fetchSites(selectedAgentId);
    const target = selectedAgentId === 'all' ? profileTargetAgentId : selectedAgentId;
    fetchFullProfile(target);

    const interval = setInterval(() => {
      fetchAgentDetails(selectedAgentId);
      fetchSites(selectedAgentId);
      if (activeSubView === 'forensics') {
        const curTarget = selectedAgentId === 'all' ? profileTargetAgentId : selectedAgentId;
        fetchFullProfile(curTarget);
      }
    }, 12000);
    return () => clearInterval(interval);
  }, [selectedAgentId, profileTargetAgentId, activeSubView, fetchAgentDetails, fetchSites, fetchFullProfile]);

  // 4. Conexión al flujo SSE en tiempo real (con reconexión backoff)
  useEffect(() => {
    let closed = false;
    let failCount = 0;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (closed) return;
      const streamUrl = buildNetworkStreamUrl();
      const es = new EventSource(streamUrl, { withCredentials: true });
      sseRef.current = es;

      es.onopen = () => {
        failCount = 0;
        setConnected(true);
      };

      es.onerror = () => {
        setConnected(false);
        es.close();
        if (closed) return;
        failCount += 1;
        const base = Math.min(1000 * 2 ** Math.min(failCount, 5), 30000);
        const delay = base + Math.floor(Math.random() * 1000);
        retryTimer = setTimeout(connect, delay);
      };

      es.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload.type === 'connected') {
            setConnected(true);
            return;
          }

          if (
            payload.type === 'network_event' ||
            payload.type === 'agent_heartbeat' ||
            payload.type === 'site_activity'
          ) {
            const item: AgentNetworkEvent = payload.data;
            if (isPausedRef.current) {
              pausedEventsRef.current = [item, ...pausedEventsRef.current].slice(0, MAX_EVENTS);
              return;
            }
            setEvents((prev) => {
              const next = [item, ...prev];
              if (next.length > MAX_EVENTS) {
                return next.slice(0, MAX_EVENTS);
              }
              return next;
            });
          }
        } catch (err) {
          console.error('Error parseando evento SSE:', err);
        }
      };
    };

    connect();

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      sseRef.current?.close();
      sseRef.current = null;
    };
  }, []);

  // Manejo de autoscroll
  useEffect(() => {
    if (autoScroll && terminalLogsRef.current && activeSubView === 'live_stream') {
      terminalLogsRef.current.scrollTop = 0;
    }
  }, [events, autoScroll, activeSubView]);

  // Ejecutar prueba de ping/sonda
  const handleProbe = async () => {
    setProbando(true);
    try {
      await dashboardService.probeNetwork();
      await fetchSummary();
      await fetchAgentDetails(selectedAgentId);
      await fetchSites(selectedAgentId);
    } catch (err) {
      console.error('Error enviando sonda de red:', err);
    } finally {
      setProbando(false);
    }
  };

  // Filtrado de eventos del stream
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (selectedAgentId !== 'all' && evt.agent_id !== selectedAgentId) {
        return false;
      }
      if (typeFilter === 'traffic' && evt.type !== 'network_traffic') return false;
      if (typeFilter === 'heartbeat' && evt.type !== 'agent_heartbeat') return false;
      if (typeFilter === 'security' && !evt.rule_id) return false;
      if (typeFilter === 'site' && evt.type !== 'site_activity') return false;

      if (searchFilter.trim()) {
        const q = searchFilter.toLowerCase();
        const text = `
          ${evt.agent_name || ''} ${evt.src_ip || ''} ${evt.dst_ip || ''} 
          ${evt.description || ''} ${evt.rule_id || ''} ${evt.protocol || ''}
          ${evt.process || ''} ${evt.status || ''}
        `.toLowerCase();
        return text.includes(q);
      }
      return true;
    });
  }, [events, selectedAgentId, typeFilter, searchFilter]);

  // Lista de agentes para selector
  const agentsList = useMemo(() => {
    return summary?.agents || [];
  }, [summary]);

  const selectedAgentObj = useMemo(() => {
    if (selectedAgentId === 'all') return null;
    return agentsList.find((a) => a.id === selectedAgentId) || null;
  }, [agentsList, selectedAgentId]);

  // Sitios activos consolidados
  const activeSitesList = useMemo(() => {
    const list: AgentSiteActivity[] = sitesSummary?.sites || agentDetails?.sites_activity || [];
    return list.filter((s) => {
      if (selectedAgentId !== 'all' && s.agent_id !== selectedAgentId) {
        return false;
      }
      if (siteCategoryFilter !== 'all' && s.category !== siteCategoryFilter) {
        return false;
      }
      if (siteStateFilter === 'active') {
        const isAct = s.state.includes('estab') || s.state.includes('syn') || s.state_label.includes('ACTIVA');
        if (!isAct) return false;
      }
      if (siteSearchQuery.trim()) {
        const q = siteSearchQuery.toLowerCase();
        const text = `${s.site_name} ${s.domain} ${s.process} ${s.remote_ip} ${s.remote_port} ${s.agent_name} ${s.category_label}`.toLowerCase();
        return text.includes(q);
      }
      return true;
    });
  }, [sitesSummary, agentDetails, selectedAgentId, siteCategoryFilter, siteStateFilter, siteSearchQuery]);

  // Dispositivos LAN detectados
  const lanDevices = useMemo(() => {
    return sitesSummary?.lan_devices || [];
  }, [sitesSummary]);

  // Helper para íconos según categoría de sitio
  const renderSiteIcon = (category: string, isWeb: boolean, iconName?: string) => {
    if (iconName === 'video') {
      return <Video size={15} style={{ color: '#ef4444' }} />;
    }
    switch (category) {
      case 'web':
        return <Globe size={15} style={{ color: '#38bdf8' }} />;
      case 'messaging':
        return <MessageSquare size={15} style={{ color: '#34d399' }} />;
      case 'dns':
        return <Layers size={15} style={{ color: '#00e5ff' }} />;
      case 'sync':
        return <ShieldAlert size={15} style={{ color: '#f59e0b' }} />;
      case 'ssh':
        return <TerminalIcon size={15} style={{ color: '#a855f7' }} />;
      case 'database':
        return <Database size={15} style={{ color: '#fb923c' }} />;
      case 'lan':
        return <Wifi size={15} style={{ color: '#10b981' }} />;
      default:
        return isWeb ? <Globe size={15} style={{ color: '#38bdf8' }} /> : <Server size={15} style={{ color: '#94a3b8' }} />;
    }
  };

  return (
    <div className={asPanel ? 'traffic-terminal-panel-host' : 'traffic-terminal-overlay'}>
      <div className={`traffic-terminal-window ${asPanel ? 'as-panel' : ''} ${maximized ? 'maximized' : ''}`}>
        
        {/* ── BARRA SUPERIOR: Título, Estado y Controles ── */}
        <div className="terminal-titlebar" style={{ borderBottom: '1px solid rgba(0, 229, 255, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <div className="terminal-logo-badge" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
              <Network size={16} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff', letterSpacing: '0.3px' }}>
                  Monitoreo de Red, Sitios Web & Equipos Wazuh (LIVE)
                </span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '10px',
                    background: connected ? 'rgba(46, 204, 113, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: connected ? 'var(--green-healthy)' : 'var(--red-error)',
                    border: `1px solid ${connected ? 'rgba(46, 204, 113, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                  }}
                >
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: connected ? 'var(--green-healthy)' : 'var(--red-error)',
                    }}
                  />
                  {connected ? 'RED SOC ENLACE ACTIVO' : 'RECONECTANDO'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Inspección de sitios web visitados, procesos en red, sockets activos y equipos conectados a la misma red WiFi
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {/* Botón Refrescar */}
            <button
              type="button"
              className="action-pill-btn"
              onClick={() => {
                fetchSummary();
                fetchAgentDetails(selectedAgentId);
                fetchSites(selectedAgentId);
              }}
              disabled={loadingDetails || loadingSites}
              title="Refrescar sitios, datos y sockets del agente"
              style={{ background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-secondary)' }}
            >
              <RefreshCw size={12} className={loadingDetails || loadingSites ? 'animate-spin' : ''} />
              <span>Refrescar</span>
            </button>

            {/* Botón Sonda de Red */}
            <button
              type="button"
              className="action-pill-btn"
              onClick={handleProbe}
              disabled={probing}
              style={{
                background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.25), rgba(6, 182, 212, 0.25))',
                borderColor: '#10b981',
                color: '#34d399',
              }}
              title="Enviar paquete sonda para medir latencia RTT y verificar sockets"
            >
              {probing ? <Loader2 size={12} className="animate-spin" /> : <Zap size={12} />}
              <span>{probing ? 'Sondeando...' : '📡 Sondear / Ping'}</span>
            </button>

            {!asPanel && (
              <button
                type="button"
                className="icon-tool-btn"
                onClick={() => setMaximized(!maximized)}
                title={maximized ? 'Restaurar tamaño' : 'Maximizar'}
              >
                {maximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
              </button>
            )}

            {onClose && (
              <button
                type="button"
                className="icon-tool-btn"
                onClick={onClose}
                title="Cerrar Terminal"
              >
                <X size={14} />
              </button>
            )}
          </div>
        </div>

        {/* ── BANNER DE ERROR VISIBLE (antes: los fallos se tragaban en console.error) ── */}
        {fetchError && (
          <div
            style={{
              margin: '8px 16px 0',
              padding: '8px 14px',
              borderRadius: '8px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              color: '#f87171',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={14} />
              {fetchError}
            </span>
            <button
              type="button"
              onClick={() => {
                setFetchError(null);
                fetchSummary();
                fetchAgentDetails(selectedAgentId);
                fetchSites(selectedAgentId);
              }}
              style={{
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#f87171',
                borderRadius: '6px',
                padding: '3px 10px',
                fontSize: '11px',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Reintentar
            </button>
          </div>
        )}

        {/* ── SELECTOR SEPARADO DE AGENTES (PESTAÑAS) ── */}
        <div
          style={{
            background: '#090e18',
            padding: '8px 16px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            overflowX: 'auto',
          }}
        >
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Equipos:
          </span>

          {/* Opción Todos */}
          <button
            type="button"
            className={`terminal-agent-tab ${selectedAgentId === 'all' ? 'active' : ''}`}
            onClick={() => setSelectedAgentId('all')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: selectedAgentId === 'all' ? 700 : 500,
              background: selectedAgentId === 'all' ? 'rgba(0, 229, 255, 0.2)' : 'rgba(255, 255, 255, 0.04)',
              color: selectedAgentId === 'all' ? '#00e5ff' : 'var(--text-secondary)',
              border: selectedAgentId === 'all' ? '1px solid #00e5ff' : '1px solid rgba(255, 255, 255, 0.08)',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            <Server size={13} />
            <span>🌐 Toda la Red ({summary?.total_agents || 0} equipos)</span>
          </button>

          {/* Agentes individuales */}
          {agentsList.map((ag: any) => {
            const isSel = selectedAgentId === ag.id;
            const osName = ag.os?.name || (ag.id === '000' ? 'Ubuntu' : 'Linux');
            const isWifi = ag.id === '001' || (ag.ip && ag.ip.startsWith('192.168.122.1'));
            return (
              <button
                key={ag.id}
                type="button"
                className={`terminal-agent-tab ${isSel ? 'active' : ''}`}
                onClick={() => setSelectedAgentId(ag.id)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: isSel ? 700 : 500,
                  background: isSel ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.25), rgba(6, 182, 212, 0.25))' : 'rgba(255, 255, 255, 0.04)',
                  color: isSel ? '#34d399' : 'var(--text-secondary)',
                  border: isSel ? '1px solid #10b981' : '1px solid rgba(255, 255, 255, 0.08)',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: ag.status === 'active' ? 'var(--green-healthy)' : 'var(--yellow-warning)',
                  }}
                />
                {isWifi ? <Wifi size={12} style={{ color: '#38bdf8' }} /> : <Laptop size={12} />}
                <span>[{ag.id}] <strong>{ag.name}</strong></span>
                <span style={{ fontSize: '10px', opacity: 0.7 }}>
                  ({osName} · {isWifi ? 'WiFi' : 'LAN'} · {ag.ip || '127.0.0.1'})
                </span>
              </button>
            );
          })}
        </div>

        {/* ── KPI STRIP: MÉTRICAS Y RESUMEN DEL AGENTE ── */}
        <div
          style={{
            background: 'rgba(6, 11, 25, 0.95)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
            padding: '8px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <div className="terminal-meta-chip">
              <Globe size={12} style={{ color: '#38bdf8' }} />
              <span>Sitios Monitoreados:</span>
              <strong style={{ color: '#38bdf8' }}>{sitesSummary?.total_sites ?? agentDetails?.kpis?.total_sites ?? 0}</strong>
            </div>

            <div className="terminal-meta-chip">
              <CheckCircle2 size={12} style={{ color: 'var(--green-healthy)' }} />
              <span>Conexiones Web Activas:</span>
              <strong style={{ color: 'var(--green-healthy)' }}>
                {sitesSummary?.web_sites_count ?? agentDetails?.kpis?.web_sites_active ?? 0}
              </strong>
            </div>

            <div className="terminal-meta-chip">
              <Activity size={12} style={{ color: '#00e5ff' }} />
              <span>Sockets Totales:</span>
              <strong style={{ color: '#fff' }}>{agentDetails?.kpis?.total_sockets ?? '-'}</strong>
            </div>

            <div className="terminal-meta-chip">
              <Radio size={12} style={{ color: '#a855f7' }} />
              <span>En Escucha:</span>
              <strong style={{ color: '#c084fc' }}>{agentDetails?.kpis?.listening_sockets ?? '-'}</strong>
            </div>

            <div className="terminal-meta-chip">
              <Network size={12} style={{ color: '#10b981' }} />
              <span>Interfaces Netiface:</span>
              <strong style={{ color: '#34d399' }}>{agentDetails?.kpis?.active_interfaces ?? '-'} UP</strong>
            </div>

            <div className="terminal-meta-chip">
              <ShieldAlert size={12} style={{ color: 'var(--yellow-warning)' }} />
              <span>Detecciones Wazuh:</span>
              <strong style={{ color: 'var(--yellow-warning)' }}>{agentDetails?.kpis?.total_wazuh_alerts ?? 0} eventos</strong>
            </div>

            {agentDetails?.kpis && (
              <div className="terminal-meta-chip">
                <span>Tráfico:</span>
                <strong style={{ color: '#38bdf8' }}>
                  ↓ {agentDetails.kpis.total_rx_mb} MB · ↑ {agentDetails.kpis.total_tx_mb} MB
                </strong>
              </div>
            )}
          </div>

          {/* Sub-Tabs de visualización para ver qué hace el agente */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <button
              type="button"
              onClick={() => setActiveSubView('sites')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'sites' ? 700 : 500,
                background: activeSubView === 'sites' ? 'linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(16, 185, 129, 0.25))' : 'transparent',
                color: activeSubView === 'sites' ? '#38bdf8' : 'var(--text-secondary)',
                border: activeSubView === 'sites' ? '1px solid #38bdf8' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🌐 Sitios Web & Destinos ({activeSitesList.length})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('live_stream')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'live_stream' ? 700 : 500,
                background: activeSubView === 'live_stream' ? 'rgba(0, 229, 255, 0.2)' : 'transparent',
                color: activeSubView === 'live_stream' ? '#00e5ff' : 'var(--text-secondary)',
                border: activeSubView === 'live_stream' ? '1px solid #00e5ff' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🖥️ Consola en Vivo
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('sockets')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'sockets' ? 700 : 500,
                background: activeSubView === 'sockets' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                color: activeSubView === 'sockets' ? '#34d399' : 'var(--text-secondary)',
                border: activeSubView === 'sockets' ? '1px solid #10b981' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🔌 Sockets ({agentDetails?.ports?.length || 0})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('interfaces')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'interfaces' ? 700 : 500,
                background: activeSubView === 'interfaces' ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
                color: activeSubView === 'interfaces' ? '#c084fc' : 'var(--text-secondary)',
                border: activeSubView === 'interfaces' ? '1px solid #a855f7' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              📡 Interfaces ({agentDetails?.ifaces?.length || 0})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('detections')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'detections' ? 700 : 500,
                background: activeSubView === 'detections' ? 'rgba(245, 158, 11, 0.2)' : 'transparent',
                color: activeSubView === 'detections' ? '#fbbf24' : 'var(--text-secondary)',
                border: activeSubView === 'detections' ? '1px solid #f59e0b' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🛡️ Detecciones ({agentDetails?.wazuh_detections?.length || 0})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('forensics')}
              style={{
                padding: '5px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'forensics' ? 700 : 500,
                background: activeSubView === 'forensics' ? 'linear-gradient(135deg, rgba(168, 85, 247, 0.3), rgba(59, 130, 246, 0.3))' : 'transparent',
                color: activeSubView === 'forensics' ? '#c084fc' : 'var(--text-secondary)',
                border: activeSubView === 'forensics' ? '1px solid #a855f7' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🔬 Ficha Forense & Auditoría
            </button>
          </div>
        </div>

        {/* ── SUB-VISTA 1: SITIOS WEB Y ACTIVIDAD DE RED (EXPLORADOR PRINCIPAL) ── */}
        {activeSubView === 'sites' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            
            {/* Panel de Equipos en la Misma Red WiFi / LAN */}
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px', padding: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Wifi size={16} style={{ color: '#00e5ff' }} />
                  <strong style={{ fontSize: '13px', color: '#fff' }}>
                    Equipos en la Misma Red WiFi / Local (Sincronizados con Wazuh Manager)
                  </strong>
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Total: {lanDevices.length || summary?.total_agents || 0} dispositivos monitoreados
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
                {lanDevices.map((dev) => {
                  const isCurSel = selectedAgentId === dev.agent_id;
                  const isManager = dev.agent_id === '000';
                  return (
                    <div
                      key={dev.agent_id}
                      onClick={() => setSelectedAgentId(dev.agent_id)}
                      style={{
                        background: isCurSel ? 'rgba(0, 229, 255, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                        border: isCurSel ? '1px solid #00e5ff' : '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--green-healthy)' }} />
                          <strong style={{ fontSize: '12px', color: '#fff' }}>[{dev.agent_id}] {dev.agent_name}</strong>
                          {isManager && (
                            <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8' }}>
                              MANAGER
                            </span>
                          )}
                        </div>
                        <span style={{ fontSize: '10px', color: '#34d399', fontWeight: 600 }}>
                          🟢 Sincronizado
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)' }}>
                        <div>
                          IP Red: <code style={{ color: '#fff' }}>{dev.ip}</code>
                        </div>
                        <div>
                          Interfaz: <span style={{ color: '#38bdf8' }}>{dev.interface_name || 'wlan0'}</span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', marginTop: '6px', paddingTop: '6px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                        <span>Sitios Activos: <strong style={{ color: '#00e5ff' }}>{dev.active_sites_count || 0}</strong></span>
                        <span>Tráfico: <strong>{dev.rx_mb || 0} MB RX</strong></span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Toolbar con Filtros y Buscador de Sitios */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 600 }}>Filtrar Tipo:</span>
                
                {[
                  { id: 'all', label: '🌐 Todos los Sitios' },
                  { id: 'web', label: '🔐 Navegación Web (80/443)' },
                  { id: 'dns', label: '🔍 Consultas DNS (53)' },
                  { id: 'messaging', label: '💬 Mensajería (Telegram/WA)' },
                  { id: 'sync', label: '🛡️ Sincronización Wazuh' },
                  { id: 'ssh', label: '🔑 Terminal SSH' },
                  { id: 'database', label: '🗄️ Bases de Datos' },
                ].map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setSiteCategoryFilter(f.id)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontWeight: siteCategoryFilter === f.id ? 700 : 500,
                      background: siteCategoryFilter === f.id ? 'rgba(0, 229, 255, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                      color: siteCategoryFilter === f.id ? '#00e5ff' : 'var(--text-secondary)',
                      border: siteCategoryFilter === f.id ? '1px solid #00e5ff' : '1px solid rgba(255, 255, 255, 0.08)',
                      cursor: 'pointer',
                    }}
                  >
                    {f.label}
                  </button>
                ))}

                <button
                  type="button"
                  onClick={() => setSiteStateFilter(siteStateFilter === 'active' ? 'all' : 'active')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: siteStateFilter === 'active' ? 700 : 500,
                    background: siteStateFilter === 'active' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                    color: siteStateFilter === 'active' ? '#34d399' : 'var(--text-secondary)',
                    border: siteStateFilter === 'active' ? '1px solid #10b981' : '1px solid rgba(255, 255, 255, 0.08)',
                    cursor: 'pointer',
                  }}
                >
                  🟢 {siteStateFilter === 'active' ? 'Solo Activas (Filtrado)' : 'Solo Conexiones Activas'}
                </button>
              </div>

              {/* Buscador de Sitios */}
              <div className="terminal-search-box" style={{ minWidth: '240px' }}>
                <Search size={12} className="search-icon" />
                <input
                  type="text"
                  placeholder="Buscar sitio, dominio, proceso (ej: google, firefox)..."
                  value={siteSearchQuery}
                  onChange={(e) => setSiteSearchQuery(e.target.value)}
                  style={{ fontSize: '11px' }}
                />
                {siteSearchQuery && (
                  <button type="button" className="clear-btn" onClick={() => setSiteSearchQuery('')}>
                    <X size={10} />
                  </button>
                )}
              </div>
            </div>

            {/* Tabla de Sitios y Destinos */}
            {loadingSites ? (
              <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Loader2 size={28} className="animate-spin" style={{ margin: '0 auto 10px', color: '#00e5ff' }} />
                <span>Analizando conexiones y resolviendo dominios de los agentes...</span>
              </div>
            ) : activeSitesList.length === 0 ? (
              <div style={{ padding: '50px', textAlign: 'center', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.02)', borderRadius: '10px' }}>
                <Globe size={36} style={{ margin: '0 auto 10px', opacity: 0.4, color: '#38bdf8' }} />
                <h4 style={{ margin: 0, color: '#fff', fontSize: '14px' }}>No hay destinos registrados con los filtros actuales</h4>
                <p style={{ fontSize: '12px', margin: '6px 0 0' }}>
                  {siteSearchQuery || siteCategoryFilter !== 'all'
                    ? 'Intenta restablecer los filtros o la búsqueda para ver todas las conexiones.'
                    : 'Los agentes están sincronizados. Navega en la web o ejecuta comandos para ver el tráfico en vivo.'}
                </p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ background: 'rgba(255, 255, 255, 0.04)', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                      <th style={{ padding: '10px 14px' }}>Sitio Web / Destino Remoto</th>
                      <th style={{ padding: '10px 14px' }}>Equipo / Agente</th>
                      <th style={{ padding: '10px 14px' }}>Aplicación / Proceso</th>
                      <th style={{ padding: '10px 14px' }}>Tipo de Tráfico</th>
                      <th style={{ padding: '10px 14px' }}>Destino IP & Puerto</th>
                      <th style={{ padding: '10px 14px' }}>Estado</th>
                      <th style={{ padding: '10px 14px' }}>Última Actividad</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeSitesList.map((site, idx) => {
                      const isEstab = site.state.includes('estab') || site.state.includes('syn') || site.state_label.includes('ACTIVA');
                      return (
                        <tr
                          key={idx}
                          style={{
                            borderBottom: '1px solid rgba(255,255,255,0.04)',
                            background: idx % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent',
                          }}
                        >
                          {/* Sitio Web / Destino */}
                          <td style={{ padding: '10px 14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <div
                                style={{
                                  width: '26px',
                                  height: '26px',
                                  borderRadius: '6px',
                                  background: 'rgba(255, 255, 255, 0.05)',
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                }}
                              >
                                {renderSiteIcon(site.category, site.is_web, (site as any).icon)}
                              </div>
                              <div>
                                <strong style={{ fontSize: '12px', color: '#fff', display: 'block' }}>
                                  {site.site_name}
                                </strong>
                                <span style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                                  {site.domain}
                                </span>
                              </div>
                            </div>
                          </td>

                          {/* Equipo / Agente */}
                          <td style={{ padding: '10px 14px' }}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '3px 8px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.04)' }}>
                              <Laptop size={12} style={{ color: '#38bdf8' }} />
                              <span style={{ fontWeight: 600, color: '#fff' }}>[{site.agent_id}] {site.agent_name}</span>
                            </div>
                            {site.agent_ip && (
                              <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px', marginLeft: '6px' }}>
                                IP: {site.agent_ip}
                              </div>
                            )}
                          </td>

                          {/* Aplicación / Proceso */}
                          <td style={{ padding: '10px 14px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontWeight: 700,
                                padding: '2px 7px',
                                borderRadius: '4px',
                                background: 'rgba(6, 182, 212, 0.15)',
                                color: '#22d3ee',
                                border: '1px solid rgba(6, 182, 212, 0.3)',
                              }}
                            >
                              {site.process}
                            </span>
                            {site.pid && (
                              <span style={{ color: 'var(--text-secondary)', marginLeft: '6px', fontSize: '10px' }}>
                                PID {site.pid}
                              </span>
                            )}
                          </td>

                          {/* Tipo de Tráfico */}
                          <td style={{ padding: '10px 14px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontWeight: 600,
                                color: site.is_web ? '#38bdf8' : site.category === 'dns' ? '#00e5ff' : '#94a3b8',
                              }}
                            >
                              {site.category_label}
                            </span>
                          </td>

                          {/* Destino IP & Puerto */}
                          <td style={{ padding: '10px 14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <code style={{ color: '#fff' }}>{site.remote_ip}:{site.remote_port}</code>
                              <span
                                style={{
                                  fontSize: '9px',
                                  padding: '1px 5px',
                                  borderRadius: '3px',
                                  background: site.protocol === 'TCP' ? 'rgba(0, 229, 255, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                                  color: site.protocol === 'TCP' ? '#00e5ff' : '#c084fc',
                                  fontWeight: 700,
                                }}
                              >
                                {site.protocol}
                              </span>
                            </div>
                          </td>

                          {/* Estado */}
                          <td style={{ padding: '10px 14px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontWeight: 700,
                                padding: '2px 8px',
                                borderRadius: '10px',
                                background: isEstab ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                                color: isEstab ? '#34d399' : '#fbbf24',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                            >
                              <span
                                style={{
                                  width: '5px',
                                  height: '5px',
                                  borderRadius: '50%',
                                  background: isEstab ? '#34d399' : '#fbbf24',
                                }}
                              />
                              {isEstab ? 'CONEXIÓN ACTIVA' : site.state_label}
                            </span>
                          </td>

                          {/* Última Actividad */}
                          <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>
                            {site.last_seen || 'LIVE'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── SUB-VISTA 2: CONSOLA EN VIVO DEL FLUJO (STREAM SSE) ── */}
        {activeSubView === 'live_stream' && (
          <>
            <div className="terminal-toolbar" style={{ flexWrap: 'wrap', gap: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Filter size={12} style={{ color: 'var(--text-secondary)' }} />
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Filtro Tráfico:</span>
                <select
                  className="terminal-select"
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  style={{ fontSize: '11px', padding: '4px 8px' }}
                >
                  <option value="all">Todo el Flujo</option>
                  <option value="site">Solo Destinos & Sitios Web</option>
                  <option value="traffic">Solo Conexiones y Paquetes</option>
                  <option value="heartbeat">Solo Keep-Alives / Heartbeat</option>
                  <option value="security">Solo Detecciones de Seguridad</option>
                </select>
              </div>

              {/* Buscador */}
              <div className="terminal-search-box" style={{ flex: 1, minWidth: '180px' }}>
                <Search size={12} className="search-icon" />
                <input
                  type="text"
                  placeholder="Buscar proceso, IP, sitio, regla o estado..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  style={{ fontSize: '11px' }}
                />
                {searchFilter && (
                  <button type="button" className="clear-btn" onClick={() => setSearchFilter('')}>
                    <X size={10} />
                  </button>
                )}
              </div>

              {/* Controles de flujo */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  type="button"
                  className="icon-tool-btn"
                  onClick={togglePause}
                  title={isPaused ? 'Reanudar flujo en vivo' : 'Pausar flujo'}
                >
                  {isPaused ? <Play size={13} style={{ color: 'var(--green-healthy)' }} /> : <Pause size={13} />}
                </button>

                <button
                  type="button"
                  className="icon-tool-btn"
                  onClick={() => setEvents([])}
                  title="Limpiar buffer de eventos"
                >
                  <Trash2 size={13} />
                </button>

                <button
                  type="button"
                  className={`icon-tool-btn ${autoScroll ? 'active' : ''}`}
                  onClick={() => setAutoScroll(!autoScroll)}
                  title={autoScroll ? 'Auto-scroll activado' : 'Auto-scroll desactivado'}
                >
                  <span style={{ fontSize: '10px', fontWeight: 700 }}>{autoScroll ? 'SCROLL ON' : 'SCROLL OFF'}</span>
                </button>

                <button
                  type="button"
                  className="icon-tool-btn"
                  onClick={() => {
                    const text = filteredEvents.map((ev) => JSON.stringify(ev)).join('\n');
                    navigator.clipboard.writeText(text);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  title="Copiar log visible al portapapeles"
                >
                  {copied ? <Check size={13} style={{ color: 'var(--green-healthy)' }} /> : <Copy size={13} />}
                </button>
              </div>
            </div>

            {/* Consola de logs */}
            <div className="terminal-logs-container" ref={terminalLogsRef}>
              {filteredEvents.length === 0 ? (
                <div className="terminal-empty-state">
                  <Activity size={32} style={{ color: 'rgba(0, 229, 255, 0.4)' }} />
                  <h4>Monitoreando tráfico del equipo...</h4>
                  <p>
                    {isPaused
                      ? 'El flujo está pausado. Haz clic en el botón de reproducción para reanudar.'
                      : 'Esperando paquetes de red, conexiones y eventos de los agentes sincronizados.'}
                  </p>
                </div>
              ) : (
                filteredEvents.map((evt, idx) => {
                  const isTraffic = evt.type === 'network_traffic';
                  const isSite = evt.type === 'site_activity' || Boolean((evt as any).site_name);
                  const isExpanded = expandedEventId === evt.id;
                  const procName = evt.process || 'wazuh-agentd';

                  return (
                    <div
                      key={evt.id || idx}
                      className={`terminal-log-row ${isSite ? 'level-medium' : isTraffic ? 'level-medium' : 'level-low'}`}
                      onClick={() => setExpandedEventId(isExpanded ? null : (evt.id || String(idx)))}
                      style={{ cursor: 'pointer' }}
                    >
                      <div className="log-row-header">
                        <span className="log-ts">
                          {evt.timestamp ? evt.timestamp.split('T')[1]?.split('+')[0]?.split('.')[0] || evt.timestamp : 'LIVE'}
                        </span>

                        {/* Badge de Proceso */}
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '1px 6px',
                            borderRadius: '4px',
                            background: isSite ? 'rgba(56, 189, 248, 0.2)' : 'rgba(6, 182, 212, 0.2)',
                            color: isSite ? '#38bdf8' : '#22d3ee',
                            border: `1px solid ${isSite ? 'rgba(56, 189, 248, 0.35)' : 'rgba(6, 182, 212, 0.35)'}`,
                          }}
                        >
                          [{procName}]
                        </span>

                        {/* Badge de Agente */}
                        <span className="log-badge-agent">
                          [{evt.agent_id}] {evt.agent_name}
                        </span>

                        {/* Dirección de Red / Destino Web */}
                        {isSite ? (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: '#38bdf8' }}>
                            <Globe size={11} />
                            <strong>{(evt as any).site_name || evt.dst_ip}</strong>
                            <span style={{ fontSize: '10px', opacity: 0.8 }}>({(evt as any).domain || evt.dst_port})</span>
                          </div>
                        ) : isTraffic ? (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: '#93c5fd' }}>
                            <code>{evt.src_ip}:{evt.src_port || '0'}</code>
                            <ArrowRight size={10} style={{ color: 'var(--text-secondary)' }} />
                            <code>{evt.dst_ip}:{evt.dst_port || '1514'}</code>
                            <span style={{ fontSize: '9px', padding: '1px 4px', background: 'rgba(59, 130, 246, 0.2)', borderRadius: '3px' }}>
                              {evt.protocol || 'TCP'}
                            </span>
                          </div>
                        ) : (
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                            {evt.connection_socket || 'Socket Wazuh Remoted (1514/TCP)'}
                          </span>
                        )}

                        {/* Regla Wazuh si existe */}
                        {evt.rule_id && (
                          <span className="log-badge-rule">
                            Regla #{evt.rule_id}
                          </span>
                        )}

                        <span className="log-desc" style={{ flex: 1, minWidth: '200px' }}>
                          {evt.description || 'Tráfico capturado'}
                        </span>

                        <span className="log-action">
                          {evt.status === 'DETECTED' ? 'DETECTADO' : evt.status || 'OK'}
                        </span>
                      </div>

                      {/* Drawer desplegable de detalles */}
                      {isExpanded && (
                        <div className="event-drawer" onClick={(e) => e.stopPropagation()}>
                          <div className="event-drawer-grid">
                            <div className="drawer-item">
                              <span className="drawer-label">Proceso Local:</span>
                              <span className="drawer-val" style={{ color: '#00e5ff' }}>{procName}</span>
                            </div>
                            <div className="drawer-item">
                              <span className="drawer-label">Destino / Socket:</span>
                              <span className="drawer-val">
                                {evt.src_ip}:{evt.src_port || '0'} → {evt.dst_ip}:{evt.dst_port || '1514'} ({evt.protocol || 'TCP'})
                              </span>
                            </div>
                            <div className="drawer-item">
                              <span className="drawer-label">Agente Emisor:</span>
                              <span className="drawer-val">[{evt.agent_id}] {evt.agent_name} ({evt.agent_ip || evt.src_ip})</span>
                            </div>
                            <div className="drawer-item">
                              <span className="drawer-label">Sistema Operativo:</span>
                              <span className="drawer-val">{evt.os || 'Linux'} · {evt.version || 'Wazuh v4.14.7'}</span>
                            </div>
                          </div>

                          <div className="event-drawer-raw">
                            <pre>{JSON.stringify(evt, null, 2)}</pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </>
        )}

        {/* ── SUB-VISTA 3: TABLA DE SOCKETS Y PUERTOS ACTIVOS (SYSCOLLECTOR) ── */}
        {activeSubView === 'sockets' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>🔌</span> Conexiones y Sockets de Red en Vivo (Wazuh Syscollector)
                </h4>
                <p style={{ margin: '2px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Puertos locales en escucha y conexiones TCP/UDP establecidas por los procesos en este equipo.
                </p>
              </div>
              <span style={{ fontSize: '11px', color: '#34d399', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.25)', padding: '3px 8px', borderRadius: '6px' }}>
                Total: {agentDetails?.ports?.length || 0} sockets inspeccionados
              </span>
            </div>

            {loadingDetails ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 8px', color: '#00e5ff' }} />
                <span>Consultando tabla de puertos y sockets en Wazuh API...</span>
              </div>
            ) : !agentDetails?.ports || agentDetails.ports.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }}>
                <p>No se encontraron sockets registrados para este agente en syscollector.</p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                      <th style={{ padding: '8px 12px' }}>Proto</th>
                      <th style={{ padding: '8px 12px' }}>Equipo</th>
                      <th style={{ padding: '8px 12px' }}>Proceso / PID</th>
                      <th style={{ padding: '8px 12px' }}>Puerto Local</th>
                      <th style={{ padding: '8px 12px' }}>Destino / Sitio Web</th>
                      <th style={{ padding: '8px 12px' }}>Estado</th>
                      <th style={{ padding: '8px 12px' }}>Clasificación</th>
                    </tr>
                  </thead>
                  <tbody>
                    {agentDetails.ports.map((socket: AgentSocket, idx: number) => {
                      const isEstab = socket.state.includes('estab') || socket.state.includes('syn');
                      const isListen = socket.state.includes('listen');
                      return (
                        <tr
                          key={idx}
                          style={{
                            borderBottom: '1px solid rgba(255,255,255,0.04)',
                            background: idx % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent',
                          }}
                        >
                          <td style={{ padding: '8px 12px' }}>
                            <span style={{
                              fontWeight: 700,
                              fontSize: '10px',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              background: socket.protocol === 'TCP' ? 'rgba(0, 229, 255, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                              color: socket.protocol === 'TCP' ? '#00e5ff' : '#c084fc',
                            }}>
                              {socket.protocol}
                            </span>
                          </td>
                          <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>
                            [{socket.agent_id || '000'}] {socket.agent_name || 'host'}
                          </td>
                          <td style={{ padding: '8px 12px', color: '#fff', fontWeight: 600 }}>
                            <span style={{ color: '#38bdf8' }}>{socket.process}</span>
                            {socket.pid && <span style={{ color: 'var(--text-secondary)', marginLeft: '6px', fontSize: '10px' }}>(PID {socket.pid})</span>}
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <code>{socket.local_ip}:{socket.local_port}</code>
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            {socket.site_name ? (
                              <div>
                                <strong style={{ color: '#38bdf8', fontSize: '11px' }}>{socket.site_name}</strong>
                                <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                                  {socket.remote_ip}:{socket.remote_port}
                                </div>
                              </div>
                            ) : (
                              <code style={{ color: socket.remote_ip !== '-' && socket.remote_ip !== '0.0.0.0' ? '#34d399' : 'var(--text-secondary)' }}>
                                {socket.remote_ip}:{socket.remote_port}
                              </code>
                            )}
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '2px 8px',
                              borderRadius: '10px',
                              background: isEstab ? 'rgba(16, 185, 129, 0.2)' : isListen ? 'rgba(59, 130, 246, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                              color: isEstab ? '#34d399' : isListen ? '#60a5fa' : '#fbbf24',
                            }}>
                              {socket.state.includes('listen')
                                ? 'ESCUCHANDO'
                                : socket.state.includes('estab') || socket.state.includes('syn')
                                ? 'ESTABLECIDA'
                                : socket.state.includes('close_wait')
                                ? 'CERRANDO'
                                : socket.state.includes('time_wait')
                                ? 'EN ESPERA'
                                : socket.state.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>
                            {socket.category_label || (
                              socket.process === 'wazuh-agentd'
                                ? 'Canal seguro con el Manager Wazuh (1514)'
                                : socket.process === 'sshd'
                                ? 'Servicio de acceso SSH'
                                : 'Conexión del sistema operativo'
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
        )}

        {/* ── SUB-VISTA 4: INTERFACES DE RED (NETIFACE) ── */}
        {activeSubView === 'interfaces' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>📡</span> Interfaces de Red y Estadísticas de Ancho de Banda (Netiface)
                </h4>
                <p style={{ margin: '2px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Tarjetas de red físicas y virtuales del agente, con bytes transmitidos y paquetes reales.
                </p>
              </div>
            </div>

            {loadingDetails ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 8px', color: '#00e5ff' }} />
                <span>Consultando interfaces de red...</span>
              </div>
            ) : !agentDetails?.ifaces || agentDetails.ifaces.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <p>No se encontraron interfaces en este agente.</p>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
                {agentDetails.ifaces.map((iface: AgentNetInterface, idx: number) => {
                  const isUp = iface.state === 'up';
                  const rxMb = (iface.rx_bytes / (1024 * 1024)).toFixed(2);
                  const txMb = (iface.tx_bytes / (1024 * 1024)).toFixed(2);
                  const isWifi = iface.name.includes('wlan') || iface.name.includes('wifi');

                  return (
                    <div
                      key={idx}
                      style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: `1px solid ${isUp ? 'rgba(16, 185, 129, 0.3)' : 'rgba(255, 255, 255, 0.08)'}`,
                        borderRadius: '10px',
                        padding: '14px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {isWifi ? <Wifi size={16} style={{ color: '#38bdf8' }} /> : <Network size={16} style={{ color: isUp ? '#10b981' : 'var(--text-secondary)' }} />}
                          <strong style={{ fontSize: '13px', color: '#fff' }}>{iface.name}</strong>
                          <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>({isWifi ? 'WiFi' : iface.type})</span>
                        </div>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '10px',
                          background: isUp ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                          color: isUp ? '#34d399' : 'var(--text-secondary)',
                        }}>
                          {iface.state.toLowerCase() === 'up' ? 'ACTIVA' : 'INACTIVA'}
                        </span>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px', marginBottom: '12px' }}>
                        <div style={{ background: 'rgba(0, 229, 255, 0.05)', padding: '8px', borderRadius: '6px', border: '1px solid rgba(0, 229, 255, 0.1)' }}>
                          <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '10px' }}>📥 Recibido (RX):</span>
                          <strong style={{ color: '#00e5ff', fontSize: '13px' }}>{rxMb} MB</strong>
                          <div style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>{iface.rx_packets} paquetes</div>
                        </div>

                        <div style={{ background: 'rgba(168, 85, 247, 0.05)', padding: '8px', borderRadius: '6px', border: '1px solid rgba(168, 85, 247, 0.1)' }}>
                          <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '10px' }}>📤 Transmitido (TX):</span>
                          <strong style={{ color: '#c084fc', fontSize: '13px' }}>{txMb} MB</strong>
                          <div style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>{iface.tx_packets} paquetes</div>
                        </div>
                      </div>

                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                        {iface.ipv4 && <div>IP: <code style={{ color: '#fff' }}>{iface.ipv4}</code></div>}
                        <div>MAC: <code>{iface.mac}</code></div>
                        <div>MTU: <code>{iface.mtu}</code> bytes</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SUB-VISTA 5: DETECCIONES DE SEGURIDAD WAZUH DEL AGENTE ── */}
        {activeSubView === 'detections' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>🛡️</span> Eventos y Detecciones de Seguridad Wazuh en este Agente
                </h4>
                <p style={{ margin: '2px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Alertas registradas por el motor de reglas de Wazuh para el equipo {selectedAgentObj ? selectedAgentObj.name : 'seleccionado'}.
                </p>
              </div>
              <span style={{ fontSize: '11px', color: '#fbbf24', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)', padding: '3px 8px', borderRadius: '6px' }}>
                {agentDetails?.wazuh_detections?.length || 0} eventos registrados
              </span>
            </div>

            {loadingDetails ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 8px', color: '#00e5ff' }} />
                <span>Cargando eventos de seguridad de Wazuh...</span>
              </div>
            ) : !agentDetails?.wazuh_detections || agentDetails.wazuh_detections.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }}>
                <p>No se registran eventos de seguridad anómalos recientes para este agente.</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {agentDetails.wazuh_detections.map((det: AgentWazuhDetection, idx: number) => {
                  const isCritical = det.level >= 10;
                  const isHigh = det.level >= 7 && det.level < 10;

                  return (
                    <div
                      key={det.id || idx}
                      style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: `1px solid ${isCritical ? 'rgba(239, 68, 68, 0.35)' : isHigh ? 'rgba(245, 158, 11, 0.3)' : 'rgba(255, 255, 255, 0.08)'}`,
                        borderRadius: '8px',
                        padding: '12px 14px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 8px',
                            borderRadius: '10px',
                            background: isCritical ? 'rgba(239, 68, 68, 0.2)' : isHigh ? 'rgba(245, 158, 11, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                            color: isCritical ? 'var(--red-error)' : isHigh ? 'var(--yellow-warning)' : '#60a5fa',
                          }}>
                            {det.level_es}
                          </span>
                          <span style={{ fontSize: '11px', color: '#00e5ff', fontWeight: 600 }}>
                            Regla #{det.rule_id}
                          </span>
                          <span style={{ fontSize: '12px', fontWeight: 700, color: '#fff' }}>
                            {det.description}
                          </span>
                        </div>
                        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                          {det.timestamp}
                        </span>
                      </div>

                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', gap: '16px', flexWrap: 'wrap', margin: '4px 0 8px' }}>
                        <span>Equipo: <strong style={{ color: '#fff' }}>[{det.agent_id}] {det.agent_name}</strong></span>
                        {det.srcip && <span>Origen: <code style={{ color: '#f87171' }}>{det.srcip}</code></span>}
                        {det.dstuser && <span>Usuario: <code style={{ color: '#38bdf8' }}>{det.dstuser}</code></span>}
                      </div>

                      {(det.full_log_es || det.full_log) && (
                        <div style={{ background: '#050811', padding: '8px 10px', borderRadius: '6px', fontSize: '11px', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.04)', fontFamily: 'monospace' }}>
                          <span style={{ color: '#38bdf8', fontSize: '10px', display: 'block', marginBottom: '2px' }}>Detalle del Evento (Español):</span>
                          {det.full_log_es || det.full_log}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SUB-VISTA 6: FICHA FORENSE & AUDITORÍA PROFUNDA ── */}
        {activeSubView === 'forensics' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>🔬</span> Ficha Forense & Auditoría Profunda
                </h4>
                <p style={{ margin: '2px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Perfil integral del agente {fullProfile ? `[${fullProfile.agent_id}] ${fullProfile.name}` : 'seleccionado'}: hardware, SO, seguridad (SCA/FIM), software y procesos.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                {fullProfile && (
                  <button
                    onClick={() => handleDownloadAgentPdf(fullProfile.agent_id, fullProfile.name)}
                    disabled={downloadingPdf}
                    style={{
                      background: 'rgba(56, 189, 248, 0.15)',
                      border: '1px solid rgba(56, 189, 248, 0.4)',
                      color: '#38bdf8',
                      padding: '5px 12px',
                      borderRadius: '6px',
                      cursor: downloadingPdf ? 'not-allowed' : 'pointer',
                      fontSize: '12px',
                      fontWeight: 600,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      transition: 'all 0.2s ease',
                    }}
                    title="Descargar reporte forense oficial en PDF"
                  >
                    {downloadingPdf ? <Loader2 size={13} className="animate-spin" /> : <FileText size={13} />}
                    <span>{downloadingPdf ? 'Generando PDF...' : '📄 Descargar Reporte PDF'}</span>
                  </button>
                )}
                {fullProfile && (
                  <span style={{ fontSize: '11px', color: '#c084fc', background: 'rgba(168, 85, 247, 0.1)', border: '1px solid rgba(168, 85, 247, 0.25)', padding: '5px 8px', borderRadius: '6px' }}>
                    Última sincronización: {new Date(fullProfile.timestamp * 1000).toLocaleString('es-AR')}
                  </span>
                )}
              </div>
            </div>

            {loadingProfile ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Loader2 size={24} className="animate-spin" style={{ margin: '0 auto 8px', color: '#c084fc' }} />
                <span>Recopilando ficha forense del agente...</span>
              </div>
            ) : !fullProfile ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }}>
                <p>No se pudo cargar la ficha forense. Verificá la conexión con el relay.</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

                {/* ── Identificación del Agente ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Server size={13} /> Identificación del Agente
                  </h5>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px', fontSize: '12px' }}>
                    <div><span style={{ color: 'var(--text-secondary)' }}>ID:</span> <code style={{ color: '#fff' }}>{fullProfile.agent_id}</code></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Nombre:</span> <strong style={{ color: '#fff' }}>{fullProfile.name}</strong></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>IP:</span> <code style={{ color: '#38bdf8' }}>{fullProfile.ip}</code></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Estado:</span> <span style={{ color: fullProfile.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)' }}>{fullProfile.status}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Versión Wazuh:</span> <span style={{ color: '#fff' }}>{fullProfile.version}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Último keep-alive:</span> <span style={{ color: '#fff' }}>{fullProfile.last_keep_alive}</span></div>
                  </div>
                </div>

                {/* ── Hardware ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Cpu size={13} /> Hardware
                  </h5>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '10px', fontSize: '12px' }}>
                    <div><span style={{ color: 'var(--text-secondary)' }}>CPU:</span> <span style={{ color: '#fff' }}>{fullProfile.hardware?.cpu_name || '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Núcleos:</span> <span style={{ color: '#fff' }}>{fullProfile.hardware?.cpu_cores ?? '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Frecuencia:</span> <span style={{ color: '#fff' }}>{fullProfile.hardware?.cpu_mhz ?? '-'} MHz</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>RAM Total:</span> <span style={{ color: '#fff' }}>{fullProfile.hardware?.ram_total_mb ?? '-'} MB</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>RAM Usada:</span> <span style={{ color: '#fbbf24' }}>{fullProfile.hardware?.ram_used_mb ?? '-'} MB ({fullProfile.hardware?.ram_usage_percent ?? '-'}%)</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>RAM Libre:</span> <span style={{ color: 'var(--green-healthy)' }}>{fullProfile.hardware?.ram_free_mb ?? '-'} MB</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Board Serial:</span> <code style={{ color: '#94a3b8' }}>{fullProfile.hardware?.board_serial || '-'}</code></div>
                  </div>
                </div>

                {/* ── Sistema Operativo ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <HardDrive size={13} /> Sistema Operativo
                  </h5>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px', fontSize: '12px' }}>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Nombre:</span> <span style={{ color: '#fff' }}>{fullProfile.os?.name || '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Plataforma:</span> <span style={{ color: '#fff' }}>{fullProfile.os?.platform || '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Versión:</span> <span style={{ color: '#fff' }}>{fullProfile.os?.version || '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Kernel:</span> <code style={{ color: '#94a3b8' }}>{fullProfile.os?.kernel || '-'}</code></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Arquitectura:</span> <span style={{ color: '#fff' }}>{fullProfile.os?.architecture || '-'}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Hostname:</span> <span style={{ color: '#fff' }}>{fullProfile.os?.hostname || '-'}</span></div>
                  </div>
                </div>

                {/* ── Red ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#00e5ff', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Wifi size={13} /> Red — Interfaces ({fullProfile.network?.interfaces?.length || 0})
                  </h5>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    Tráfico total: <strong style={{ color: '#fff' }}>{fullProfile.network?.total_rx_mb ?? 0} MB recibidos</strong> · <strong style={{ color: '#fff' }}>{fullProfile.network?.total_tx_mb ?? 0} MB enviados</strong>
                  </div>
                  {(fullProfile.network?.interfaces || []).map((iface, idx) => (
                    <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '8px 10px', marginBottom: '6px', fontSize: '11px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <strong style={{ color: '#fff' }}>{iface.name}</strong>
                        <span style={{ color: iface.state === 'up' ? 'var(--green-healthy)' : 'var(--red-error)', fontSize: '10px', fontWeight: 700 }}>{iface.state?.toUpperCase()}</span>
                        {iface.ipv4 && <code style={{ color: '#38bdf8' }}>{iface.ipv4}</code>}
                        <code style={{ color: 'var(--text-secondary)' }}>{iface.mac}</code>
                        <span style={{ color: 'var(--text-secondary)' }}>MTU {iface.mtu}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>↓{Math.round((iface.rx_bytes || 0) / 1048576)} MB ↑{Math.round((iface.tx_bytes || 0) / 1048576)} MB</span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* ── SCA CIS Benchmark ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#f59e0b', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldCheck size={13} /> Seguridad de Configuración (SCA) — {fullProfile.sca?.name || 'CIS Benchmark'}
                  </h5>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))', gap: '10px', fontSize: '12px', marginBottom: '10px' }}>
                    <div style={{ textAlign: 'center', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '6px', padding: '8px' }}>
                      <div style={{ fontSize: '20px', fontWeight: 700, color: (fullProfile.sca?.score ?? 0) >= 80 ? 'var(--green-healthy)' : (fullProfile.sca?.score ?? 0) >= 50 ? '#fbbf24' : 'var(--red-error)' }}>{fullProfile.sca?.score ?? 0}%</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Score</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '6px', padding: '8px' }}>
                      <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--green-healthy)' }}>{fullProfile.sca?.pass ?? 0}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Aprobados</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '6px', padding: '8px' }}>
                      <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--red-error)' }}>{fullProfile.sca?.fail ?? 0}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Fallidos</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'rgba(255,255,255,0.04)', borderRadius: '6px', padding: '8px' }}>
                      <div style={{ fontSize: '20px', fontWeight: 700, color: '#fff' }}>{fullProfile.sca?.total_checks ?? 0}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Total Controles</div>
                    </div>
                  </div>
                  {(fullProfile.sca?.failed_checks || []).length > 0 && (
                    <div>
                      <div style={{ fontSize: '11px', color: '#f87171', fontWeight: 600, marginBottom: '6px' }}>Controles fallidos:</div>
                      {fullProfile.sca.failed_checks.map((chk, idx) => (
                        <div key={idx} style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', borderRadius: '6px', padding: '8px 10px', marginBottom: '6px', fontSize: '11px' }}>
                          <div style={{ color: '#f87171', fontWeight: 600 }}>#{chk.id} — {chk.title}</div>
                          {chk.rationale && <div style={{ color: 'var(--text-secondary)', marginTop: '2px' }}>{chk.rationale}</div>}
                          {chk.remediation && <div style={{ color: '#34d399', marginTop: '2px' }}>Fix: {chk.remediation}</div>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* ── FIM Syscheck ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#a855f7', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileCheck size={13} /> Integridad de Archivos (FIM) — {fullProfile.fim?.total_monitored ?? 0} archivos monitoreados
                  </h5>
                  {(fullProfile.fim?.recent_files || []).length === 0 ? (
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Sin cambios recientes registrados por Syscheck.</div>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', color: 'var(--text-secondary)' }}>
                            <th style={{ textAlign: 'left', padding: '4px 8px' }}>Archivo</th>
                            <th style={{ textAlign: 'left', padding: '4px 8px' }}>Tamaño</th>
                            <th style={{ textAlign: 'left', padding: '4px 8px' }}>Permisos</th>
                            <th style={{ textAlign: 'left', padding: '4px 8px' }}>MD5</th>
                          </tr>
                        </thead>
                        <tbody>
                          {fullProfile.fim.recent_files.map((f, idx) => (
                            <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                              <td style={{ padding: '4px 8px', color: '#fff', fontFamily: 'monospace', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.file}</td>
                              <td style={{ padding: '4px 8px', color: 'var(--text-secondary)' }}>{f.size ?? '-'}</td>
                              <td style={{ padding: '4px 8px', color: 'var(--text-secondary)' }}>{f.perm || '-'}</td>
                              <td style={{ padding: '4px 8px', color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '10px' }}>{f.md5 ? f.md5.slice(0, 12) + '…' : '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* ── Software Instalado ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#fb923c', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Package size={13} /> Software Instalado — {fullProfile.software?.total_packages ?? 0} paquetes detectados
                  </h5>
                  <input
                    type="text"
                    placeholder="Buscar paquete..."
                    value={packageSearch}
                    onChange={(e) => setPackageSearch(e.target.value)}
                    style={{
                      width: '100%', maxWidth: '300px', padding: '6px 10px', borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(0,0,0,0.3)', color: '#fff',
                      fontSize: '11px', marginBottom: '10px', outline: 'none',
                    }}
                  />
                  {(fullProfile.software?.sample_packages || []).filter((p) => {
                    if (!packageSearch.trim()) return true;
                    const q = packageSearch.toLowerCase();
                    return `${p.name} ${p.version} ${p.vendor}`.toLowerCase().includes(q);
                  }).map((pkg, idx) => (
                    <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '6px 10px', marginBottom: '4px', fontSize: '11px', display: 'flex', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap' }}>
                      <span style={{ color: '#fff', fontWeight: 600 }}>{pkg.name}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{pkg.version} {pkg.vendor ? `· ${pkg.vendor}` : ''}</span>
                    </div>
                  ))}
                </div>

                {/* ── Procesos ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#34d399', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <TerminalIcon size={13} /> Procesos Activos — {fullProfile.processes?.total_count ?? 0} detectados
                  </h5>
                  <input
                    type="text"
                    placeholder="Buscar proceso..."
                    value={processSearch}
                    onChange={(e) => setProcessSearch(e.target.value)}
                    style={{
                      width: '100%', maxWidth: '300px', padding: '6px 10px', borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(0,0,0,0.3)', color: '#fff',
                      fontSize: '11px', marginBottom: '10px', outline: 'none',
                    }}
                  />
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {(fullProfile.processes?.top_processes || []).filter((p) => {
                      if (!processSearch.trim()) return true;
                      const q = processSearch.toLowerCase();
                      return `${p.name} ${p.cmd} ${p.euser}`.toLowerCase().includes(q);
                    }).map((proc, idx) => (
                      <span key={idx} style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: '6px', padding: '3px 8px', fontSize: '11px', color: '#34d399' }}>
                        <code>{proc.pid}</code> {proc.name} {proc.euser ? `(${proc.euser})` : ''}
                      </span>
                    ))}
                  </div>
                </div>

                {/* ── Sitios Activos (resumen desde la ficha) ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Globe size={13} /> Destinos de Red Activos — {(fullProfile.active_sites || []).length} sitios
                  </h5>
                  {(fullProfile.active_sites || []).slice(0, 15).map((site, idx) => (
                    <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '6px 10px', marginBottom: '4px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      {renderSiteIcon(site.category, site.is_web)}
                      <strong style={{ color: '#fff' }}>{site.site_name}</strong>
                      <code style={{ color: 'var(--text-secondary)' }}>{site.remote_ip}:{site.remote_port}</code>
                      <span style={{ color: 'var(--text-secondary)' }}>{site.process}</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>{site.category_label}</span>
                    </div>
                  ))}
                </div>

                {/* ── Detecciones recientes (resumen desde la ficha) ── */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '14px' }}>
                  <h5 style={{ margin: '0 0 10px', fontSize: '12px', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldAlert size={13} /> Detecciones Wazuh Recientes — {(fullProfile.recent_detections || []).length} alertas
                  </h5>
                  {(fullProfile.recent_detections || []).slice(0, 10).map((det, idx) => {
                    const isCritical = det.level >= 10;
                    return (
                      <div key={idx} style={{ background: isCritical ? 'rgba(239,68,68,0.06)' : 'rgba(0,0,0,0.2)', border: `1px solid ${isCritical ? 'rgba(239,68,68,0.2)' : 'transparent'}`, borderRadius: '6px', padding: '6px 10px', marginBottom: '4px', fontSize: '11px' }}>
                        <span style={{ color: isCritical ? '#f87171' : '#fbbf24', fontWeight: 700, fontSize: '10px' }}>{det.level_es}</span>
                        {' '}<span style={{ color: '#00e5ff' }}>#{det.rule_id}</span>
                        {' '}<span style={{ color: '#fff' }}>{det.description}</span>
                        {det.srcip && <span style={{ color: 'var(--text-secondary)' }}> · origen <code>{det.srcip}</code></span>}
                      </div>
                    );
                  })}
                </div>

              </div>
            )}
          </div>
        )}

        {/* ── STATUSBAR INFERIOR ── */}
        <div className="terminal-statusbar">
          <div className="statusbar-left">
            <span>Equipo Seleccionado: <strong>{selectedAgentId === 'all' ? 'Toda la Red' : `[${selectedAgentId}] ${selectedAgentObj?.name || 'Agente'}`}</strong></span>
            <span>·</span>
            <span>Sitios Detectados: <strong>{activeSitesList.length}</strong></span>
            <span>·</span>
            <span>Canal Remoted: <strong>1514/TCP</strong></span>
            <span>·</span>
            <span>Equipos WiFi/LAN: <strong>{lanDevices.length || summary?.total_agents || 0}</strong></span>
          </div>

          <div className="statusbar-right">
            <span>{isPaused ? '⏸ Flujo en pausa' : '▶ Transmisión en vivo activa'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkAgentsTerminal;
