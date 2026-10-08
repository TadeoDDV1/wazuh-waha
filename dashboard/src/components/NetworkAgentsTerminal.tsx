import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './LiveTrafficTerminal.css';
import { dashboardService, buildNetworkStreamUrl } from '../services/api';
import type { AgentNetworkEvent, NetworkSummary, AgentTrafficDetails, AgentSocket, AgentNetInterface, AgentWazuhDetection } from '../types/dashboard';
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
} from 'lucide-react';

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
  const [activeSubView, setActiveSubView] = useState<'live_stream' | 'sockets' | 'interfaces' | 'detections'>('live_stream');

  // Telemetría detallada del agente seleccionado
  const [agentDetails, setAgentDetails] = useState<AgentTrafficDetails | null>(null);
  const [loadingDetails, setLoadingDetails] = useState<boolean>(false);

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

  const terminalLogsRef = useRef<HTMLDivElement>(null);
  const sseRef = useRef<EventSource | null>(null);

  // 1. Cargar resumen general de red y agentes
  const fetchSummary = useCallback(async () => {
    try {
      const data = await dashboardService.getNetworkSummary();
      setSummary(data);
    } catch (err) {
      console.error('Error fetching network summary:', err);
    }
  }, []);

  // 2. Cargar telemetría detallada del agente seleccionado
  const fetchAgentDetails = useCallback(async (agentId: string) => {
    setLoadingDetails(true);
    try {
      const details = await dashboardService.getAgentTrafficDetails(agentId);
      setAgentDetails(details);
    } catch (err) {
      console.error(`Error fetching traffic details for agent ${agentId}:`, err);
    } finally {
      setLoadingDetails(false);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  useEffect(() => {
    fetchAgentDetails(selectedAgentId);
    const interval = setInterval(() => {
      fetchAgentDetails(selectedAgentId);
    }, 12000);
    return () => clearInterval(interval);
  }, [selectedAgentId, fetchAgentDetails]);

  // 3. Conexión al flujo SSE en tiempo real
  useEffect(() => {
    const streamUrl = buildNetworkStreamUrl();
    const es = new EventSource(streamUrl, { withCredentials: true });
    sseRef.current = es;

    es.onopen = () => {
      setConnected(true);
    };

    es.onerror = () => {
      setConnected(false);
    };

    es.onmessage = (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.type === 'connected') {
          setConnected(true);
          return;
        }

        if (payload.type === 'network_event' || payload.type === 'agent_heartbeat') {
          const item: AgentNetworkEvent = payload.data;
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

    return () => {
      es.close();
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
    } catch (err) {
      console.error('Error enviando sonda de red:', err);
    } finally {
      setProbando(false);
    }
  };

  // Filtrado de eventos del stream
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      // Filtro por agente
      if (selectedAgentId !== 'all' && evt.agent_id !== selectedAgentId) {
        return false;
      }
      // Filtro por tipo
      if (typeFilter === 'traffic' && evt.type !== 'network_traffic') return false;
      if (typeFilter === 'heartbeat' && evt.type !== 'agent_heartbeat') return false;
      if (typeFilter === 'security' && !evt.rule_id) return false;

      // Filtro de búsqueda
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
                  Terminal de Red & Telemetría por Agente (LIVE)
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
                  {connected ? 'CANAL REMOTED ACTIVO' : 'RECONECTANDO'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Captura conexiones de red en tiempo real, sockets por proceso, interfaces netiface y detecciones Wazuh por equipo
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
              }}
              disabled={loadingDetails}
              title="Refrescar datos y sockets del agente"
              style={{ background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-secondary)' }}
            >
              <RefreshCw size={12} className={loadingDetails ? 'animate-spin' : ''} />
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
            <span>🌐 Todos los Agentes ({summary?.total_agents || 0})</span>
          </button>

          {/* Agentes individuales */}
          {agentsList.map((ag: any) => {
            const isSel = selectedAgentId === ag.id;
            const osName = ag.os?.name || (ag.id === '000' ? 'Ubuntu' : 'Linux');
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
                <span>[{ag.id}] <strong>{ag.name}</strong></span>
                <span style={{ fontSize: '10px', opacity: 0.7 }}>({osName} · {ag.ip || '127.0.0.1'})</span>
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
              <Activity size={12} style={{ color: '#00e5ff' }} />
              <span>Sockets Activos:</span>
              <strong style={{ color: '#fff' }}>{agentDetails?.kpis?.total_sockets ?? '-'}</strong>
            </div>

            <div className="terminal-meta-chip">
              <CheckCircle2 size={12} style={{ color: 'var(--green-healthy)' }} />
              <span>Conexiones Establecidas:</span>
              <strong style={{ color: 'var(--green-healthy)' }}>{agentDetails?.kpis?.established_connections ?? '-'}</strong>
            </div>

            <div className="terminal-meta-chip">
              <Radio size={12} style={{ color: '#a855f7' }} />
              <span>Puertos en Escucha:</span>
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
                <span>Tráfico Red:</span>
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
              onClick={() => setActiveSubView('live_stream')}
              style={{
                padding: '4px 10px',
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
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'sockets' ? 700 : 500,
                background: activeSubView === 'sockets' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                color: activeSubView === 'sockets' ? '#34d399' : 'var(--text-secondary)',
                border: activeSubView === 'sockets' ? '1px solid #10b981' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🔌 Sockets & Conexiones ({agentDetails?.ports?.length || 0})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('interfaces')}
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'interfaces' ? 700 : 500,
                background: activeSubView === 'interfaces' ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
                color: activeSubView === 'interfaces' ? '#c084fc' : 'var(--text-secondary)',
                border: activeSubView === 'interfaces' ? '1px solid #a855f7' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              📡 Interfaces Netiface ({agentDetails?.ifaces?.length || 0})
            </button>

            <button
              type="button"
              onClick={() => setActiveSubView('detections')}
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: activeSubView === 'detections' ? 700 : 500,
                background: activeSubView === 'detections' ? 'rgba(245, 158, 11, 0.2)' : 'transparent',
                color: activeSubView === 'detections' ? '#fbbf24' : 'var(--text-secondary)',
                border: activeSubView === 'detections' ? '1px solid #f59e0b' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              🛡️ Detecciones Wazuh ({agentDetails?.wazuh_detections?.length || 0})
            </button>
          </div>
        </div>

        {/* ── CONTENIDO PRINCIPAL SEGÚN SUB-VISTA ── */}
        {activeSubView === 'live_stream' && (
          <>
            {/* Toolbar con filtros de stream */}
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
                  placeholder="Buscar proceso, IP, regla o estado..."
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
                  onClick={() => setIsPaused(!isPaused)}
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
                      : 'Esperando paquetes de red y eventos de seguridad del agente Wazuh.'}
                  </p>
                </div>
              ) : (
                filteredEvents.map((evt, idx) => {
                  const isTraffic = evt.type === 'network_traffic';
                  const isExpanded = expandedEventId === evt.id;
                  const procName = evt.process || 'wazuh-agentd';

                  return (
                    <div
                      key={evt.id || idx}
                      className={`terminal-log-row ${isTraffic ? 'level-medium' : 'level-low'}`}
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
                            background: 'rgba(6, 182, 212, 0.2)',
                            color: '#22d3ee',
                            border: '1px solid rgba(6, 182, 212, 0.35)',
                          }}
                        >
                          [{procName}]
                        </span>

                        {/* Badge de Agente */}
                        <span className="log-badge-agent">
                          [{evt.agent_id}] {evt.agent_name}
                        </span>

                        {/* Dirección de Red */}
                        {isTraffic ? (
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
                              <span className="drawer-label">Socket de Conexión:</span>
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

        {/* ── SUB-VISTA 2: TABLA DE SOCKETS Y PUERTOS ACTIVOS (SYSCOLLECTOR) ── */}
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
                      <th style={{ padding: '8px 12px' }}>Proceso / PID</th>
                      <th style={{ padding: '8px 12px' }}>Puerto Local</th>
                      <th style={{ padding: '8px 12px' }}>Destino / IP Remota</th>
                      <th style={{ padding: '8px 12px' }}>Estado</th>
                      <th style={{ padding: '8px 12px' }}>Detalle</th>
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
                          <td style={{ padding: '8px 12px', color: '#fff', fontWeight: 600 }}>
                            <span style={{ color: '#38bdf8' }}>{socket.process}</span>
                            {socket.pid && <span style={{ color: 'var(--text-secondary)', marginLeft: '6px', fontSize: '10px' }}>(PID {socket.pid})</span>}
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <code>{socket.local_ip}:{socket.local_port}</code>
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <code style={{ color: socket.remote_ip !== '-' && socket.remote_ip !== '0.0.0.0' ? '#34d399' : 'var(--text-secondary)' }}>
                              {socket.remote_ip}:{socket.remote_port}
                            </code>
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
                            {socket.process === 'wazuh-agentd'
                              ? 'Canal seguro con el Manager Wazuh (1514)'
                              : socket.process === 'sshd'
                              ? 'Servicio de acceso SSH'
                              : socket.process === 'docker-proxy'
                              ? 'Proxy de contenedor Docker'
                              : 'Conexión del sistema operativo'}
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

        {/* ── SUB-VISTA 3: INTERFACES DE RED (NETIFACE) ── */}
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
                          <Network size={16} style={{ color: isUp ? '#10b981' : 'var(--text-secondary)' }} />
                          <strong style={{ fontSize: '13px', color: '#fff' }}>{iface.name}</strong>
                          <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>({iface.type})</span>
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

        {/* ── SUB-VISTA 4: DETECCIONES DE SEGURIDAD WAZUH DEL AGENTE ── */}
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

        {/* ── STATUSBAR INFERIOR ── */}
        <div className="terminal-statusbar">
          <div className="statusbar-left">
            <span>Agente Activo: <strong>{selectedAgentId === 'all' ? 'Todos los Equipos' : `[${selectedAgentId}] ${selectedAgentObj?.name || 'Agente'}`}</strong></span>
            <span>·</span>
            <span>Buffer en Vivo: <strong>{filteredEvents.length}</strong> eventos</span>
            <span>·</span>
            <span>Canal Remoted: <strong>1514/TCP</strong></span>
          </div>

          <div className="statusbar-right">
            <span>{isPaused ? '⏸ Flujo en pausa' : '▶ Transmisión en vivo'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkAgentsTerminal;
