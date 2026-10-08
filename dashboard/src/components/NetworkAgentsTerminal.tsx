import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './LiveTrafficTerminal.css';
import { dashboardService, buildNetworkStreamUrl } from '../services/api';
import type { AgentNetworkEvent, NetworkSummary } from '../types/dashboard';
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
  const [events, setEvents] = useState<AgentNetworkEvent[]>([]);
  const [summary, setSummary] = useState<NetworkSummary | null>(null);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [pendingWhilePaused, setPendingWhilePaused] = useState<AgentNetworkEvent[]>([]);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [agentFilter, setAgentFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [maximized, setMaximized] = useState<boolean>(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  const [probing, setProbing] = useState<boolean>(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const isPausedRef = useRef(isPaused);
  const pendingRef = useRef<AgentNetworkEvent[]>([]);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    pendingRef.current = pendingWhilePaused;
  }, [pendingWhilePaused]);

  // Consultar resumen inicial de red y agentes
  const fetchSummary = useCallback(async () => {
    try {
      const data = await dashboardService.getNetworkSummary();
      if (data && data.ok) {
        setSummary(data);
      }
    } catch (e) {
      console.error('Error fetching network summary', e);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
    const interval = setInterval(fetchSummary, 12000);
    return () => clearInterval(interval);
  }, [fetchSummary]);

  const appendEvent = useCallback((newEvt: AgentNetworkEvent) => {
    if (isPausedRef.current) {
      const next = [...pendingRef.current, newEvt];
      pendingRef.current = next.slice(-MAX_EVENTS);
      setPendingWhilePaused(pendingRef.current);
      return;
    }
    setEvents((prev) => {
      const updated = [...prev, newEvt];
      return updated.length > MAX_EVENTS ? updated.slice(updated.length - MAX_EVENTS) : updated;
    });
  }, []);

  // Conexión SSE
  useEffect(() => {
    const url = buildNetworkStreamUrl();
    const es = new EventSource(url, { withCredentials: true });
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
    };

    es.onmessage = (msg) => {
      try {
        const payload = JSON.parse(msg.data);
        if (payload.type === 'connected') {
          setConnected(true);
          appendEvent({
            type: 'connected',
            id: `init-${Date.now()}`,
            timestamp: new Date().toISOString(),
            msg: 'Capturador de paquetes y sockets activo. Monitoreando tráfico de red y agentes.',
          });
        } else if (payload.type === 'network_event' && payload.data) {
          appendEvent(payload.data);
        } else if (payload.type === 'agent_heartbeat' && payload.data) {
          appendEvent(payload.data);
        }
      } catch (e) {
        console.error('Error parsing SSE event', e);
      }
    };

    es.onerror = () => {
      setConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [appendEvent]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && scrollRef.current && !isPaused) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll, isPaused]);

  const handleTogglePause = () => {
    if (isPaused) {
      if (pendingRef.current.length > 0) {
        setEvents((prev) => {
          const merged = [...prev, ...pendingRef.current];
          return merged.length > MAX_EVENTS ? merged.slice(merged.length - MAX_EVENTS) : merged;
        });
        setPendingWhilePaused([]);
      }
      setIsPaused(false);
    } else {
      setIsPaused(true);
    }
  };

  const handleClear = () => {
    setEvents([]);
    setPendingWhilePaused([]);
  };

  const handleCopyLogs = () => {
    const text = filteredEvents
      .map((e) => {
        const ts = e.timestamp || '';
        const ag = e.agent_name ? `[${e.agent_id || '000'} | ${e.agent_name}]` : '';
        const desc = e.description || e.msg || e.connection_socket || '';
        const ip = e.src_ip ? `${e.src_ip}:${e.src_port || ''} -> ${e.dst_ip || ''}:${e.dst_port || ''}` : '';
        return `${ts} ${e.type.toUpperCase()} ${ag} ${ip} ${desc}`;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleProbe = async () => {
    setProbing(true);
    try {
      const res = await dashboardService.probeNetwork();
      if (res?.ok && Array.isArray(res.results)) {
        res.results.forEach((r: any) => {
          appendEvent({
            type: 'agent_heartbeat',
            subtype: 'probe_response',
            id: `probe-${Date.now()}-${r.agent_id}`,
            timestamp: r.timestamp || new Date().toISOString(),
            agent_id: r.agent_id,
            agent_name: r.agent_name,
            agent_ip: r.ip,
            status: r.status,
            latency_ms: r.rtt_ms,
            description: `Sonda de red completada con éxito. Latencia RTT: ${r.rtt_ms}ms`,
          });
        });
      }
    } catch (e) {
      console.error('Error probing network', e);
    } finally {
      setProbing(false);
    }
  };

  // Filtrado de eventos
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (agentFilter !== 'all' && e.agent_id !== agentFilter && e.agent_name !== agentFilter) {
        return false;
      }
      if (typeFilter !== 'all') {
        if (typeFilter === 'traffic' && e.type !== 'network_traffic') return false;
        if (typeFilter === 'heartbeat' && e.type !== 'agent_heartbeat') return false;
        if (typeFilter === 'security' && !e.rule_id) return false;
      }
      if (searchFilter.trim()) {
        const q = searchFilter.toLowerCase();
        const hay = `${e.agent_name || ''} ${e.agent_id || ''} ${e.src_ip || ''} ${e.dst_ip || ''} ${e.description || ''} ${e.msg || ''} ${e.connection_socket || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, agentFilter, typeFilter, searchFilter]);

  const agentsList = summary?.agents || [];

  return (
    <div className={asPanel ? 'traffic-terminal-panel' : 'traffic-terminal-overlay'}>
      <div className={`traffic-terminal-window ${asPanel ? 'as-panel' : ''} ${maximized ? 'maximized' : ''}`}>
        {/* Titlebar */}
        <div className="terminal-titlebar">
          <div className="terminal-titlebar-left">
            <div
              style={{
                width: '28px',
                height: '28px',
                borderRadius: '6px',
                background: 'rgba(59, 130, 246, 0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#60a5fa',
                border: '1px solid rgba(59, 130, 246, 0.4)',
              }}
            >
              <Network size={16} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>
                  Terminal de Red & Equipos Agentes Wazuh (LIVE)
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
                  {connected ? 'SOCKET CONECTADO' : 'DESCONECTADO'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Captura de paquetes, conexiones de red (puerto 1514), estados keepalive y telemetría de equipos
              </div>
            </div>
          </div>

          {/* Chips de estado rápido */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div className="terminal-meta-chip">
              <Server size={12} style={{ color: '#00e5ff' }} />
              <span>Agentes:</span>
              <strong style={{ color: '#fff' }}>
                {summary ? `${summary.active_agents}/${summary.total_agents} activos` : 'Consultando...'}
              </strong>
            </div>

            <div className="terminal-meta-chip">
              <Radio size={12} style={{ color: '#a855f7' }} />
              <span>Puerto 1514 Remoted:</span>
              <strong style={{ color: summary?.services_ports?.find((p) => p.port === 1514)?.open ? 'var(--green-healthy)' : 'var(--yellow-warning)' }}>
                {summary?.services_ports?.find((p) => p.port === 1514)?.open ? 'ABIERTO (ESCUCHANDO)' : 'VERIFICANDO'}
              </strong>
            </div>

            <button
              type="button"
              className="action-pill-btn"
              onClick={handleProbe}
              disabled={probing}
              style={{
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.25), rgba(147, 51, 234, 0.25))',
                borderColor: '#60a5fa',
                color: '#93c5fd',
              }}
              title="Enviar paquete sonda para medir latencia en tiempo real"
            >
              {probing ? <Loader2 size={12} className="animate-spin" /> : <Zap size={12} />}
              <span>{probing ? 'Sondeando...' : '📡 Sondear Red / Ping'}</span>
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

        {/* Toolbar con filtros */}
        <div className="terminal-toolbar" style={{ flexWrap: 'wrap', gap: '8px' }}>
          {/* Selector de Agentes */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Equipo:</span>
            <select
              className="terminal-select"
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              style={{ fontSize: '11px', padding: '4px 8px' }}
            >
              <option value="all">Todos los Equipos</option>
              {agentsList.map((ag: any) => (
                <option key={ag.id} value={ag.id}>
                  [{ag.id}] {ag.name} ({ag.ip || '127.0.0.1'})
                </option>
              ))}
            </select>
          </div>

          {/* Selector de Tipo de Tráfico */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Tipo:</span>
            <select
              className="terminal-select"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              style={{ fontSize: '11px', padding: '4px 8px' }}
            >
              <option value="all">Todo el Tráfico</option>
              <option value="traffic">Conexiones y Paquetes</option>
              <option value="heartbeat">Keep-Alives / Heartbeat</option>
              <option value="security">Eventos de Red de Seguridad</option>
            </select>
          </div>

          {/* Buscador */}
          <div className="terminal-search-box">
            <Search size={13} className="terminal-search-icon" />
            <input
              type="text"
              placeholder="Filtrar por IP, puerto, agente, payload..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="terminal-search-input"
            />
          </div>

          {/* Botones de acción de la consola */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginLeft: 'auto' }}>
            <button
              type="button"
              className={`terminal-btn ${isPaused ? 'warning' : ''}`}
              onClick={handleTogglePause}
              title={isPaused ? 'Reanudar flujo' : 'Pausar flujo'}
            >
              {isPaused ? <Play size={13} /> : <Pause size={13} />}
              <span>{isPaused ? `Pausado (${pendingWhilePaused.length})` : 'Pausar'}</span>
            </button>

            <button
              type="button"
              className="terminal-btn"
              onClick={handleClear}
              title="Limpiar pantalla"
            >
              <Trash2 size={13} />
              <span>Limpiar</span>
            </button>

            <button
              type="button"
              className="terminal-btn"
              onClick={handleCopyLogs}
              title="Copiar registro visible"
            >
              {copied ? <Check size={13} /> : <Copy size={13} />}
              <span>{copied ? 'Copiado' : 'Copiar'}</span>
            </button>

            <label
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                marginLeft: '6px',
              }}
            >
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
              />
              <span>Auto-scroll</span>
            </label>
          </div>
        </div>

        {/* Consola Terminal */}
        <div className="terminal-body" ref={scrollRef}>
          {filteredEvents.length === 0 ? (
            <div className="terminal-empty-state">
              <Network size={36} style={{ color: 'rgba(0, 229, 255, 0.4)', marginBottom: '12px' }} />
              <div style={{ color: '#fff', fontSize: '13px', fontWeight: 600 }}>
                Esperando eventos de tráfico de red y agentes...
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Los sockets de los agentes y paquetes en el puerto 1514 aparecerán aquí en tiempo real.
              </div>
            </div>
          ) : (
            filteredEvents.map((evt, idx) => {
              const evtId = evt.id || `evt-${idx}`;
              const isExpanded = expandedId === evtId;

              const isSecurity = evt.type === 'network_traffic' && evt.rule_id;
              const isHeartbeat = evt.type === 'agent_heartbeat';
              const isInit = evt.type === 'connected';

              const timeStr = evt.timestamp ? evt.timestamp.split('T')?.[1]?.slice(0, 12) || evt.timestamp : '';

              return (
                <div
                  key={evtId}
                  className={`terminal-log-line ${isExpanded ? 'expanded' : ''}`}
                  onClick={() => setExpandedId(isExpanded ? null : evtId)}
                  style={{
                    borderLeft: isSecurity
                      ? '3px solid #ef4444'
                      : isHeartbeat
                      ? '3px solid #10b981'
                      : isInit
                      ? '3px solid #00e5ff'
                      : '3px solid #3b82f6',
                  }}
                >
                  <span className="log-col-time">{timeStr || '00:00:00'}</span>

                  {/* Badge de tipo */}
                  {isSecurity && (
                    <span className="log-col-level" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#f87171' }}>
                      RED-ALERTA #{evt.rule_id}
                    </span>
                  )}
                  {isHeartbeat && (
                    <span className="log-col-level" style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399' }}>
                      KEEPALIVE
                    </span>
                  )}
                  {isInit && (
                    <span className="log-col-level" style={{ background: 'rgba(0, 229, 255, 0.2)', color: '#00e5ff' }}>
                      SISTEMA
                    </span>
                  )}

                  {/* Agente */}
                  <span
                    className="log-col-agent"
                    style={{
                      color: evt.agent_id === '000' ? '#67e8f9' : '#a78bfa',
                      fontWeight: 600,
                    }}
                  >
                    [{evt.agent_id || '000'}|{evt.agent_name || 'host'}]
                  </span>

                  {/* Conexión de red / Socket */}
                  {evt.src_ip && (
                    <span
                      style={{
                        color: '#93c5fd',
                        fontFamily: 'monospace',
                        marginRight: '8px',
                        fontSize: '11px',
                      }}
                    >
                      {evt.protocol || 'TCP'} {evt.src_ip}:{evt.src_port || '1514'} ➔ {evt.dst_ip}:{evt.dst_port}
                    </span>
                  )}

                  {/* Descripción / Mensaje */}
                  <span className="log-col-desc" style={{ color: isSecurity ? '#fca5a5' : '#e2e8f0' }}>
                    {evt.description || evt.msg || evt.connection_socket}
                  </span>

                  {/* Métrica de latencia / bytes */}
                  {evt.latency_ms !== undefined && (
                    <span style={{ color: '#10b981', fontSize: '11px', marginLeft: 'auto', fontWeight: 600 }}>
                      ⚡ {evt.latency_ms}ms
                    </span>
                  )}

                  {isExpanded && (
                    <div className="terminal-event-drawer">
                      <div className="event-drawer-grid">
                        <div className="drawer-item">
                          <span className="drawer-label">ID Evento:</span>
                          <span className="drawer-val">{evt.id}</span>
                        </div>
                        <div className="drawer-item">
                          <span className="drawer-label">Equipo / Agente:</span>
                          <span className="drawer-val">{evt.agent_name} (ID: {evt.agent_id})</span>
                        </div>
                        <div className="drawer-item">
                          <span className="drawer-label">IP del Agente:</span>
                          <span className="drawer-val">{evt.agent_ip || evt.src_ip || 'N/D'}</span>
                        </div>
                        <div className="drawer-item">
                          <span className="drawer-label">Socket Remoto:</span>
                          <span className="drawer-val">{evt.connection_socket || 'Puerto 1514/TCP'}</span>
                        </div>
                        <div className="drawer-item">
                          <span className="drawer-label">Sistema Operativo:</span>
                          <span className="drawer-val">{evt.os || 'Linux'}</span>
                        </div>
                        <div className="drawer-item">
                          <span className="drawer-label">Versión Wazuh:</span>
                          <span className="drawer-val">{evt.version || 'v4.9.0'}</span>
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

        {/* Statusbar */}
        <div className="terminal-statusbar">
          <div className="statusbar-left">
            <span>Buffer: <strong>{filteredEvents.length}</strong> eventos</span>
            <span>·</span>
            <span>Agentes Conectados: <strong>{summary?.active_agents ?? 0}</strong></span>
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
