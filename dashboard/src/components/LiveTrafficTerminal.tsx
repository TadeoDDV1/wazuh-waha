import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import './LiveTrafficTerminal.css';
import type { TrafficEvent, TrafficSourceInfo } from '../types/telemetry';
import {
  buildTrafficStreamUrl,
  fetchTrafficTail,
  fetchTrafficSource,
  simulateTrafficEvent,
} from '../services/telemetryService';
import {
  Terminal,
  Play,
  Pause,
  Trash2,
  Copy,
  Check,
  Search,
  Maximize2,
  Minimize2,
  X,
  ArrowDown,
  Zap,
  ChevronRight,
  ChevronDown,
} from 'lucide-react';

interface LiveTrafficTerminalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Si true, se renderiza como panel/pestaña principal (sin overlay modal). */
  asPanel?: boolean;
}

const MAX_EVENTS = 500;
const BASE_RETRY_MS = 1000;
const MAX_RETRY_MS = 30000;

const SOURCE_LABELS: Record<string, string> = {
  auto: 'auto',
  local: 'alerts.json local',
  ssh: 'SSH → VM manager',
  api: 'API Wazuh manager',
  off: 'inactivo',
  relay: 'relay /alerts',
  simulate: 'simulación',
  follower: 'follower (journal)',
  unknown: 'desconocida',
};

export const LiveTrafficTerminal: React.FC<LiveTrafficTerminalProps> = ({
  isOpen,
  onClose,
  asPanel = false,
}) => {
  const [events, setEvents] = useState<TrafficEvent[]>([]);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [pendingWhilePaused, setPendingWhilePaused] = useState<TrafficEvent[]>([]);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [minLevel, setMinLevel] = useState<number>(1);
  const [maximized, setMaximized] = useState<boolean>(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [sourceInfo, setSourceInfo] = useState<TrafficSourceInfo | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryDelayRef = useRef(BASE_RETRY_MS);
  const failuresRef = useRef(0);
  const activeRef = useRef(true);
  const isPausedRef = useRef(isPaused);
  const pendingRef = useRef<TrafficEvent[]>([]);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    pendingRef.current = pendingWhilePaused;
  }, [pendingWhilePaused]);

  const appendEvent = useCallback((newEvt: TrafficEvent) => {
    if (isPausedRef.current) {
      const next = [...pendingRef.current, newEvt];
      pendingRef.current = next.slice(-MAX_EVENTS);
      setPendingWhilePaused(pendingRef.current);
      return;
    }
    setEvents((prev) => {
      if (prev.some((e) => e.id === newEvt.id)) return prev;
      const updated = [...prev, newEvt];
      return updated.length > MAX_EVENTS ? updated.slice(updated.length - MAX_EVENTS) : updated;
    });
  }, []);

  const connectSSERef = useRef<() => void>(() => undefined);

  const connectSSE = useCallback(() => {
    if (!activeRef.current) return;

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }

    const es = new EventSource(buildTrafficStreamUrl());
    eventSourceRef.current = es;

    es.onopen = () => {
      if (!activeRef.current) return;
      failuresRef.current = 0;
      retryDelayRef.current = BASE_RETRY_MS;
      setConnected(true);
    };

    es.onmessage = (msgEvent) => {
      if (!activeRef.current) return;
      try {
        const payload = JSON.parse(msgEvent.data);
        if (payload.type === 'event' && payload.data) {
          appendEvent(payload.data as TrafficEvent);
        }
      } catch {
        // frames heartbeat/connected o malformados: ignorar
      }
    };

    es.onerror = () => {
      if (!activeRef.current) return;
      setConnected(false);
      failuresRef.current += 1;
      es.close();
      if (eventSourceRef.current === es) eventSourceRef.current = null;

      const jitter = Math.random() * 400;
      const delay = Math.min(retryDelayRef.current + jitter, MAX_RETRY_MS);
      retryDelayRef.current = Math.min(retryDelayRef.current * 2, MAX_RETRY_MS);
      retryTimerRef.current = setTimeout(() => {
        if (activeRef.current) connectSSERef.current();
      }, delay);
    };
  }, [appendEvent]);

  useEffect(() => {
    connectSSERef.current = connectSSE;
  }, [connectSSE]);

  // ── Abrir/cerrar terminal: tail + SSE + source info ──────────────────────
  useEffect(() => {
    if (!isOpen) {
      activeRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
      setConnected(false);
      return;
    }

    activeRef.current = true;
    failuresRef.current = 0;
    retryDelayRef.current = BASE_RETRY_MS;

    fetchTrafficTail(100)
      .then((items) => {
        if (activeRef.current && items.length > 0) {
          setEvents(items);
        }
      })
      .catch(() => {
        // tail opcional; el stream puede seguir solo
      });

    fetchTrafficSource()
      .then((info) => {
        if (activeRef.current) setSourceInfo(info);
      })
      .catch(() => undefined);

    if (typeof EventSource === 'undefined') {
      setConnected(false);
    } else {
      connectSSE();
    }

    return () => {
      activeRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    };
  }, [isOpen, connectSSE]);

  // Reanudar: volcar cola de pausa
  useEffect(() => {
    if (!isPaused && pendingWhilePaused.length > 0) {
      setEvents((prev) => {
        const ids = new Set(prev.map((e) => e.id));
        const merged = [...prev];
        for (const ev of pendingWhilePaused) {
          if (!ids.has(ev.id)) {
            merged.push(ev);
            ids.add(ev.id);
          }
        }
        return merged.length > MAX_EVENTS ? merged.slice(merged.length - MAX_EVENTS) : merged;
      });
      setPendingWhilePaused([]);
      pendingRef.current = [];
    }
  }, [isPaused, pendingWhilePaused]);

  // ── Auto-scroll ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (autoScroll && !isPaused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll, isPaused]);

  const handleScroll = () => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    const atBottom = scrollHeight - scrollTop - clientHeight < 40;
    if (!atBottom && autoScroll) {
      setAutoScroll(false);
    }
  };

  const filteredEvents = useMemo(() => {
    const query = searchFilter.trim().toLowerCase();
    return events.filter((ev) => {
      if (ev.level < minLevel) return false;
      if (!query) return true;
      return (
        ev.rule_id.toLowerCase().includes(query) ||
        ev.description.toLowerCase().includes(query) ||
        ev.agent_name.toLowerCase().includes(query) ||
        (ev.src_ip && ev.src_ip.toLowerCase().includes(query)) ||
        (ev.src_user && ev.src_user.toLowerCase().includes(query)) ||
        (ev.dst_user && ev.dst_user.toLowerCase().includes(query)) ||
        (ev.command && ev.command.toLowerCase().includes(query)) ||
        (ev.full_log && ev.full_log.toLowerCase().includes(query))
      );
    });
  }, [events, searchFilter, minLevel]);

  const handleClear = () => {
    setEvents([]);
    setPendingWhilePaused([]);
    pendingRef.current = [];
  };

  const handleCopy = () => {
    const textLines = filteredEvents.map((ev) => {
      const src = ev.src_ip ? `${ev.src_ip}:${ev.src_port || ''}` : 'local';
      return `${ev.timestamp} [L${ev.level}] [${ev.agent_name}] [${src}] #${ev.rule_id}: ${ev.description} | ${ev.full_log}`;
    }).join('\n');

    navigator.clipboard.writeText(textLines).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => undefined);
  };

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      await simulateTrafficEvent({
        rule_id: '57100',
        level: 10,
        description: 'Simulación: SSH login exitoso generado desde la consola del Dashboard',
        src_ip: '192.168.122.1',
        src_user: 'operator',
      });
    } catch {
      // el error de red no debe romper la UI; el stream mostrará el evento si llega
    } finally {
      setTimeout(() => setSimulating(false), 600);
    }
  };

  if (!isOpen) return null;

  const levelBadgeClass = (lvl: number) => {
    if (lvl >= 12) return 't-level crit';
    if (lvl >= 8) return 't-level high';
    if (lvl >= 5) return 't-level warn';
    return 't-level info';
  };

  const levelText = (lvl: number) => {
    if (lvl >= 12) return `CRIT L${lvl}`;
    if (lvl >= 8) return `HIGH L${lvl}`;
    if (lvl >= 5) return `WARN L${lvl}`;
    return `INFO L${lvl}`;
  };

  const resolvedSource =
    sourceInfo?.resolved ||
    sourceInfo?.mode ||
    'auto';
  const sourceLabel = SOURCE_LABELS[resolvedSource] || resolvedSource;

  const window = (
    <div
      className={`traffic-terminal-window ${maximized ? 'maximized' : ''} ${asPanel ? 'as-panel' : ''}`}
      onClick={(e) => e.stopPropagation()}
    >
      {/* ── Titlebar ── */}
      <div className="terminal-titlebar">
        <div className="terminal-titlebar-left">
          {!asPanel && (
            <div className="terminal-window-dots">
              <button className="terminal-dot close" onClick={onClose} title="Cerrar terminal" />
              <button className="terminal-dot minimize" onClick={() => setMaximized(false)} title="Restaurar ventana" />
              <button className="terminal-dot maximize" onClick={() => setMaximized((p) => !p)} title="Maximizar terminal" />
            </div>
          )}

          <div className="terminal-title">
            <Terminal size={16} style={{ color: '#00e5ff' }} />
            <span>wazuh@relay:~$</span>
            <span className="terminal-title-tag">
              tráfico Wazuh · fuente: {sourceLabel}
            </span>
          </div>

          <div className={`terminal-status-badge ${connected ? (isPaused ? 'paused' : 'live') : 'offline'}`}>
            <div className="terminal-pulse-dot" />
            {connected ? (isPaused ? `EN PAUSA (+${pendingWhilePaused.length})` : 'LIVE (SSE)') : 'RECONECTANDO'}
          </div>
        </div>

        <div className="terminal-titlebar-right">
          {!asPanel && (
            <>
              <button
                className="terminal-action-icon-btn"
                onClick={() => setMaximized((p) => !p)}
                title={maximized ? 'Restaurar' : 'Maximizar'}
              >
                {maximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
              </button>
              <button className="terminal-action-icon-btn" onClick={onClose} title="Cerrar (Esc)">
                <X size={15} />
              </button>
            </>
          )}
          {asPanel && (
            <button className="terminal-action-icon-btn" onClick={onClose} title="Volver al dashboard">
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div className="terminal-toolbar">
        <div className="terminal-toolbar-left">
          <button
            className={`terminal-btn ${isPaused ? 'active' : ''}`}
            onClick={() => setIsPaused((p) => !p)}
            title={isPaused ? 'Reanudar y volcar eventos encolados' : 'Pausar: retiene eventos sin mover el scroll'}
          >
            {isPaused ? <Play size={12} /> : <Pause size={12} />}
            <span>{isPaused ? `Reanudar${pendingWhilePaused.length ? ` (+${pendingWhilePaused.length})` : ''}` : 'Pausar'}</span>
          </button>

          <button
            className={`terminal-btn ${autoScroll ? 'active' : ''}`}
            onClick={() => {
              setAutoScroll(true);
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }
            }}
            title="Seguir automáticamente las líneas nuevas al final"
          >
            <ArrowDown size={12} />
            <span>Auto-Scroll</span>
          </button>

          <button className="terminal-btn danger" onClick={handleClear} title="Limpiar buffer visual">
            <Trash2 size={12} />
            <span>Limpiar</span>
          </button>

          <button className="terminal-btn" onClick={handleCopy} title="Copiar logs visibles al portapapeles">
            {copied ? <Check size={12} style={{ color: '#2ecc71' }} /> : <Copy size={12} />}
            <span>{copied ? 'Copiado!' : 'Copiar'}</span>
          </button>

          <button
            className="terminal-btn primary"
            onClick={handleSimulate}
            disabled={simulating}
            title="Generar evento de prueba en el stream"
          >
            <Zap size={12} />
            <span>{simulating ? 'Enviando...' : 'Test Event'}</span>
          </button>
        </div>

        <div className="terminal-toolbar-right">
          <select
            className="terminal-select"
            value={minLevel}
            onChange={(e) => setMinLevel(Number(e.target.value))}
            title="Filtrar por nivel mínimo de severidad"
          >
            <option value={1}>Severidad: Todas (L1+)</option>
            <option value={3}>Severidad: Info (L3+)</option>
            <option value={5}>Severidad: Media (L5+)</option>
            <option value={8}>Severidad: Alta / WAHA (L8+)</option>
            <option value={12}>Severidad: Crítica (L12+)</option>
          </select>

          <div className="terminal-search-box">
            <Search size={13} style={{ color: '#6b7280' }} />
            <input
              type="text"
              className="terminal-search-input"
              placeholder="Buscar IP, regla, usuario, texto..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
            />
            {searchFilter && (
              <button
                className="terminal-action-icon-btn"
                style={{ padding: 0 }}
                onClick={() => setSearchFilter('')}
              >
                <X size={12} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Console Output ── */}
      <div className="terminal-output-container" ref={scrollRef} onScroll={handleScroll}>
        <div className="terminal-welcome-banner">
          <pre>{` _       __                     __  ______  ___   ____  ___   _____ ____  ______
| |     / /___ _____  __  ______/ / / / __ \\/   | / __ \\/   | / ___// __ \\/ ____/
| | /| / / __ \`/ __ \\/ / / / __  / / / /_/ / /| |/ /_/ / /| | \\__ \\/ / / / /
| |/ |/ / /_/ / /_/ / /_/ / /_/ / /_/ / __  / ___ / _, _/ ___ |___/ / /_/ / /___
|__/|__/\\__,_/\\__,_/\\__,_/\\__,_/\\____/_/ /_/_/  |_/_/ |_/_/  |_/____/\\____/\\____/`}</pre>
          <div style={{ marginTop: '8px' }}>
            <strong>Terminal de Telemetría y Tráfico Wazuh en Vivo</strong> · fuente:{' '}
            <code>{sourceLabel}</code>
            {sourceInfo?.journal && (
              <>
                {' · journal: '}
                <code>{sourceInfo.journal}</code>
              </>
            )}
            <br />
            Muestra alertas de <strong>todos los agentes</strong> que reportan al manager Wazuh.
            Clic en un evento para inspeccionar el payload JSON completo.
          </div>
        </div>

        {filteredEvents.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#6b7280', fontSize: '12px' }}>
            {events.length === 0
              ? 'Conectando al stream de Wazuh... esperando tráfico de los agentes.'
              : 'Ningún evento coincide con los filtros aplicados.'}
            <span className="terminal-cursor" />
          </div>
        ) : (
          filteredEvents.map((ev, index) => {
            const isExpanded = expandedId === ev.id;
            const formattedTime = ev.timestamp ? ev.timestamp.replace('T', ' ').slice(11, 23) : '--:--:--';
            const srcDisplay = ev.src_ip ? `${ev.src_ip}${ev.src_port ? `:${ev.src_port}` : ''}` : '';

            return (
              <div
                key={`${ev.id}-${index}`}
                className={`terminal-row ${isExpanded ? 'expanded' : ''}`}
                onClick={() => setExpandedId(isExpanded ? null : ev.id)}
              >
                <div className="terminal-row-line">
                  {isExpanded ? <ChevronDown size={11} color="#00e5ff" /> : <ChevronRight size={11} color="#6b7280" />}
                  <span className="t-time">{formattedTime}</span>
                  <span className={levelBadgeClass(ev.level)}>{levelText(ev.level)}</span>
                  <span className="t-agent">[{ev.agent_name || ev.agent_id}]</span>
                  {srcDisplay && <span className="t-ip">[{srcDisplay}]</span>}
                  <span className="t-rule">#{ev.rule_id}</span>
                  <span className="t-desc">{ev.description}</span>
                  {ev.source && ev.source !== 'unknown' && (
                    <span className="t-mitre">[{ev.source}]</span>
                  )}
                  {ev.mitre_ids && ev.mitre_ids.length > 0 && (
                    <span className="t-mitre">[{ev.mitre_ids.join(', ')}]</span>
                  )}
                </div>

                {isExpanded && (
                  <div className="terminal-row-detail" onClick={(e) => e.stopPropagation()}>
                    <div className="terminal-meta-grid">
                      <div className="terminal-meta-item">
                        <span className="terminal-meta-label">Timestamp completo:</span>
                        <span className="terminal-meta-val">{ev.timestamp}</span>
                      </div>
                      <div className="terminal-meta-item">
                        <span className="terminal-meta-label">Agente:</span>
                        <span className="terminal-meta-val">{ev.agent_name} (ID: {ev.agent_id})</span>
                      </div>
                      {ev.src_ip && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">IP / Puerto Origen:</span>
                          <span className="terminal-meta-val" style={{ color: '#00e5ff' }}>
                            {ev.src_ip}{ev.src_port ? `:${ev.src_port}` : ''}
                          </span>
                        </div>
                      )}
                      {(ev.src_user || ev.dst_user) && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">Usuarios:</span>
                          <span className="terminal-meta-val">
                            {ev.src_user ? `origen: ${ev.src_user} ` : ''}
                            {ev.dst_user ? `destino: ${ev.dst_user}` : ''}
                          </span>
                        </div>
                      )}
                      {ev.command && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">Comando ejecutado:</span>
                          <span className="terminal-meta-val" style={{ color: '#f39c12' }}>{ev.command}</span>
                        </div>
                      )}
                      {ev.location && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">Ubicación / Decoder:</span>
                          <span className="terminal-meta-val">{ev.location}</span>
                        </div>
                      )}
                      {ev.source && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">Fuente:</span>
                          <span className="terminal-meta-val">{SOURCE_LABELS[ev.source] || ev.source}</span>
                        </div>
                      )}
                      {ev.mitre_techniques && ev.mitre_techniques.length > 0 && (
                        <div className="terminal-meta-item">
                          <span className="terminal-meta-label">Técnicas MITRE:</span>
                          <span className="terminal-meta-val" style={{ color: '#ec4899' }}>
                            {ev.mitre_techniques.join(', ')}
                          </span>
                        </div>
                      )}
                    </div>

                    {ev.full_log && (
                      <div>
                        <div className="terminal-meta-label" style={{ marginBottom: '4px' }}>Log en Bruto:</div>
                        <div style={{ background: '#090d16', padding: '6px 8px', borderRadius: '4px', color: '#e5e7eb', fontSize: '11px', wordBreak: 'break-all' }}>
                          {ev.full_log}
                        </div>
                      </div>
                    )}

                    {ev.raw_json != null && (
                      <div>
                        <div className="terminal-meta-label" style={{ marginBottom: '4px' }}>Payload JSON de Wazuh:</div>
                        <pre className="terminal-json-viewer">
                          {JSON.stringify(ev.raw_json, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ── Footer ── */}
      <div className="terminal-footer">
        <div className="terminal-footer-left">
          <div className="terminal-footer-chip">
            <span>Eventos visibles:</span>
            <strong>{filteredEvents.length}</strong> / {events.length}
          </div>
          {searchFilter && (
            <div className="terminal-footer-chip" style={{ color: '#00e5ff' }}>
              <span>Filtro activo:</span>
              <strong>"{searchFilter}"</strong>
            </div>
          )}
          {minLevel > 1 && (
            <div className="terminal-footer-chip" style={{ color: '#f39c12' }}>
              <span>Nivel min:</span>
              <strong>L{minLevel}</strong>
            </div>
          )}
          {isPaused && pendingWhilePaused.length > 0 && (
            <div className="terminal-footer-chip" style={{ color: '#f1c40f' }}>
              <span>Encolados en pausa:</span>
              <strong>{pendingWhilePaused.length}</strong>
            </div>
          )}
        </div>

        <div className="terminal-footer-right">
          <div className="terminal-footer-chip">
            <span>Fuente:</span>
            <strong style={{ color: '#00e5ff' }}>{sourceLabel}</strong>
          </div>
          <div className="terminal-footer-chip">
            <span>Auto-Scroll:</span>
            <strong style={{ color: autoScroll ? '#2ecc71' : '#e74c3c' }}>
              {autoScroll ? 'ACTIVO' : 'PAUSADO'}
            </strong>
          </div>
          <div className="terminal-footer-chip">
            <span>Buffer:</span>
            <strong>{events.length} / {MAX_EVENTS}</strong>
          </div>
        </div>
      </div>
    </div>
  );

  if (asPanel) {
    return <div className="traffic-terminal-panel-host">{window}</div>;
  }

  return (
    <div className="traffic-terminal-overlay" onClick={onClose}>
      {window}
    </div>
  );
};

export default LiveTrafficTerminal;
