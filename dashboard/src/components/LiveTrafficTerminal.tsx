import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import './LiveTrafficTerminal.css';
import type { TrafficEvent, TrafficSourceInfo } from '../types/telemetry';
import {
  buildTrafficStreamUrl,
  fetchTrafficTail,
  fetchTrafficSource,
} from '../services/telemetryService';
import { buildNetworkStreamUrl } from '../services/api';
import { X, Pause, Play, Trash2, Search, Maximize2, Minimize2, ArrowLeft, Cable } from 'lucide-react';

interface LiveTrafficTerminalProps {
  isOpen: boolean;
  onClose: () => void;
  asPanel?: boolean;
}

const SOURCE_LABELS: Record<string, string> = {
  auto: 'auto',
  local: 'alerts.json local',
  ssh: 'SSH → Wazuh Manager',
  api: 'API Wazuh Manager',
  off: 'inactivo',
  relay: 'relay /alerts',
  simulate: 'simulación',
  follower: 'follower (journal)',
  unknown: 'desconocida',
};

const MAX_BUFFER = 2000;

function ts(value?: string): string {
  if (!value) return new Date().toISOString().slice(11, 23);
  return value.replace('T', ' ').slice(11, 23);
}

function ansiLevel(level: number): string {
  if (level >= 12) return '\x1b[1;31m'; // rojo
  if (level >= 8) return '\x1b[1;33m';  // amarillo
  if (level >= 5) return '\x1b[1;36m';  // cyan
  return '\x1b[0;37m';
}

function ansiDirection(dir: string): string {
  if (dir === 'inbound') return '\x1b[1;32m'; // verde
  if (dir === 'outbound') return '\x1b[1;36m'; // cyan
  if (dir === 'listen') return '\x1b[1;34m'; // azul
  return '\x1b[0;37m';
}

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

export const LiveTrafficTerminal: React.FC<LiveTrafficTerminalProps> = ({
  isOpen,
  onClose,
  asPanel = false,
}) => {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const alertEsRef = useRef<EventSource | null>(null);
  const connEsRef = useRef<EventSource | null>(null);
  const pausedRef = useRef(false);
  const filterRef = useRef('');
  const showConnRef = useRef(true);
  const pendingRef = useRef<string[]>([]);
  const lineCountRef = useRef(0);
  const [paused, setPaused] = useState(false);
  const [showConnections, setShowConnections] = useState(true);
  const [filter, setFilter] = useState('');
  const [connected, setConnected] = useState(false);
  const [maximized, setMaximized] = useState(false);
  const [sourceInfo, setSourceInfo] = useState<TrafficSourceInfo | null>(null);
  const [lines, setLines] = useState(0);

  useEffect(() => { pausedRef.current = paused; }, [paused]);
  useEffect(() => { filterRef.current = filter; }, [filter]);
  useEffect(() => { showConnRef.current = showConnections; }, [showConnections]);

  const write = useCallback((line: string) => {
    const term = termRef.current;
    if (!term) return;
    const f = filterRef.current.trim().toLowerCase();
    if (f) {
      const plain = line.replace(/\x1b\[[0-9;]*m/g, '').toLowerCase();
      if (!plain.includes(f)) return;
    }
    if (pausedRef.current) {
      pendingRef.current.push(line);
      if (pendingRef.current.length > MAX_BUFFER) pendingRef.current.shift();
      return;
    }
    term.writeln(line);
    lineCountRef.current += 1;
  }, []);

  const banner = useCallback((info: TrafficSourceInfo | null) => {
    const term = termRef.current;
    if (!term) return;
    const source = SOURCE_LABELS[info?.resolved || info?.mode || 'auto'] || info?.resolved || 'auto';
    term.writeln('\x1b[1;36mwazuh-waha — consola de tráfico en vivo\x1b[0m');
    term.writeln(`${DIM}host: ${window.location.host}   fuente: ${source}   journal: ${info?.journal || '-'}${RESET}`);
    term.writeln(`${DIM}stream: alertas Wazuh + conexiones reales (ss/syscollector)${RESET}`);
    term.writeln('\x1b[32m$\x1b[0m tail -f /var/ossec/logs/alerts/alerts.json && ss -tunap');
    term.writeln('');
  }, []);

  useEffect(() => {
    if (!isOpen && !asPanel) return;
    if (!hostRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 12.5,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      theme: {
        background: '#05080e',
        foreground: '#d8e2f0',
        cursor: '#00e5ff',
        selectionBackground: '#1e3a4a',
        black: '#0b1220',
        red: '#f87171',
        green: '#34d399',
        yellow: '#fbbf24',
        blue: '#60a5fa',
        magenta: '#c084fc',
        cyan: '#22d3ee',
        white: '#e2e8f0',
      },
      scrollback: 10000,
      convertEol: true,
      disableStdin: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    let disposed = false;
    const safeWrite = (line: string) => {
      if (!disposed) write(line);
    };

    const init = async () => {
      let info: TrafficSourceInfo | null = null;
      try {
        info = await fetchTrafficSource();
      } catch { /* sin fuente */ }
      if (disposed) return;
      setSourceInfo(info);
      safeWrite('\x1b[2J\x1b[H');
      banner(info);
      try {
        const items = await fetchTrafficTail(120);
        if (disposed) return;
        const recent = items.slice(-80);
        if (recent.length === 0) {
          safeWrite(`${DIM}(sin eventos previos en el journal)${RESET}`);
        }
        recent.forEach((ev) => {
          safeWrite(
            `${DIM}${ts(ev.timestamp)}${RESET} ${ansiLevel(ev.level)}ALERT L${ev.level}${RESET} ` +
            `[${ev.agent_id} ${ev.agent_name}] #${ev.rule_id} ` +
            `${ev.src_ip ? `${ev.src_ip}${ev.src_port ? ':' + ev.src_port : ''} ` : ''}` +
            `${ev.description}`
          );
        });
      } catch { /* ignore */ }
    };
    init();

    const connectAlerts = () => {
      const es = new EventSource(buildTrafficStreamUrl());
      alertEsRef.current = es;
      es.onopen = () => setConnected(true);
      es.onerror = () => {
        setConnected(false);
        es.close();
        if (!disposed) setTimeout(() => { if (!disposed) connectAlerts(); }, 3000);
      };
      es.onmessage = (evt) => {
        try {
          const payload = JSON.parse(evt.data);
          if (payload.type === 'connected') { setConnected(true); return; }
          if (payload.type !== 'event') return;
          const ev: TrafficEvent = payload.data;
          const src = ev.src_ip ? `${ev.src_ip}${ev.src_port ? ':' + ev.src_port : ''} ` : '';
          safeWrite(
            `${DIM}${ts(ev.timestamp)}${RESET} ${ansiLevel(ev.level)}ALERT L${ev.level}${RESET} ` +
            `[${ev.agent_id} ${ev.agent_name}] #${ev.rule_id} ${src}${ev.description}`
          );
        } catch { /* ignore */ }
      };
    };

    const connectConnections = () => {
      const es = new EventSource(buildNetworkStreamUrl());
      connEsRef.current = es;
      es.onopen = () => setConnected(true);
      es.onerror = () => {
        es.close();
        if (!disposed) setTimeout(() => { if (!disposed) connectConnections(); }, 3000);
      };
      es.onmessage = (evt) => {
        if (!showConnRef.current) return;
        try {
          const payload = JSON.parse(evt.data);
          if (payload.type !== 'network_event') return;
          const data = payload.data || {};
          if (data.subtype === 'connection' || data.type === 'network_event') {
            const dir = String(data.direction || 'conn').toUpperCase();
            const color = ansiDirection(String(data.direction || ''));
            safeWrite(
              `${DIM}${ts(data.timestamp)}${RESET} ${color}NET ${dir.padEnd(8)}${RESET} ` +
              `[${data.agent_id} ${data.agent_name}] ` +
              `${data.local_ip}:${data.local_port} -> ${data.remote_ip}:${data.remote_port} ` +
              `${data.protocol} ${data.state} ` +
              `${data.domain ? `(${data.domain}) ` : ''}` +
              `${data.process ? `[${data.process}]` : ''}`
            );
          } else if (data.type === 'agent_heartbeat') {
            safeWrite(
              `${DIM}${ts(data.timestamp)}${RESET} \x1b[1;35mAGENT${RESET} ` +
              `[${data.agent_id} ${data.agent_name}] ${String(data.status || '').toUpperCase()} ` +
              `${data.agent_ip || ''} ${data.last_keep_alive ? `last=${data.last_keep_alive}` : ''}`
            );
          }
        } catch { /* ignore */ }
      };
    };

    connectAlerts();
    connectConnections();

    const onResize = () => {
      try { fit.fit(); } catch { /* ignore */ }
    };
    const ro = new ResizeObserver(onResize);
    ro.observe(hostRef.current);
    window.addEventListener('resize', onResize);
    const counter = setInterval(() => setLines(lineCountRef.current), 700);

    return () => {
      disposed = true;
      clearInterval(counter);
      window.removeEventListener('resize', onResize);
      ro.disconnect();
      alertEsRef.current?.close();
      connEsRef.current?.close();
      alertEsRef.current = null;
      connEsRef.current = null;
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      setConnected(false);
    };
  }, [isOpen, asPanel, write, banner]);

  const togglePause = () => {
    setPaused((prev) => {
      const next = !prev;
      pausedRef.current = next;
      if (!next && pendingRef.current.length > 0) {
        const term = termRef.current;
        if (term) {
          pendingRef.current.forEach((line) => term.writeln(line));
          lineCountRef.current += pendingRef.current.length;
        }
        pendingRef.current = [];
      }
      return next;
    });
  };

  const clear = () => {
    const term = termRef.current;
    if (!term) return;
    term.clear();
    lineCountRef.current = 0;
    setLines(0);
    banner(sourceInfo);
  };

  if (!isOpen && !asPanel) return null;

  return (
    <div className={`live-console-host ${asPanel ? 'as-panel' : ''} ${maximized ? 'maximized' : ''}`}>
      <div className="live-console-window">
        <div className="live-console-toolbar">
          <div className="live-console-left">
            {asPanel && (
              <button className="live-console-btn" onClick={onClose} title="Volver al dashboard">
                <ArrowLeft size={13} /> Dashboard
              </button>
            )}
            <div className="live-console-title">
              <Cable size={15} />
              <span>wazuh@relay:~$</span>
              <span className="live-console-tag">
                tráfico en vivo · {SOURCE_LABELS[sourceInfo?.resolved || sourceInfo?.mode || 'auto'] || 'auto'}
              </span>
            </div>
            <span className={`live-console-status ${connected ? 'on' : 'off'}`}>
              <span className="dot" /> {connected ? 'STREAM ACTIVO' : 'RECONECTANDO'}
            </span>
          </div>

          <div className="live-console-right">
            <div className="live-console-search">
              <Search size={12} />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="filtrar ip, agente, regla, dominio..."
              />
            </div>
            <button className={`live-console-btn ${paused ? 'active' : ''}`} onClick={togglePause} title={paused ? 'Reanudar' : 'Pausar'}>
              {paused ? <Play size={12} /> : <Pause size={12} />}
              <span>{paused ? `Reanudar${pendingRef.current.length ? ` (${pendingRef.current.length})` : ''}` : 'Pausar'}</span>
            </button>
            <button className={`live-console-btn ${showConnections ? 'active' : ''}`} onClick={() => setShowConnections((v) => !v)} title="Mostrar/ocultar conexiones reales">
              <Cable size={12} /> <span>Conexiones</span>
            </button>
            <button className="live-console-btn" onClick={clear} title="Limpiar pantalla">
              <Trash2 size={12} /> <span>Limpiar</span>
            </button>
            <button className="live-console-btn icon" onClick={() => setMaximized((v) => !v)} title={maximized ? 'Restaurar' : 'Pantalla completa'}>
              {maximized ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
            </button>
            {!asPanel && (
              <button className="live-console-btn icon" onClick={onClose} title="Cerrar">
                <X size={13} />
              </button>
            )}
          </div>
        </div>

        <div className="live-console-term-wrap">
          <div ref={hostRef} className="live-console-term" />
        </div>

        <div className="live-console-footer">
          <span>{lines} líneas</span>
          <span>fuente: {SOURCE_LABELS[sourceInfo?.resolved || sourceInfo?.mode || 'auto'] || 'auto'}</span>
          <span>{sourceInfo?.journal || ''}</span>
        </div>
      </div>
    </div>
  );
};

export default LiveTrafficTerminal;
