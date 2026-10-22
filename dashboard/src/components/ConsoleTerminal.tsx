import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { dashboardService, buildConsoleWsUrl } from '../services/api';
import { Loader2, Play, Square, ShieldAlert, TerminalSquare, Maximize2 } from 'lucide-react';
import './ConsoleTerminal.css';

interface ConsoleTarget {
  id: string;
  label: string;
  type: 'local' | 'ssh';
}

interface ConsoleTerminalProps {
  defaultTarget?: string;
  mode?: 'traffic' | 'console';
}

export const ConsoleTerminal: React.FC<ConsoleTerminalProps> = ({ defaultTarget, mode = 'console' }) => {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [targets, setTargets] = useState<ConsoleTarget[]>([]);
  const [target, setTarget] = useState<string>('');
  const [enabled, setEnabled] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  const [busy, setBusy] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [maximized, setMaximized] = useState<boolean>(false);

  useEffect(() => {
    dashboardService.getConsoleTargets()
      .then((res) => {
        setEnabled(Boolean(res.enabled));
        setTargets(res.targets || []);
        if (res.targets?.length) {
          const preferred = defaultTarget && res.targets.some((t: ConsoleTarget) => t.id === defaultTarget)
            ? defaultTarget
            : res.targets[0].id;
          setTarget(preferred);
        }
      })
      .catch((err) => {
        setError(err?.response?.status === 403
          ? 'La consola requiere sesión con permisos completos.'
          : 'No se pudieron cargar los destinos de consola.');
      });
  }, []);

  const sendResize = useCallback(() => {
    const term = termRef.current;
    const ws = wsRef.current;
    if (!term || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
  }, []);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    termRef.current?.dispose();
    termRef.current = null;
    fitRef.current = null;
    setConnected(false);
    setBusy(false);
  }, []);

  const connect = useCallback(() => {
    if (!target || !hostRef.current) return;
    setError(null);
    setBusy(true);

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      theme: {
        background: '#070b12',
        foreground: '#d8e2f0',
        cursor: '#00e5ff',
        selectionBackground: '#1e3a4a',
      },
      convertEol: true,
      scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const ws = new WebSocket(buildConsoleWsUrl(target));
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setBusy(false);
      term.focus();
      sendResize();
    };
    ws.onmessage = (evt) => {
      if (typeof evt.data === 'string') term.write(evt.data);
    };
    ws.onerror = () => {
      setError('Error de conexión con la consola. Revisá la sesión y el destino.');
    };
    ws.onclose = (evt) => {
      setConnected(false);
      setBusy(false);
      if (evt.code === 4401) setError('Sesión no autorizada. Volvé a iniciar sesión.');
      else if (evt.code === 4403) setError('Consola deshabilitada o destino no permitido.');
      else if (evt.code === 4404) setError('Destino de consola no permitido.');
      else if (evt.code === 4408) setError('Sesión cerrada por inactividad.');
      else if (evt.code === 4429) setError('Límite de sesiones simultáneas alcanzado.');
      term.write('\r\n\x1b[33m[sesión finalizada]\x1b[0m\r\n');
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
      }
    });

    const onResize = () => {
      try {
        fit.fit();
        sendResize();
      } catch {
        /* noop */
      }
    };
    window.addEventListener('resize', onResize);
    const ro = new ResizeObserver(onResize);
    ro.observe(hostRef.current);
    (term as unknown as { _cleanup?: () => void })._cleanup = () => {
      window.removeEventListener('resize', onResize);
      ro.disconnect();
    };
  }, [target, sendResize]);

  useEffect(() => () => {
    const term = termRef.current as unknown as { _cleanup?: () => void } | null;
    term?._cleanup?.();
    disconnect();
  }, [disconnect]);

  const sendCommand = (command: string) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'input', data: command + '\n' }));
    termRef.current?.focus();
  };

  return (
    <div className={`console-shell ${maximized ? 'maximized' : ''}`}>
      <div className="console-toolbar">
        <div className="console-title">
          <TerminalSquare size={18} />
          <div>
            <h2>{mode === 'traffic' ? 'Terminal de Tráfico & Comandos' : 'Consola Web & SSH'}</h2>
            <p>{mode === 'traffic' ? 'Terminal interactiva para ejecutar comandos y ver el tráfico en vivo del SOC.' : 'Acceso interactivo auditado al relay o al Wazuh Manager.'}</p>
          </div>
        </div>
        <div className="console-controls">
          <select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={connected || !enabled}
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
          </select>
          {!connected ? (
            <button className="console-btn primary" onClick={connect} disabled={!enabled || !target || busy}>
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
              Conectar
            </button>
          ) : (
            <button className="console-btn danger" onClick={disconnect}>
              <Square size={14} /> Desconectar
            </button>
          )}
          <button
            className="console-btn ghost"
            onClick={() => {
              setMaximized((v) => !v);
              setTimeout(() => { fitRef.current?.fit(); sendResize(); }, 120);
            }}
            title="Pantalla completa"
          >
            <Maximize2 size={14} />
          </button>
        </div>
      </div>

      {!enabled && (
        <div className="console-warning">
          <ShieldAlert size={16} /> La consola está deshabilitada. Configurá <code>CONSOLE_ENABLED=true</code>.
        </div>
      )}
      {error && <div className="console-error">{error}</div>}

      <div className="console-quick">
        <span className="console-quick-label">Comandos rápidos:</span>
        <button className="console-quick-btn" disabled={!connected} onClick={() => sendCommand('tail -f /var/ossec/logs/alerts/alerts.json')}>
          tail -f alertas
        </button>
        <button className="console-quick-btn" disabled={!connected} onClick={() => sendCommand('ss -tunap')}>
          conexiones
        </button>
        <button className="console-quick-btn" disabled={!connected} onClick={() => sendCommand('df -h && free -m && uptime')}>
          recursos
        </button>
        <button className="console-quick-btn" disabled={!connected} onClick={() => sendCommand('sudo -n /var/ossec/bin/wazuh-control status 2>/dev/null || systemctl status wazuh-manager --no-pager | head -30')}>
          estado wazuh
        </button>
      </div>

      <div className="console-term-wrap">
        {!connected && !busy && (
          <div className="console-placeholder">
            <TerminalSquare size={34} />
            <strong>Seleccioná un destino y pulsá Conectar</strong>
            <span>Shell local del relay o SSH al manager/agentes configurados.</span>
          </div>
        )}
        <div ref={hostRef} className="console-term" />
      </div>

      <div className="console-footnote">
        <ShieldAlert size={13} />
        Toda sesión queda auditada. El shell local corre como el usuario del servicio, no como root.
      </div>
    </div>
  );
};

export default ConsoleTerminal;
