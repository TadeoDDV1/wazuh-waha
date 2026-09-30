/**
 * useTelemetry — hook React para recibir telemetría en vivo del relay.
 *
 * Ya NO abre su propia conexión: se suscribe al telemetryBus compartido
 * (un solo EventSource por pestaña para Navbar + tarjetas + módulos).
 * El bus maneja fallback a polling y reconexión con backoff.
 *
 * Limpieza automática en unmount (la última baja cierra la conexión).
 */

import { useEffect, useState } from 'react';
import { subscribeTelemetry, type TelemetryMode } from '../services/telemetryBus';
import type { TelemetrySnapshot } from '../types/telemetry';

export type { TelemetryMode as TelemetryConnectionMode };

export interface UseTelemetryResult {
  snapshot: TelemetrySnapshot | null;
  connected: boolean;
  mode: TelemetryMode;
  error: string | null;
  workerId: string | null;
}

export function useTelemetry(): UseTelemetryResult {
  const [snapshot, setSnapshot] = useState<TelemetrySnapshot | null>(null);
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<TelemetryMode>('disconnected');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const unsubscribe = subscribeTelemetry(
      (snap) => setSnapshot(snap),
      (status) => {
        setConnected(status.connected);
        setMode(status.mode);
        setError(status.error);
      },
    );
    return unsubscribe;
  }, []);

  // El worker_id no está en el snapshot; se expone via cabecera X-Worker-Id
  // de la respuesta SSE (no accesible desde JS). Lo dejamos como null.
  return { snapshot, connected, mode, error, workerId: null };
}
