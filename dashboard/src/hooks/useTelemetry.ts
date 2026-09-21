/**
 * useTelemetry — hook React para recibir telemetría en vivo del relay.
 *
 * Estrategia de conexión:
 *   1. Intenta SSE (EventSource) — actualización ~1s
 *   2. Si SSE falla 3 veces → fallback a polling cada POLL_INTERVAL_MS
 *   3. Reconexión exponencial con jitter: 1s, 2s, 4s, 8s, máx 30s
 *
 * Limpieza automática en unmount (EventSource.close + clearInterval).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchTelemetrySnapshot, buildSSEUrl } from '../services/telemetryService';
import type { TelemetrySnapshot } from '../types/telemetry';

const POLL_INTERVAL_MS = 3_000;
const MAX_SSE_FAILURES = 3;
const BASE_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;

export type TelemetryConnectionMode = 'sse' | 'polling' | 'disconnected';

export interface UseTelemetryResult {
  snapshot: TelemetrySnapshot | null;
  connected: boolean;
  mode: TelemetryConnectionMode;
  error: string | null;
  workerId: string | null;
}

export function useTelemetry(): UseTelemetryResult {
  const [snapshot, setSnapshot] = useState<TelemetrySnapshot | null>(null);
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<TelemetryConnectionMode>('disconnected');
  const [error, setError] = useState<string | null>(null);
  const [workerId, setWorkerId] = useState<string | null>(null);

  // Refs para no crear re-renders innecesarios en la lógica de reconexión
  const esRef = useRef<EventSource | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sseFailuresRef = useRef(0);
  const retryDelayRef = useRef(BASE_RETRY_MS);
  const mountedRef = useRef(true);

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const stopSSE = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
  }, []);

  // ── Polling fallback ───────────────────────────────────────────────────────
  const startPolling = useCallback(() => {
    if (!mountedRef.current) return;
    stopSSE();
    setMode('polling');

    const poll = async () => {
      if (!mountedRef.current) return;
      try {
        const data = await fetchTelemetrySnapshot();
        if (mountedRef.current) {
          setSnapshot(data);
          setConnected(true);
          setError(null);
        }
      } catch (e) {
        if (mountedRef.current) {
          setConnected(false);
          setError(e instanceof Error ? e.message : 'Error de conexión');
        }
      }
    };

    poll(); // inmediato
    pollTimerRef.current = setInterval(poll, POLL_INTERVAL_MS);
  }, [stopSSE]);

  // ── SSE ───────────────────────────────────────────────────────────────────
  const connectSSE = useCallback(() => {
    if (!mountedRef.current) return;
    stopPolling();
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    const url = buildSSEUrl();
    const es = new EventSource(url);
    esRef.current = es;
    setMode('sse');

    es.onopen = () => {
      if (!mountedRef.current) return;
      sseFailuresRef.current = 0;
      retryDelayRef.current = BASE_RETRY_MS;
      setConnected(true);
      setError(null);
    };

    es.onmessage = (event) => {
      if (!mountedRef.current) return;
      try {
        const data: TelemetrySnapshot = JSON.parse(event.data);
        setSnapshot(data);
        setConnected(true);
        setError(null);
      } catch {
        // ignorar frames malformados
      }
    };

    es.onerror = () => {
      if (!mountedRef.current) return;
      es.close();
      esRef.current = null;
      setConnected(false);
      sseFailuresRef.current += 1;

      if (sseFailuresRef.current >= MAX_SSE_FAILURES) {
        // Demasiados fallos → cambiar a polling
        setError('SSE no disponible, usando polling cada 3s');
        startPolling();
        return;
      }

      // Reintentar SSE con backoff exponencial + jitter
      const jitter = Math.random() * 500;
      const delay = Math.min(retryDelayRef.current + jitter, MAX_RETRY_MS);
      retryDelayRef.current = Math.min(retryDelayRef.current * 2, MAX_RETRY_MS);

      retryTimerRef.current = setTimeout(() => {
        if (mountedRef.current) connectSSE();
      }, delay);
    };
  }, [stopPolling, startPolling]);

  // ── Inicialización ────────────────────────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true;

    // Verificar soporte de SSE (todos los navegadores modernos lo soportan,
    // pero puede fallar en prod si el proxy corta la conexión)
    if (typeof EventSource === 'undefined') {
      startPolling();
    } else {
      connectSSE();
    }

    return () => {
      mountedRef.current = false;
      stopSSE();
      stopPolling();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Exponer worker ID desde snapshot ─────────────────────────────────────
  useEffect(() => {
    if (snapshot && workerId === null) {
      // El worker_id no está en el snapshot; se expone via cabecera X-Worker-Id
      // en la respuesta SSE (no accesible desde JS). Lo dejamos como null.
      setWorkerId(null);
    }
  }, [snapshot, workerId]);

  return { snapshot, connected, mode, error, workerId };
}
