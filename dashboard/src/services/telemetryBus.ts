/**
 * telemetryBus — UN solo EventSource de telemetría compartido por todos los
 * componentes (Navbar, TelemetryGlobalCard, WazuhModulesControlCard…).
 *
 * Antes cada hook abría su propia conexión: con 3 consumidores por pestaña se
 * agotaba rápido el cap de clientes SSE del relay (20/worker) y las
 * respuestas 503 disparaban bucles de reintento.
 *
 * Estrategia: SSE (push ~1s) → 3 fallos → polling cada 3s → backoff
 * exponencial con jitter (1s..30s) para reintentar SSE. La conexión se cierra
 * cuando el último consumidor se da de baja (p. ej. al mostrar el login).
 */

import { buildSSEUrl, fetchTelemetrySnapshot } from './telemetryService';
import type { TelemetrySnapshot } from '../types/telemetry';

export type TelemetryMode = 'sse' | 'polling' | 'disconnected';

export interface TelemetryStatus {
  connected: boolean;
  mode: TelemetryMode;
  error: string | null;
}

const POLL_INTERVAL_MS = 3_000;
const MAX_SSE_FAILURES = 3;
const BASE_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;

type SnapshotListener = (snap: TelemetrySnapshot) => void;
type StatusListener = (status: TelemetryStatus) => void;

const snapshotListeners = new Set<SnapshotListener>();
const statusListeners = new Set<StatusListener>();

let es: EventSource | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let sseFailures = 0;
let retryDelay = BASE_RETRY_MS;
let running = false;

let lastSnapshot: TelemetrySnapshot | null = null;
let status: TelemetryStatus = { connected: false, mode: 'disconnected', error: null };

function emitStatus(): void {
  const payload = { ...status };
  statusListeners.forEach((l) => l(payload));
}

function setStatus(patch: Partial<TelemetryStatus>): void {
  status = { ...status, ...patch };
  emitStatus();
}

function emitSnapshot(snap: TelemetrySnapshot): void {
  lastSnapshot = snap;
  snapshotListeners.forEach((l) => l(snap));
}

function stopTimers(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  if (retryTimer) {
    clearTimeout(retryTimer);
    retryTimer = null;
  }
}

function stopAll(): void {
  stopTimers();
  if (es) {
    es.close();
    es = null;
  }
  running = false;
  lastSnapshot = null;
  status = { connected: false, mode: 'disconnected', error: null };
  sseFailures = 0;
  retryDelay = BASE_RETRY_MS;
}

// ── Polling fallback ────────────────────────────────────────────────────────

function startPolling(): void {
  stopTimers();
  if (es) {
    es.close();
    es = null;
  }
  setStatus({ mode: 'polling', connected: false, error: 'SSE no disponible, usando polling cada 3s' });

  const poll = async () => {
    if (!running) return;
    try {
      const data = await fetchTelemetrySnapshot();
      if (!running) return;
      emitSnapshot(data);
      setStatus({ connected: true, error: null });
    } catch (e) {
      if (!running) return;
      setStatus({ connected: false, error: e instanceof Error ? e.message : 'Error de conexión' });
    }
  };

  poll();
  pollTimer = setInterval(poll, POLL_INTERVAL_MS);
}

// ── SSE ─────────────────────────────────────────────────────────────────────

function connectSSE(): void {
  if (!running) return;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  if (es) {
    es.close();
    es = null;
  }
  if (typeof EventSource === 'undefined') {
    startPolling();
    return;
  }

  const source = new EventSource(buildSSEUrl());
  es = source;
  setStatus({ mode: 'sse' });

  source.onopen = () => {
    if (!running) return;
    sseFailures = 0;
    retryDelay = BASE_RETRY_MS;
    setStatus({ connected: true, error: null });
  };

  source.onmessage = (event) => {
    if (!running) return;
    try {
      const data: TelemetrySnapshot = JSON.parse(event.data);
      emitSnapshot(data);
      setStatus({ connected: true, error: null });
    } catch {
      // frame malformado: ignorar
    }
  };

  source.onerror = () => {
    if (!running) return;
    source.close();
    if (es === source) es = null;
    setStatus({ connected: false });
    sseFailures += 1;

    if (sseFailures >= MAX_SSE_FAILURES) {
      startPolling();
      // Reintentar SSE periódicamente aunque estemos en polling:
      // un timer simple que evalúe cada reintento con backoff.
      retryTimer = setTimeout(() => {
        if (!running) return;
        // No matar el polling todavía: primero validar con un snapshot.
        // Si SSE vuelve, connectSSE lo reemplaza.
        sseFailures = 0;
        connectSSE();
      }, Math.min(retryDelay * 4, MAX_RETRY_MS));
      return;
    }

    const jitter = Math.random() * 500;
    const delay = Math.min(retryDelay + jitter, MAX_RETRY_MS);
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_MS);
    retryTimer = setTimeout(() => connectSSE(), delay);
  };
}

// ── API pública ─────────────────────────────────────────────────────────────

export function subscribeTelemetry(
  onSnapshot: SnapshotListener,
  onStatus: StatusListener,
): () => void {
  snapshotListeners.add(onSnapshot);
  statusListeners.add(onStatus);

  if (lastSnapshot) onSnapshot(lastSnapshot);
  onStatus({ ...status });

  if (!running) {
    running = true;
    connectSSE();
  }

  return () => {
    snapshotListeners.delete(onSnapshot);
    statusListeners.delete(onStatus);
    if (snapshotListeners.size === 0 && statusListeners.size === 0) {
      stopAll();
    }
  };
}

export function getTelemetrySnapshot(): TelemetrySnapshot | null {
  return lastSnapshot;
}
