/**
 * TelemetryService — gestiona la conexión SSE al relay y el fallback a polling.
 *
 * La API key se inyecta como query param porque EventSource no permite headers
 * personalizados (limitación del estándar). El relay verifica X-Api-Key en headers
 * para REST, pero aceptará ?api_key= como alternativa en el endpoint SSE.
 *
 * Fallback: si SSE falla 3 veces consecutivas → polling cada 3s sobre /snapshot.
 */

import type { TelemetrySnapshot, TrafficEvent, TrafficSourceInfo } from '../types/telemetry';

const API_URL = import.meta.env.DEV ? (import.meta.env.VITE_API_URL || 'http://localhost:8765') : '';
// Sin fallback hardcodeado: en dev usa VITE_RELAY_API_KEY; en prod nginx no inyecta
// la key (el browser solo manda ?api_key= en SSE o X-Api-Key en REST si está seteada).
const RELAY_API_KEY = import.meta.env.VITE_RELAY_API_KEY || '';

const TELEMETRY_BASE = `${API_URL}/api/v1/telemetry`;

// ── REST snapshot (para polling fallback) ──────────────────────────────────

export async function fetchTelemetrySnapshot(): Promise<TelemetrySnapshot> {
  const res = await fetch(`${TELEMETRY_BASE}/snapshot`, {
    headers: {
      'X-Api-Key': RELAY_API_KEY,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) throw new Error(`Telemetry snapshot failed: ${res.status}`);
  return res.json() as Promise<TelemetrySnapshot>;
}

// ── SSE URL (api_key como query param) ────────────────────────────────────

export function buildSSEUrl(): string {
  const params = new URLSearchParams({ api_key: RELAY_API_KEY });
  return `${TELEMETRY_BASE}/stream?${params.toString()}`;
}

// ── Streaming y Tail de Todo el Tráfico de Wazuh (Terminal en Vivo) ──────────

export function buildTrafficStreamUrl(): string {
  const params = new URLSearchParams({ api_key: RELAY_API_KEY });
  return `${TELEMETRY_BASE}/traffic/stream?${params.toString()}`;
}

export async function fetchTrafficTail(limit: number = 100): Promise<TrafficEvent[]> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/tail?limit=${limit}`, {
    headers: {
      'X-Api-Key': RELAY_API_KEY,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) throw new Error(`Error al consultar tail de tráfico: ${res.status}`);
  const data = await res.json();
  return (data.items || []) as TrafficEvent[];
}

export async function simulateTrafficEvent(payload: Partial<TrafficEvent> = {}): Promise<void> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/simulate`, {
    method: 'POST',
    headers: {
      'X-Api-Key': RELAY_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Error al simular evento: ${res.status}`);
}

export async function fetchTrafficSource(): Promise<TrafficSourceInfo> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/source`, {
    headers: {
      'X-Api-Key': RELAY_API_KEY,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) throw new Error(`Error al consultar fuente de tráfico: ${res.status}`);
  return res.json() as Promise<TrafficSourceInfo>;
}

