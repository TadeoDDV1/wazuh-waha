/**
 * TelemetryService — gestiona la conexión SSE al relay y el fallback a polling.
 *
 * Autenticación: cookie de sesión (BFF). Como el dashboard y la API comparten
 * origen (nginx en prod, vite proxy en dev), EventSource y fetch envían la
 * cookie automáticamente — no hay ?api_key= en URLs (quedaba en logs e
 * historial) ni X-Api-Key en headers.
 *
 * Fallback: si SSE falla 3 veces consecutivas → polling cada 3s sobre /snapshot.
 */

import type { TelemetrySnapshot, TrafficEvent, TrafficSourceInfo } from '../types/telemetry';
import { notifyAuthExpired } from './authService';

// Mismo origen SIEMPRE (nginx en prod, proxy de vite en dev): la cookie
// de sesión BFF solo fluye en same-origin y así no se necesita CORS en dev.
const API_URL = '';

const TELEMETRY_BASE = `${API_URL}/api/v1/telemetry`;

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function checkAuth(res: Response): void {
  if (res.status === 401) notifyAuthExpired();
}

// ── REST snapshot (para polling fallback) ──────────────────────────────────

export async function fetchTelemetrySnapshot(): Promise<TelemetrySnapshot> {
  const res = await fetch(`${TELEMETRY_BASE}/snapshot`, {
    headers: JSON_HEADERS,
    credentials: 'same-origin',
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Telemetry snapshot failed: ${res.status}`);
  return res.json() as Promise<TelemetrySnapshot>;
}

// ── SSE URL (la cookie va sola: mismo origen) ──────────────────────────────

export function buildSSEUrl(): string {
  return `${TELEMETRY_BASE}/stream`;
}

// ── Streaming y Tail de Todo el Tráfico de Wazuh (Terminal en Vivo) ──────────

export function buildTrafficStreamUrl(): string {
  return `${TELEMETRY_BASE}/traffic/stream`;
}

export async function fetchTrafficTail(limit: number = 100): Promise<TrafficEvent[]> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/tail?limit=${limit}`, {
    headers: JSON_HEADERS,
    credentials: 'same-origin',
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Error al consultar tail de tráfico: ${res.status}`);
  const data = await res.json();
  return (data.items || []) as TrafficEvent[];
}

export async function simulateTrafficEvent(payload: Partial<TrafficEvent> = {}): Promise<void> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/simulate`, {
    method: 'POST',
    headers: JSON_HEADERS,
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Error al simular evento: ${res.status}`);
}

export async function fetchTrafficSource(): Promise<TrafficSourceInfo> {
  const res = await fetch(`${TELEMETRY_BASE}/traffic/source`, {
    headers: JSON_HEADERS,
    credentials: 'same-origin',
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Error al consultar fuente de tráfico: ${res.status}`);
  return res.json() as Promise<TrafficSourceInfo>;
}
