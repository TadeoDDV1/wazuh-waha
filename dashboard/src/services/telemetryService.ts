/**
 * TelemetryService — gestiona la conexión SSE al relay y el fallback a polling.
 *
 * La API key se inyecta como query param porque EventSource no permite headers
 * personalizados (limitación del estándar). El relay verifica X-Api-Key en headers
 * para REST, pero aceptará ?api_key= como alternativa en el endpoint SSE.
 *
 * Fallback: si SSE falla 3 veces consecutivas → polling cada 3s sobre /snapshot.
 */

import type { TelemetrySnapshot } from '../types/telemetry';

const API_URL = import.meta.env.DEV ? (import.meta.env.VITE_API_URL || 'http://localhost:8765') : '';
const RELAY_API_KEY = import.meta.env.VITE_RELAY_API_KEY || 'f7b6d3906106ef820179e853768b8db23cb119690030d103';

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

// Nota: el hook useTelemetry usa directamente EventSource con esta URL.
// La autenticación en SSE se hace via query param porque EventSource
// no permite headers personalizados.
