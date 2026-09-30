/**
 * authService — BFF de sesión.
 *
 * La API key NUNCA se guarda en el bundle: se ingresa una sola vez en el
 * login y el relay devuelve una cookie HttpOnly (ww_session). El browser no
 * puede leerla ni reenviarla en otro origen (SameSite=Strict).
 */

// Mismo origen SIEMPRE (nginx en prod, proxy de vite en dev): la cookie
// de sesión BFF solo fluye en same-origin y así no se necesita CORS en dev.
const API_URL = '';

export type AuthScope = 'full' | 'read';

export interface SessionInfo {
  authenticated: boolean;
  scope?: AuthScope;
  expires_at?: number;
  sid?: string;
}

// Bus de eventos para que los servicios avisen cuando el relay responde 401
// (sesión expirada) y la UI muestre el login de nuevo.
const bus = new EventTarget();

export function onAuthExpired(cb: () => void): () => void {
  bus.addEventListener('expired', cb);
  return () => bus.removeEventListener('expired', cb);
}

export function notifyAuthExpired(): void {
  bus.dispatchEvent(new Event('expired'));
}

export async function fetchSession(): Promise<SessionInfo> {
  const res = await fetch(`${API_URL}/api/v1/auth/session`, {
    credentials: 'same-origin',
  });
  if (res.status === 401) return { authenticated: false };
  if (!res.ok) throw new Error(`session check failed: ${res.status}`);
  return (await res.json()) as SessionInfo;
}

export async function login(apiKey: string): Promise<{ scope: AuthScope; expiresAt: number }> {
  const res = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: apiKey }),
  });
  if (res.status === 401) throw new Error('API key inválida');
  if (res.status === 429) throw new Error('Demasiados intentos: espera un minuto');
  if (!res.ok) throw new Error(`Login falló: ${res.status}`);
  const data = await res.json();
  return { scope: data.scope, expiresAt: data.expires_at };
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API_URL}/api/v1/auth/logout`, {
      method: 'POST',
      credentials: 'same-origin',
    });
  } finally {
    notifyAuthExpired();
  }
}
