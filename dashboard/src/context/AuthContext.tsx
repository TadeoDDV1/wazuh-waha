/**
 * AuthContext — gate de sesión del dashboard.
 *
 * Estados: checking (verificando cookie) → authenticated | unauthenticated.
 * Cualquier 401 del relay (interceptor en api.ts / telemetryService) dispara
 * notifyAuthExpired() y vuelve a mostrar el login.
 */
import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  fetchSession,
  login as apiLogin,
  logout as apiLogout,
  onAuthExpired,
  type AuthScope,
} from '../services/authService';

interface AuthContextValue {
  status: 'checking' | 'authenticated' | 'unauthenticated';
  scope: AuthScope | null;
  login: (apiKey: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<AuthContextValue['status']>('checking');
  const [scope, setScope] = useState<AuthScope | null>(null);

  useEffect(() => {
    let alive = true;
    fetchSession()
      .then((info) => {
        if (!alive) return;
        if (info.authenticated) {
          setScope(info.scope ?? null);
          setStatus('authenticated');
        } else {
          setStatus('unauthenticated');
        }
      })
      .catch(() => {
        if (alive) setStatus('unauthenticated');
      });

    const off = onAuthExpired(() => {
      setStatus('unauthenticated');
      setScope(null);
    });
    return () => {
      alive = false;
      off();
    };
  }, []);

  const login = useCallback(async (apiKey: string) => {
    const res = await apiLogin(apiKey);
    setScope(res.scope);
    setStatus('authenticated');
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setStatus('unauthenticated');
    setScope(null);
  }, []);

  return (
    <AuthContext.Provider value={{ status, scope, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de AuthProvider');
  return ctx;
}
