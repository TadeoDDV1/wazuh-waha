import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react';
import './LoginScreen.css';

const LoginScreen: React.FC = () => {
  const { login } = useAuth();
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await login(apiKey.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error de autenticación');
    } finally {
      setBusy(false);
      setApiKey('');
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-icon">
          <ShieldCheck size={34} />
        </div>
        <h1 className="login-title">wazuh-waha</h1>
        <p className="login-subtitle">
          Ingresa la API key del relay para acceder al dashboard.
          La key no se almacena en el navegador: se cambia por una cookie de sesión.
        </p>

        <label className="login-label" htmlFor="api-key-input">
          API Key
        </label>
        <div className="login-input-wrap">
          <KeyRound size={16} className="login-input-icon" />
          <input
            id="api-key-input"
            className="login-input"
            type="password"
            autoComplete="current-password"
            placeholder="••••••••••••••••••••••••"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            autoFocus
          />
        </div>

        {error && <div className="login-error">{error}</div>}

        <button className="login-button" type="submit" disabled={busy || !apiKey.trim()}>
          {busy ? <Loader2 size={16} className="login-spin" /> : null}
          {busy ? 'Verificando…' : 'Iniciar sesión'}
        </button>
      </form>
    </div>
  );
};

export default LoginScreen;
