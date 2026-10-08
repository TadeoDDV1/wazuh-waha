import React, { useState, useEffect, useCallback } from 'react';
import './WhatsappCard.css';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  Send,
  CheckCircle2,
  Loader2,
  ExternalLink,
  KeyRound,
  RefreshCw,
  Bell,
  X,
  Radio,
} from 'lucide-react';

interface TelegramCardProps {
  onRefreshNeeded?: () => void;
}

export const TelegramCard: React.FC<TelegramCardProps> = ({ onRefreshNeeded }) => {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [pairing, setPairing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [tokenInput, setTokenInput] = useState('');
  const [savingToken, setSavingToken] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await dashboardService.getTelegramStatus();
      setStatus(data);
    } catch (e) {
      console.error('Error fetching telegram status', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const handlePair = async () => {
    setPairing(true);
    toast.info('Iniciando vinculación... Abre Telegram y envía /start al bot.');
    try {
      const res = await dashboardService.pairTelegram();
      if (res?.ok && res?.chat_id) {
        toast.success(`¡Vinculado con éxito a ${res.first_name || 'Admin'} (Chat ID: ${res.chat_id})!`);
        await fetchStatus();
        if (onRefreshNeeded) onRefreshNeeded();
      } else if (res?.waiting) {
        toast.warning(res.instructions || 'Esperando /start... Vuelve a intentarlo tras enviar el mensaje.');
      } else {
        toast.error(res?.error || 'No se pudo detectar el mensaje.');
      }
    } catch (e: any) {
      toast.error('Error al intentar emparejar: ' + (e.message || String(e)));
    } finally {
      setPairing(false);
    }
  };

  const handleTestMessage = async () => {
    setTesting(true);
    try {
      const res = await dashboardService.testTelegram();
      if (res?.ok) {
        toast.success('¡Mensaje de prueba enviado exitosamente a Telegram!');
      } else {
        toast.error(res?.detail || 'Error al enviar mensaje de prueba');
      }
    } catch (e: any) {
      toast.error('Error al probar Telegram: ' + (e.message || String(e)));
    } finally {
      setTesting(false);
    }
  };

  const handleSaveToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) {
      toast.error('Por favor ingresa un token válido de @BotFather');
      return;
    }
    setSavingToken(true);
    try {
      const res = await dashboardService.updateConfigBatch({
        TELEGRAM_BOT_TOKEN: tokenInput.trim(),
        TELEGRAM_ENABLED: 'true',
      });
      if (res?.ok) {
        toast.success('Token guardado y Telegram habilitado.');
        setShowTokenModal(false);
        setTokenInput('');
        await fetchStatus();
        if (onRefreshNeeded) onRefreshNeeded();
      } else {
        toast.error('Error guardando token: ' + (res?.result || 'Error desconocido'));
      }
    } catch (err: any) {
      toast.error('Error al guardar token: ' + (err.message || String(err)));
    } finally {
      setSavingToken(false);
    }
  };

  const isConfigured = Boolean(status?.configured);
  const botInfo = status?.bot_info;
  const isConnected = Boolean(botInfo?.ok);
  const botUsername = botInfo?.username;
  const hasChatId = Boolean(status?.chat_id);

  return (
    <div className="component-card healthy" style={{ borderColor: isConnected ? 'rgba(0, 188, 212, 0.4)' : undefined }}>
      <div className="card-top-row">
        <div className="card-identity">
          <div className="service-icon-box" style={{ background: 'rgba(0, 136, 204, 0.15)', color: '#29b6f6' }}>
            <Send size={20} />
          </div>
          <div>
            <div className="card-title-line">
              <span className="card-title">Telegram Bot Gateway</span>
              <span
                className="status-pill healthy"
                style={{
                  background: isConnected
                    ? 'rgba(46, 204, 113, 0.15)'
                    : isConfigured
                    ? 'rgba(255, 179, 0, 0.15)'
                    : 'rgba(239, 68, 68, 0.15)',
                  color: isConnected
                    ? 'var(--green-healthy)'
                    : isConfigured
                    ? 'var(--yellow-warning)'
                    : 'var(--red-error)',
                }}
              >
                {isConnected ? '✓ CONECTADO' : isConfigured ? '⚠️ SIN VINCULAR' : '⚪ NO CONFIGURADO'}
              </span>
            </div>
            <div className="card-category">Canal de Notificaciones de Seguridad y Monitoreo Remoto</div>
          </div>
        </div>

        <button
          type="button"
          className="icon-tool-btn"
          onClick={fetchStatus}
          disabled={loading}
          title="Refrescar estado de Telegram"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="whatsapp-details-grid" style={{ marginTop: '14px' }}>
        <div className="waha-metric-box">
          <span className="waha-metric-label">Bot de Telegram</span>
          <span className="waha-metric-value" style={{ color: isConnected ? '#00e5ff' : 'var(--text-secondary)' }}>
            {botUsername ? `@${botUsername}` : isConfigured ? 'Token configurado' : 'Sin Token'}
          </span>
        </div>

        <div className="waha-metric-box">
          <span className="waha-metric-label">Chat ID de Destino</span>
          <span className="waha-metric-value" style={{ color: hasChatId ? 'var(--green-healthy)' : 'var(--yellow-warning)' }}>
            {status?.chat_id || 'No vinculado aún'}
          </span>
        </div>
      </div>

      {/* Acciones principales */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '16px' }}>
        {botUsername ? (
          <a
            href={`https://t.me/${botUsername}?start=pair`}
            target="_blank"
            rel="noreferrer"
            className="action-pill-btn"
            style={{
              background: 'rgba(0, 136, 204, 0.2)',
              borderColor: 'rgba(0, 136, 204, 0.5)',
              color: '#38bdf8',
              textDecoration: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <ExternalLink size={13} />
            <span>Abrir @{botUsername} en Telegram</span>
          </a>
        ) : null}

        <button
          type="button"
          className="action-pill-btn"
          onClick={handlePair}
          disabled={pairing || !isConfigured}
          style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.15), rgba(59, 130, 246, 0.2))',
            borderColor: 'var(--cyan-accent)',
            color: 'var(--cyan-accent)',
          }}
          title={isConfigured ? 'Esperar mensaje /start para capturar el Chat ID' : 'Configura el token primero'}
        >
          {pairing ? <Loader2 size={13} className="animate-spin" /> : <Radio size={13} />}
          <span>{pairing ? 'Detectando /start...' : '🔗 Vincular con /start'}</span>
        </button>

        <button
          type="button"
          className="action-pill-btn"
          onClick={handleTestMessage}
          disabled={testing || !hasChatId}
          style={{
            background: hasChatId ? 'rgba(46, 204, 113, 0.15)' : 'rgba(255, 255, 255, 0.05)',
            borderColor: hasChatId ? 'rgba(46, 204, 113, 0.4)' : 'rgba(255, 255, 255, 0.1)',
            color: hasChatId ? 'var(--green-healthy)' : 'var(--text-secondary)',
          }}
          title={hasChatId ? 'Enviar alerta de prueba al chat' : 'Vincula el chat antes de probar'}
        >
          {testing ? <Loader2 size={13} className="animate-spin" /> : <Bell size={13} />}
          <span>{testing ? 'Enviando...' : '📩 Enviar Alerta de Prueba'}</span>
        </button>

        <button
          type="button"
          className="action-pill-btn"
          onClick={() => setShowTokenModal(true)}
          style={{ marginLeft: 'auto' }}
        >
          <KeyRound size={13} />
          <span>{isConfigured ? 'Cambiar Token' : 'Configurar Token'}</span>
        </button>
      </div>

      {/* Instrucciones rápidas si no está vinculado */}
      {!hasChatId && (
        <div style={{
          marginTop: '12px',
          padding: '10px 12px',
          background: 'rgba(255, 179, 0, 0.08)',
          border: '1px solid rgba(255, 179, 0, 0.2)',
          borderRadius: '8px',
          fontSize: '11px',
          color: 'var(--yellow-warning)',
          lineHeight: '1.4',
        }}>
          💡 <strong>Pasos para vincular:</strong> 1. Si aún no tienes bot, créalo con @BotFather en Telegram y copia el token aquí. 2. Presiona <strong>"🔗 Vincular con /start"</strong>. 3. En Telegram abre tu bot y dale a <strong>Iniciar (/start)</strong>. ¡El relay detectará tu cuenta automáticamente!
        </div>
      )}

      {/* Modal para configurar Token de Telegram */}
      {showTokenModal && (
        <div className="qr-modal-overlay" onClick={() => setShowTokenModal(false)}>
          <div className="qr-modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
            <div className="qr-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <KeyRound size={18} style={{ color: 'var(--cyan-accent)' }} />
                <h3>Token del Bot de Telegram</h3>
              </div>
              <button
                type="button"
                className="qr-close-btn"
                onClick={() => setShowTokenModal(false)}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveToken} style={{ padding: '16px 20px' }}>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '14px', lineHeight: '1.5' }}>
                Copia el token que te dio <strong>@BotFather</strong> (ej: <code>7123456789:ABCDefGhI...</code>). Este token se guardará de forma segura en el archivo <code>.env</code> del servidor.
              </p>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                  TELEGRAM_BOT_TOKEN
                </label>
                <input
                  type="text"
                  className="field-input"
                  placeholder="123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: 'rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-card)',
                    borderRadius: '6px',
                    color: '#fff',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                  }}
                  autoFocus
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  className="nav-btn"
                  onClick={() => setShowTokenModal(false)}
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="nav-btn primary"
                  disabled={savingToken}
                >
                  {savingToken ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                  <span>Guardar Token</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
