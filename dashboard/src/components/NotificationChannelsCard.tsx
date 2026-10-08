import React, { useState, useEffect } from 'react';
import './ComponentCard.css';
import { useDashboardContext } from '../context/DashboardContext';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  BellRing,
  MessageSquare,
  Send,
  Mail,
  Settings,
} from 'lucide-react';

export const NotificationChannelsCard: React.FC = () => {
  const { config, refresh, setShowSettings } = useDashboardContext();
  const form = config?.form;

  const [whatsappActive, setWhatsappActive] = useState<boolean>(true);
  const [telegramActive, setTelegramActive] = useState<boolean>(false);
  const [emailActive, setEmailActive] = useState<boolean>(false);
  const [updating, setUpdating] = useState<string | null>(null);

  useEffect(() => {
    if (form) {
      setWhatsappActive(form.whatsapp_enabled !== false); // default true
      setTelegramActive(Boolean(form.telegram_enabled));
      setEmailActive(Boolean(form.email_alerts_enabled));
    }
  }, [form]);

  const toggleChannel = async (channel: 'whatsapp' | 'telegram' | 'email', nextVal: boolean) => {
    setUpdating(channel);
    try {
      const payload: any = {};
      if (channel === 'whatsapp') payload.whatsapp_enabled = nextVal;
      if (channel === 'telegram') payload.telegram_enabled = nextVal;
      if (channel === 'email') payload.email_alerts_enabled = nextVal;

      const res = await dashboardService.updateNotificationChannels(payload);
      if (res?.ok) {
        if (channel === 'whatsapp') setWhatsappActive(nextVal);
        if (channel === 'telegram') setTelegramActive(nextVal);
        if (channel === 'email') setEmailActive(nextVal);

        const channelNames: Record<string, string> = {
          whatsapp: 'WhatsApp (WAHA)',
          telegram: 'Telegram Bot',
          email: 'Correo Electrónico (SMTP)',
        };
        toast.success(`${channelNames[channel]} ${nextVal ? 'activado' : 'desactivado'} para alertas.`);
        refresh();
      } else {
        toast.error('Error al actualizar canal de notificación');
      }
    } catch (e: any) {
      toast.error('Error: ' + (e.message || String(e)));
    } finally {
      setUpdating(null);
    }
  };

  const activeCount = [whatsappActive, telegramActive, emailActive].filter(Boolean).length;

  return (
    <div
      className="component-card"
      style={{
        margin: '0 24px 30px',
        background: 'linear-gradient(135deg, rgba(8, 14, 30, 0.9), rgba(12, 22, 45, 0.85))',
        border: '1px solid var(--border-card)',
        borderRadius: '14px',
        padding: '20px 24px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.2), rgba(59, 130, 246, 0.25))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--cyan-accent)',
              border: '1px solid rgba(0, 229, 255, 0.3)',
            }}
          >
            <BellRing size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#fff' }}>
                Canales de Despacho de Notificaciones y Alertas
              </h3>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '12px',
                  background: activeCount > 0 ? 'rgba(46, 204, 113, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  color: activeCount > 0 ? 'var(--green-healthy)' : 'var(--red-error)',
                  border: `1px solid ${activeCount > 0 ? 'rgba(46, 204, 113, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                }}
              >
                {activeCount > 0 ? `${activeCount} ACTIVO(S)` : 'NINGUNO ACTIVO'}
              </span>
            </div>
            <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              Selecciona a través de qué plataformas deseas recibir alertas de seguridad en tiempo real. Puedes activar uno o varios simultáneamente.
            </p>
          </div>
        </div>

        <button
          type="button"
          className="action-pill-btn"
          onClick={() => setShowSettings(true)}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
        >
          <Settings size={13} />
          <span>Configurar Destinatarios</span>
        </button>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '14px',
          marginTop: '12px',
        }}
      >
        {/* Canal 1: WhatsApp */}
        <div
          style={{
            background: whatsappActive ? 'rgba(37, 211, 102, 0.06)' : 'rgba(255, 255, 255, 0.02)',
            border: `1px solid ${whatsappActive ? 'rgba(37, 211, 102, 0.3)' : 'rgba(255, 255, 255, 0.08)'}`,
            borderRadius: '10px',
            padding: '14px 16px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: 'rgba(37, 211, 102, 0.15)',
                  color: '#25d366',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <MessageSquare size={16} />
              </div>
              <div>
                <strong style={{ fontSize: '13px', color: '#fff' }}>WhatsApp (WAHA)</strong>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {form?.admin_phone ? `Destino: +${form.admin_phone}` : 'Número no configurado'}
                </div>
              </div>
            </div>

            <label className="switch" style={{ position: 'relative', display: 'inline-block', width: '42px', height: '22px' }}>
              <input
                type="checkbox"
                checked={whatsappActive}
                disabled={updating === 'whatsapp'}
                onChange={(e) => toggleChannel('whatsapp', e.target.checked)}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span
                style={{
                  position: 'absolute',
                  cursor: 'pointer',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: whatsappActive ? '#25d366' : 'rgba(255,255,255,0.15)',
                  transition: '0.3s',
                  borderRadius: '22px',
                }}
              >
                <span
                  style={{
                    position: 'absolute',
                    content: '""',
                    height: '16px',
                    width: '16px',
                    left: whatsappActive ? '22px' : '3px',
                    bottom: '3px',
                    backgroundColor: '#fff',
                    transition: '0.3s',
                    borderRadius: '50%',
                  }}
                />
              </span>
            </label>
          </div>
          <div style={{ fontSize: '11px', color: whatsappActive ? '#86efac' : 'var(--text-secondary)', marginTop: '4px' }}>
            {updating === 'whatsapp' ? 'Actualizando...' : whatsappActive ? '● Despacho de alertas activo' : '○ Canal silenciado'}
          </div>
        </div>

        {/* Canal 2: Telegram */}
        <div
          style={{
            background: telegramActive ? 'rgba(0, 136, 204, 0.08)' : 'rgba(255, 255, 255, 0.02)',
            border: `1px solid ${telegramActive ? 'rgba(0, 188, 212, 0.35)' : 'rgba(255, 255, 255, 0.08)'}`,
            borderRadius: '10px',
            padding: '14px 16px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: 'rgba(0, 136, 204, 0.15)',
                  color: '#38bdf8',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Send size={16} />
              </div>
              <div>
                <strong style={{ fontSize: '13px', color: '#fff' }}>Telegram Bot</strong>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {form?.telegram_chat_id ? `Chat ID: ${form.telegram_chat_id}` : 'Pendiente de vincular'}
                </div>
              </div>
            </div>

            <label className="switch" style={{ position: 'relative', display: 'inline-block', width: '42px', height: '22px' }}>
              <input
                type="checkbox"
                checked={telegramActive}
                disabled={updating === 'telegram'}
                onChange={(e) => toggleChannel('telegram', e.target.checked)}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span
                style={{
                  position: 'absolute',
                  cursor: 'pointer',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: telegramActive ? '#00e5ff' : 'rgba(255,255,255,0.15)',
                  transition: '0.3s',
                  borderRadius: '22px',
                }}
              >
                <span
                  style={{
                    position: 'absolute',
                    content: '""',
                    height: '16px',
                    width: '16px',
                    left: telegramActive ? '22px' : '3px',
                    bottom: '3px',
                    backgroundColor: '#fff',
                    transition: '0.3s',
                    borderRadius: '50%',
                  }}
                />
              </span>
            </label>
          </div>
          <div style={{ fontSize: '11px', color: telegramActive ? '#67e8f9' : 'var(--text-secondary)', marginTop: '4px' }}>
            {updating === 'telegram' ? 'Actualizando...' : telegramActive ? '● Despacho a bot interactivo activo' : '○ Canal silenciado'}
          </div>
        </div>

        {/* Canal 3: Correo Electrónico */}
        <div
          style={{
            background: emailActive ? 'rgba(168, 85, 247, 0.08)' : 'rgba(255, 255, 255, 0.02)',
            border: `1px solid ${emailActive ? 'rgba(168, 85, 247, 0.35)' : 'rgba(255, 255, 255, 0.08)'}`,
            borderRadius: '10px',
            padding: '14px 16px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: 'rgba(168, 85, 247, 0.15)',
                  color: '#c084fc',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Mail size={16} />
              </div>
              <div>
                <strong style={{ fontSize: '13px', color: '#fff' }}>Correo Electrónico (SMTP)</strong>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {form?.admin_email ? `Destino: ${form.admin_email}` : 'Sin destinatario'}
                </div>
              </div>
            </div>

            <label className="switch" style={{ position: 'relative', display: 'inline-block', width: '42px', height: '22px' }}>
              <input
                type="checkbox"
                checked={emailActive}
                disabled={updating === 'email'}
                onChange={(e) => toggleChannel('email', e.target.checked)}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span
                style={{
                  position: 'absolute',
                  cursor: 'pointer',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: emailActive ? '#a855f7' : 'rgba(255,255,255,0.15)',
                  transition: '0.3s',
                  borderRadius: '22px',
                }}
              >
                <span
                  style={{
                    position: 'absolute',
                    content: '""',
                    height: '16px',
                    width: '16px',
                    left: emailActive ? '22px' : '3px',
                    bottom: '3px',
                    backgroundColor: '#fff',
                    transition: '0.3s',
                    borderRadius: '50%',
                  }}
                />
              </span>
            </label>
          </div>
          <div style={{ fontSize: '11px', color: emailActive ? '#d8b4fe' : 'var(--text-secondary)', marginTop: '4px' }}>
            {updating === 'email' ? 'Actualizando...' : emailActive ? '● Despacho por correo activo' : '○ Canal silenciado'}
          </div>
        </div>
      </div>
    </div>
  );
};
