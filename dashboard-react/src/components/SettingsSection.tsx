import React, { useEffect, useState } from 'react';
import './SettingsSection.css';
import { useDashboardContext } from '../context/DashboardContext';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  Settings,
  X,
  Send,
  Save,
  AlertTriangle,
  Loader2,
  Eye,
  EyeOff,
  Server,
  MessageSquare,
  Mail,
  Brain,
  Sliders,
} from 'lucide-react';

export const SettingsSection: React.FC = () => {
  const { config, showSettings, setShowSettings, refresh } = useDashboardContext();
  const form = config?.form;

  type TabType = 'wazuh' | 'whatsapp' | 'email' | 'ai' | 'relay';
  const [activeTab, setActiveTab] = useState<TabType>('wazuh');
  const [values, setValues] = useState<Record<string, string>>({});
  const [provider, setProvider] = useState('smtp');
  const [autoReconcile, setAutoReconcile] = useState(false);
  const [ollamaEnabled, setOllamaEnabled] = useState(false);
  const [wazuhVerifyTls, setWazuhVerifyTls] = useState(false);
  const [smtpTls, setSmtpTls] = useState(true);

  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [testingWhatsApp, setTestingWhatsApp] = useState(false);
  const [testingWazuh, setTestingWazuh] = useState(false);
  const [needRestart, setNeedRestart] = useState(false);

  useEffect(() => {
    if (!form) return;
    setValues({
      // Wazuh & Network
      WAZUH_SERVER_IP: form.wazuh_server_ip || '',
      WAZUH_SERVER_IP_FALLBACK: form.wazuh_server_ip_fallback || '',
      WAZUH_MANAGER_API_PORT: String(form.wazuh_manager_api_port ?? '55000'),
      WAZUH_MANAGER_API_USER: form.wazuh_manager_api_user || 'wazuh',
      WAZUH_MANAGER_API_PASS: '',
      // WhatsApp & WAHA
      ADMIN_PHONE: form.admin_phone || '',
      WAHA_HOST: form.waha_host || 'http://localhost:3000',
      WAHA_SESSION: form.waha_session || 'default',
      WAHA_API_KEY: '',
      WAHA_LOG_LEVEL: form.waha_log_level || 'info',
      WAHA_HOOK_URL: form.waha_hook_url || '',
      WAHA_RECOVERY_COOLDOWN_SEC: String(form.waha_recovery_cooldown_sec ?? '300'),
      WAHA_RECOVERY_MAX_WAIT_SEC: String(form.waha_recovery_max_wait_sec ?? '60'),
      WAHA_WATCHDOG_INTERVAL_SEC: String(form.waha_watchdog_interval_sec ?? '300'),
      // Email
      SMTP_HOST: form.smtp_host || '',
      SMTP_PORT: String(form.smtp_port ?? '587'),
      SMTP_USER: form.smtp_user || '',
      SMTP_PASS: '',
      SMTP_FROM: form.smtp_from || '',
      SMTP_TO: form.smtp_to || '',
      HYVOR_BASE_URL: form.hyvor_base_url || '',
      HYVOR_API_KEY: '',
      HYVOR_FROM: form.hyvor_from || '',
      HYVOR_TO: form.hyvor_to || '',
      // AI
      OLLAMA_HOST: form.ollama_host || 'http://localhost:11434',
      OLLAMA_MODEL: form.ollama_model || 'qwen2.5:0.5b',
      OLLAMA_TIMEOUT: String(form.ollama_timeout ?? '10'),
      // Relay
      RELAY_PORT: String(form.relay_port ?? '8765'),
      RELAY_DEDUP_TTL: String(form.relay_dedup_ttl ?? '300'),
      RELAY_MIN_LEVEL_UNKNOWN: String(form.relay_min_level_unknown ?? '10'),
      RELAY_WORKERS: String(form.relay_workers ?? '2'),
    });

    setProvider(form.email_provider || 'smtp');
    setAutoReconcile(Boolean(form.auto_reconcile));
    setOllamaEnabled(Boolean(form.ollama_enabled));
    setWazuhVerifyTls(Boolean(form.wazuh_manager_api_verify_tls));
    setSmtpTls(form.smtp_tls !== false);
  }, [form]);

  if (!showSettings) return null;

  const handleChange = (key: string, val: string) => {
    setValues((prev) => ({ ...prev, [key]: val }));
  };

  const togglePasswordVisibility = (field: string) => {
    setShowPasswords((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      const payload: Record<string, string> = {
        // Wazuh
        WAZUH_SERVER_IP: values.WAZUH_SERVER_IP || '',
        WAZUH_SERVER_IP_FALLBACK: values.WAZUH_SERVER_IP_FALLBACK || '',
        AUTO_RECONCILE: autoReconcile ? '1' : '0',
        WAZUH_MANAGER_API_PORT: values.WAZUH_MANAGER_API_PORT || '55000',
        WAZUH_MANAGER_API_USER: values.WAZUH_MANAGER_API_USER || 'wazuh',
        WAZUH_MANAGER_API_VERIFY_TLS: wazuhVerifyTls ? 'true' : 'false',

        // WhatsApp & WAHA
        ADMIN_PHONE: values.ADMIN_PHONE || '',
        WAHA_HOST: values.WAHA_HOST || 'http://localhost:3000',
        WAHA_SESSION: values.WAHA_SESSION || 'default',
        WAHA_LOG_LEVEL: values.WAHA_LOG_LEVEL || 'info',
        WAHA_HOOK_URL: values.WAHA_HOOK_URL || '',
        WAHA_RECOVERY_COOLDOWN_SEC: values.WAHA_RECOVERY_COOLDOWN_SEC || '300',
        WAHA_RECOVERY_MAX_WAIT_SEC: values.WAHA_RECOVERY_MAX_WAIT_SEC || '60',
        WAHA_WATCHDOG_INTERVAL_SEC: values.WAHA_WATCHDOG_INTERVAL_SEC || '300',

        // Email
        EMAIL_PROVIDER: provider,
        SMTP_HOST: values.SMTP_HOST || '',
        SMTP_PORT: values.SMTP_PORT || '587',
        SMTP_USER: values.SMTP_USER || '',
        SMTP_FROM: values.SMTP_FROM || '',
        SMTP_TO: values.SMTP_TO || '',
        SMTP_TLS: smtpTls ? 'true' : 'false',
        HYVOR_BASE_URL: values.HYVOR_BASE_URL || '',
        HYVOR_FROM: values.HYVOR_FROM || '',
        HYVOR_TO: values.HYVOR_TO || '',

        // AI
        OLLAMA_ENABLED: ollamaEnabled ? 'true' : 'false',
        OLLAMA_HOST: values.OLLAMA_HOST || 'http://localhost:11434',
        OLLAMA_MODEL: values.OLLAMA_MODEL || 'qwen2.5:0.5b',
        OLLAMA_TIMEOUT: values.OLLAMA_TIMEOUT || '10',

        // Relay
        RELAY_PORT: values.RELAY_PORT || '8765',
        RELAY_DEDUP_TTL: values.RELAY_DEDUP_TTL || '300',
        RELAY_MIN_LEVEL_UNKNOWN: values.RELAY_MIN_LEVEL_UNKNOWN || '10',
        RELAY_WORKERS: values.RELAY_WORKERS || '2',
      };

      // Incluir contraseñas solo si se ingresó un nuevo valor
      if (values.WAZUH_MANAGER_API_PASS) payload.WAZUH_MANAGER_API_PASS = values.WAZUH_MANAGER_API_PASS;
      if (values.WAHA_API_KEY) payload.WAHA_API_KEY = values.WAHA_API_KEY;
      if (values.SMTP_PASS) payload.SMTP_PASS = values.SMTP_PASS;
      if (values.HYVOR_API_KEY) payload.HYVOR_API_KEY = values.HYVOR_API_KEY;

      const res = await dashboardService.updateConfigBatch(payload);

      if (res.ok) {
        toast.success(`Configuración guardada en .env (${res.updated_count || 0} variables actualizadas)`);
        if (res.warnings && res.warnings.length > 0) {
          res.warnings.forEach((w) => toast.warning(w));
        }
        if (res.restart_recommended) {
          setNeedRestart(true);
        }
        refresh();
      } else {
        toast.error(`Error al guardar configuración: ${res.result}`);
      }
    } catch (err: any) {
      toast.error(`Fallo al enviar configuración: ${err.message || err}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTestEmail = async () => {
    setTestingEmail(true);
    try {
      const res = await dashboardService.testEmail();
      if (res.ok) {
        toast.success(`Email de prueba enviado: ${res.detail}`);
      } else {
        toast.error(`Fallo envío de email: ${res.detail}`);
      }
    } catch {
      toast.error('Error al conectar con el endpoint de test email');
    } finally {
      setTestingEmail(false);
    }
  };

  const handleTestWhatsApp = async () => {
    setTestingWhatsApp(true);
    try {
      const res = await dashboardService.testWhatsApp();
      if (res.ok) {
        toast.success(`WhatsApp de prueba enviado: ${res.detail}`);
      } else {
        toast.error(`Fallo WhatsApp: ${res.detail}`);
      }
    } catch {
      toast.error('Error al conectar con el endpoint de test WhatsApp');
    } finally {
      setTestingWhatsApp(false);
    }
  };

  const handleTestWazuh = async () => {
    setTestingWazuh(true);
    try {
      const res = await dashboardService.testWazuh();
      if (res.ok) {
        toast.success(`Wazuh alcanzable: ${res.detail}`);
      } else {
        toast.warning(`Verificación Wazuh: ${res.detail}`);
      }
    } catch {
      toast.error('Error al probar conexión con el Manager Wazuh');
    } finally {
      setTestingWazuh(false);
    }
  };

  return (
    <div className="settings-modal-overlay" onClick={() => setShowSettings(false)}>
      <div className="settings-modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="settings-modal-header">
          <div className="settings-modal-title">
            <Settings size={18} style={{ color: 'var(--cyan-accent)' }} />
            <span>Configuración del Stack Wazuh-WAHA</span>
          </div>
          <button
            className="settings-modal-close"
            onClick={() => setShowSettings(false)}
            title="Cerrar configuración"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body Form */}
        <form onSubmit={handleSave} className="settings-modal-body">
          {needRestart && (
            <div className="restart-alert-box">
              <AlertTriangle size={16} />
              <span>Se modificaron puertos o parámetros de workers. Es recomendable reiniciar el servicio relay.</span>
            </div>
          )}

          {/* Tab buttons */}
          <div className="settings-tabs">
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'wazuh' ? 'active' : ''}`}
              onClick={() => setActiveTab('wazuh')}
            >
              <Server size={14} />
              <span>Wazuh & Red</span>
            </button>
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'whatsapp' ? 'active' : ''}`}
              onClick={() => setActiveTab('whatsapp')}
            >
              <MessageSquare size={14} />
              <span>WhatsApp & WAHA</span>
            </button>
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'email' ? 'active' : ''}`}
              onClick={() => setActiveTab('email')}
            >
              <Mail size={14} />
              <span>Email Backup</span>
            </button>
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'ai' ? 'active' : ''}`}
              onClick={() => setActiveTab('ai')}
            >
              <Brain size={14} />
              <span>Ollama AI</span>
            </button>
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'relay' ? 'active' : ''}`}
              onClick={() => setActiveTab('relay')}
            >
              <Sliders size={14} />
              <span>Relay & Daemon</span>
            </button>
          </div>

          {/* Tab 1: Wazuh & Network */}
          {activeTab === 'wazuh' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Servidor Manager Wazuh</h3>
                <span className="block-tag">Fuente de Verdad (.env)</span>
              </div>
              <p className="block-desc">
                Define las direcciones IP y credenciales de comunicación entre los agentes locales y el servidor Wazuh.
              </p>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>IP Principal del Manager (WAZUH_SERVER_IP)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="Ej. 192.168.1.72"
                    value={values.WAZUH_SERVER_IP || ''}
                    onChange={(e) => handleChange('WAZUH_SERVER_IP', e.target.value)}
                  />
                  <span className="field-hint">IP única donde corre el Wazuh Manager</span>
                </div>

                <div className="field-group">
                  <label>IPs Candidatas Fallback (WAZUH_SERVER_IP_FALLBACK)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="Ej. 172.44.30.5, 192.168.1.80"
                    value={values.WAZUH_SERVER_IP_FALLBACK || ''}
                    onChange={(e) => handleChange('WAZUH_SERVER_IP_FALLBACK', e.target.value)}
                  />
                  <span className="field-hint">Separadas por coma si la IP principal cambia</span>
                </div>
              </div>

              <div className="checkbox-row highlight-box">
                <input
                  type="checkbox"
                  id="auto_reconcile"
                  checked={autoReconcile}
                  onChange={(e) => setAutoReconcile(e.target.checked)}
                />
                <label htmlFor="auto_reconcile">
                  <strong>Auto-reconciliación de IP (AUTO_RECONCILE)</strong>
                  <br />
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Actualiza automáticamente <code>ossec.conf</code> del agente cuando el watchdog detecte cambio de IP.
                  </span>
                </label>
              </div>

              <h4 className="sub-title">API REST del Manager (Reporte de Eventos)</h4>
              <div className="field-grid-3">
                <div className="field-group">
                  <label>Puerto API</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="55000"
                    value={values.WAZUH_MANAGER_API_PORT || ''}
                    onChange={(e) => handleChange('WAZUH_MANAGER_API_PORT', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Usuario API</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="wazuh"
                    value={values.WAZUH_MANAGER_API_USER || ''}
                    onChange={(e) => handleChange('WAZUH_MANAGER_API_USER', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Contraseña API</label>
                  <div className="field-input-wrapper">
                    <input
                      type={showPasswords.WAZUH_MANAGER_API_PASS ? 'text' : 'password'}
                      className="field-input"
                      placeholder={form?.wazuh_manager_api_pass_set ? '•••••••• (guardada)' : 'Pass API'}
                      value={values.WAZUH_MANAGER_API_PASS || ''}
                      onChange={(e) => handleChange('WAZUH_MANAGER_API_PASS', e.target.value)}
                    />
                    <button
                      type="button"
                      className="password-toggle-btn"
                      onClick={() => togglePasswordVisibility('WAZUH_MANAGER_API_PASS')}
                    >
                      {showPasswords.WAZUH_MANAGER_API_PASS ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="checkbox-row">
                <input
                  type="checkbox"
                  id="wazuh_verify_tls"
                  checked={wazuhVerifyTls}
                  onChange={(e) => setWazuhVerifyTls(e.target.checked)}
                />
                <label htmlFor="wazuh_verify_tls">Verificar certificado TLS en API Wazuh (WAZUH_MANAGER_API_VERIFY_TLS)</label>
              </div>
            </div>
          )}

          {/* Tab 2: WhatsApp & WAHA */}
          {activeTab === 'whatsapp' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Integración con WhatsApp (WAHA)</h3>
                <span className="block-tag">Gateway</span>
              </div>
              <p className="block-desc">
                Configura el número destinatario de las alertas de seguridad y la conexión con el contenedor WAHA.
              </p>

              <div className="field-group">
                <label>Número WhatsApp Destino (ADMIN_PHONE)</label>
                <div className="field-input-wrapper">
                  <input
                    type="text"
                    className="field-input"
                    placeholder="Ej. 5219991234567 (código de país + número, sin +)"
                    value={values.ADMIN_PHONE || ''}
                    onChange={(e) => handleChange('ADMIN_PHONE', e.target.value)}
                  />
                </div>
                <span className="field-hint">
                  Formato E.164 sin el signo +. Ejemplo para México: <code>521</code> + 10 dígitos.
                </span>
              </div>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>Host WAHA (WAHA_HOST)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="http://localhost:3000"
                    value={values.WAHA_HOST || ''}
                    onChange={(e) => handleChange('WAHA_HOST', e.target.value)}
                  />
                </div>

                <div className="field-group">
                  <label>Nombre de Sesión (WAHA_SESSION)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="default"
                    value={values.WAHA_SESSION || ''}
                    onChange={(e) => handleChange('WAHA_SESSION', e.target.value)}
                  />
                </div>
              </div>

              <div className="field-group">
                <label>WAHA API Key (WAHA_API_KEY)</label>
                <div className="field-input-wrapper">
                  <input
                    type={showPasswords.WAHA_API_KEY ? 'text' : 'password'}
                    className="field-input"
                    placeholder={form?.waha_api_key_set ? '•••••••• (guardada)' : 'API Key de WAHA'}
                    value={values.WAHA_API_KEY || ''}
                    onChange={(e) => handleChange('WAHA_API_KEY', e.target.value)}
                  />
                  <button
                    type="button"
                    className="password-toggle-btn"
                    onClick={() => togglePasswordVisibility('WAHA_API_KEY')}
                  >
                    {showPasswords.WAHA_API_KEY ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <h4 className="sub-title">Watchdog & Auto-recuperación de Sesión</h4>
              <div className="field-grid-3">
                <div className="field-group">
                  <label>Intervalo Watchdog (seg)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="300"
                    value={values.WAHA_WATCHDOG_INTERVAL_SEC || ''}
                    onChange={(e) => handleChange('WAHA_WATCHDOG_INTERVAL_SEC', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Cooldown Recovery (seg)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="300"
                    value={values.WAHA_RECOVERY_COOLDOWN_SEC || ''}
                    onChange={(e) => handleChange('WAHA_RECOVERY_COOLDOWN_SEC', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Max Wait Recovery (seg)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="60"
                    value={values.WAHA_RECOVERY_MAX_WAIT_SEC || ''}
                    onChange={(e) => handleChange('WAHA_RECOVERY_MAX_WAIT_SEC', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Email Backup */}
          {activeTab === 'email' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Canal de Respaldo por Correo Electrónico</h3>
                <span className="block-tag">Fallback</span>
              </div>

              <div className="field-group">
                <label>Proveedor de Email (EMAIL_PROVIDER)</label>
                <select
                  className="field-input"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                >
                  <option value="smtp">SMTP Directo (Gmail, Outlook, SendGrid, etc.)</option>
                  <option value="hyvor_relay">Hyvor Relay (API self-hosted)</option>
                  <option value="none">Desactivado (Solo WhatsApp)</option>
                </select>
              </div>

              {provider === 'smtp' && (
                <>
                  <div className="field-grid-2">
                    <div className="field-group">
                      <label>Servidor SMTP (Host)</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="smtp.gmail.com"
                        value={values.SMTP_HOST || ''}
                        onChange={(e) => handleChange('SMTP_HOST', e.target.value)}
                      />
                    </div>
                    <div className="field-group">
                      <label>Puerto SMTP</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="587"
                        value={values.SMTP_PORT || ''}
                        onChange={(e) => handleChange('SMTP_PORT', e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="field-grid-2">
                    <div className="field-group">
                      <label>Usuario SMTP</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="tu-correo@gmail.com"
                        value={values.SMTP_USER || ''}
                        onChange={(e) => handleChange('SMTP_USER', e.target.value)}
                      />
                    </div>
                    <div className="field-group">
                      <label>Contraseña / App Password</label>
                      <div className="field-input-wrapper">
                        <input
                          type={showPasswords.SMTP_PASS ? 'text' : 'password'}
                          className="field-input"
                          placeholder={form?.smtp_pass_set ? '•••••••• (guardada)' : 'Contraseña de app'}
                          value={values.SMTP_PASS || ''}
                          onChange={(e) => handleChange('SMTP_PASS', e.target.value)}
                        />
                        <button
                          type="button"
                          className="password-toggle-btn"
                          onClick={() => togglePasswordVisibility('SMTP_PASS')}
                        >
                          {showPasswords.SMTP_PASS ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="field-grid-2">
                    <div className="field-group">
                      <label>Email Remitente (From)</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="wazuh-alerts@tudominio.com"
                        value={values.SMTP_FROM || ''}
                        onChange={(e) => handleChange('SMTP_FROM', e.target.value)}
                      />
                    </div>
                    <div className="field-group">
                      <label>Email Destino (To)</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="admin@tudominio.com"
                        value={values.SMTP_TO || ''}
                        onChange={(e) => handleChange('SMTP_TO', e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="checkbox-row">
                    <input
                      type="checkbox"
                      id="smtp_tls"
                      checked={smtpTls}
                      onChange={(e) => setSmtpTls(e.target.checked)}
                    />
                    <label htmlFor="smtp_tls">Habilitar STARTTLS / TLS seguro (SMTP_TLS)</label>
                  </div>
                </>
              )}

              {provider === 'hyvor_relay' && (
                <>
                  <div className="field-grid-2">
                    <div className="field-group">
                      <label>Hyvor Base URL</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="https://relay.tudominio.com"
                        value={values.HYVOR_BASE_URL || ''}
                        onChange={(e) => handleChange('HYVOR_BASE_URL', e.target.value)}
                      />
                    </div>
                    <div className="field-group">
                      <label>Hyvor API Key</label>
                      <div className="field-input-wrapper">
                        <input
                          type={showPasswords.HYVOR_API_KEY ? 'text' : 'password'}
                          className="field-input"
                          placeholder={form?.hyvor_api_key_set ? '•••••••• (guardada)' : 'API Key'}
                          value={values.HYVOR_API_KEY || ''}
                          onChange={(e) => handleChange('HYVOR_API_KEY', e.target.value)}
                        />
                        <button
                          type="button"
                          className="password-toggle-btn"
                          onClick={() => togglePasswordVisibility('HYVOR_API_KEY')}
                        >
                          {showPasswords.HYVOR_API_KEY ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="field-grid-2">
                    <div className="field-group">
                      <label>Hyvor Remitente (From)</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="alerts@tudominio.com"
                        value={values.HYVOR_FROM || ''}
                        onChange={(e) => handleChange('HYVOR_FROM', e.target.value)}
                      />
                    </div>
                    <div className="field-group">
                      <label>Hyvor Destino (To)</label>
                      <input
                        type="text"
                        className="field-input"
                        placeholder="admin@tudominio.com"
                        value={values.HYVOR_TO || ''}
                        onChange={(e) => handleChange('HYVOR_TO', e.target.value)}
                      />
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Tab 4: AI (Ollama) */}
          {activeTab === 'ai' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Resumen & Análisis con Inteligencia Artificial (Ollama)</h3>
                <span className="block-tag">Local LLM</span>
              </div>
              <p className="block-desc">
                Ollama permite generar resúmenes contextuales en lenguaje natural para alertas de severidad crítica.
              </p>

              <div className="checkbox-row highlight-box">
                <input
                  type="checkbox"
                  id="ollama_enabled"
                  checked={ollamaEnabled}
                  onChange={(e) => setOllamaEnabled(e.target.checked)}
                />
                <label htmlFor="ollama_enabled">
                  <strong>Activar Enriquecimiento con Ollama AI (OLLAMA_ENABLED)</strong>
                  <br />
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Desactivado por defecto para garantizar despacho en sub-segundo sin depender de GPU/CPU local.
                  </span>
                </label>
              </div>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>Host de Ollama (OLLAMA_HOST)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="http://localhost:11434"
                    value={values.OLLAMA_HOST || ''}
                    onChange={(e) => handleChange('OLLAMA_HOST', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Modelo LLM (OLLAMA_MODEL)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="qwen2.5:0.5b"
                    value={values.OLLAMA_MODEL || ''}
                    onChange={(e) => handleChange('OLLAMA_MODEL', e.target.value)}
                  />
                </div>
              </div>

              <div className="field-group">
                <label>Timeout Máximo de Inferencia (segundos)</label>
                <input
                  type="text"
                  className="field-input"
                  placeholder="10"
                  value={values.OLLAMA_TIMEOUT || ''}
                  onChange={(e) => handleChange('OLLAMA_TIMEOUT', e.target.value)}
                />
                <span className="field-hint">Si el modelo supera este tiempo, la alerta se despacha con la plantilla base de Wazuh.</span>
              </div>
            </div>
          )}

          {/* Tab 5: Relay & Daemon */}
          {activeTab === 'relay' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Parámetros del Servicio Relay</h3>
                <span className="block-tag">FastAPI Core</span>
              </div>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>Puerto HTTP de Escucha (RELAY_PORT)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="8765"
                    value={values.RELAY_PORT || ''}
                    onChange={(e) => handleChange('RELAY_PORT', e.target.value)}
                  />
                </div>
                <div className="field-group">
                  <label>Workers Uvicorn (RELAY_WORKERS)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="2"
                    value={values.RELAY_WORKERS || ''}
                    onChange={(e) => handleChange('RELAY_WORKERS', e.target.value)}
                  />
                </div>
              </div>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>TTL Deduplicación (RELAY_DEDUP_TTL seg)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="300"
                    value={values.RELAY_DEDUP_TTL || ''}
                    onChange={(e) => handleChange('RELAY_DEDUP_TTL', e.target.value)}
                  />
                  <span className="field-hint">Ventana de tiempo para evitar alertas repetidas de la misma regla</span>
                </div>
                <div className="field-group">
                  <label>Nivel Mínimo Alertas Sin Plantilla</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="10"
                    value={values.RELAY_MIN_LEVEL_UNKNOWN || ''}
                    onChange={(e) => handleChange('RELAY_MIN_LEVEL_UNKNOWN', e.target.value)}
                  />
                  <span className="field-hint">Descarta alertas de bajo nivel si no tienen formato específico</span>
                </div>
              </div>
            </div>
          )}

          {/* Footer Actions */}
          <div className="settings-modal-footer">
            <div className="footer-actions-left">
              {activeTab === 'wazuh' && (
                <button
                  type="button"
                  className="nav-btn test-btn"
                  onClick={handleTestWazuh}
                  disabled={testingWazuh}
                  title="Verificar puertos del Manager Wazuh"
                >
                  {testingWazuh ? <Loader2 size={13} className="animate-spin" /> : <Server size={13} />}
                  <span>{testingWazuh ? 'Probando...' : 'Test Conexión Wazuh'}</span>
                </button>
              )}

              {activeTab === 'whatsapp' && (
                <button
                  type="button"
                  className="nav-btn test-btn"
                  onClick={handleTestWhatsApp}
                  disabled={testingWhatsApp}
                  title="Mandar un WhatsApp de prueba al número configurado"
                >
                  {testingWhatsApp ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
                  <span>{testingWhatsApp ? 'Enviando...' : 'Test WhatsApp'}</span>
                </button>
              )}

              {activeTab === 'email' && provider !== 'none' && (
                <button
                  type="button"
                  className="nav-btn test-btn"
                  onClick={handleTestEmail}
                  disabled={testingEmail}
                  title="Enviar email de prueba con los datos guardados"
                >
                  {testingEmail ? <Loader2 size={13} className="animate-spin" /> : <Mail size={13} />}
                  <span>{testingEmail ? 'Enviando...' : 'Test de Email'}</span>
                </button>
              )}
            </div>

            <div className="footer-actions-right">
              <button
                type="button"
                className="nav-btn"
                onClick={() => setShowSettings(false)}
              >
                Cancelar
              </button>

              <button
                type="submit"
                className="nav-btn primary"
                disabled={saving}
              >
                {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                <span>{saving ? 'Guardando en .env...' : 'Guardar Todo'}</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default SettingsSection;

