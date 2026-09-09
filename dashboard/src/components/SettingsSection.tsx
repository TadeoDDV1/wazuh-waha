import React, { useState, useEffect } from 'react';
import './SettingsSection.css';
import { useDashboardContext } from '../context/DashboardContext';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  Settings,
  Server,
  MessageSquare,
  Mail,
  Brain,
  Terminal,
  X,
  Eye,
  EyeOff,
  AlertTriangle,
  Loader2,
  Save,
  Info,
} from 'lucide-react';

export const SettingsSection: React.FC = () => {
  const { config, setShowSettings, refresh } = useDashboardContext();
  const form = config?.form;

  type TabType = 'wazuh' | 'whatsapp' | 'email' | 'ai' | 'logs';
  const [activeTab, setActiveTab] = useState<TabType>('wazuh');
  const [values, setValues] = useState<Record<string, string>>({});
  const [autoReconcile, setAutoReconcile] = useState(false);
  const [ollamaEnabled, setOllamaEnabled] = useState(false);
  const [wazuhVerifyTls, setWazuhVerifyTls] = useState(false);
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [testingWazuh, setTestingWazuh] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [needRestart, setNeedRestart] = useState(false);

  const [logsOutput, setLogsOutput] = useState<string>('');
  const [loadingLogs, setLoadingLogs] = useState(false);

  useEffect(() => {
    if (!form) return;
    setValues({
      // Wazuh & Network
      WAZUH_SERVER_IP: form.wazuh_server_ip || '',
      WAZUH_SERVER_IP_FALLBACK: form.wazuh_server_ip_fallback || '',
      WAZUH_MANAGER_API_PORT: String(form.wazuh_manager_api_port ?? '55000'),
      WAZUH_MANAGER_API_USER: form.wazuh_manager_api_user || 'wazuh',
      WAZUH_MANAGER_API_PASS: '',

      // WhatsApp & WAHA (solo watchdog y autorecuperación)
      WAHA_RECOVERY_COOLDOWN_SEC: String(form.waha_recovery_cooldown_sec ?? '300'),
      WAHA_RECOVERY_MAX_WAIT_SEC: String(form.waha_recovery_max_wait_sec ?? '60'),
      WAHA_WATCHDOG_INTERVAL_SEC: String(form.waha_watchdog_interval_sec ?? '300'),

      // Email (solo destinatario)
      ADMIN_EMAIL: form.admin_email || '',

      // AI
      OLLAMA_HOST: form.ollama_host || 'http://localhost:11434',
      OLLAMA_MODEL: form.ollama_model || 'qwen2.5:0.5b',
      OLLAMA_TIMEOUT: String(form.ollama_timeout ?? '10'),
    });

    setAutoReconcile(Boolean(form.auto_reconcile));
    setOllamaEnabled(Boolean(form.ollama_enabled));
    setWazuhVerifyTls(Boolean(form.wazuh_manager_api_verify_tls));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form ? JSON.stringify(form) : null]);

  useEffect(() => {
    if (activeTab === 'logs') {
      const fetchLogs = async () => {
        setLoadingLogs(true);
        try {
          const res = await dashboardService.getLogs(100);
          setLogsOutput(res.logs || 'No logs available');
        } catch (err) {
          setLogsOutput('Error al consultar logs: ' + String(err));
        } finally {
          setLoadingLogs(false);
        }
      };
      fetchLogs();
      const interval = setInterval(fetchLogs, 5000);
      return () => clearInterval(interval);
    }
  }, [activeTab]);

  const togglePasswordVisibility = (field: string) => {
    setShowPasswords((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  const handleChange = (field: string, val: string) => {
    setValues((prev) => ({ ...prev, [field]: val }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload: Record<string, any> = {
        // Wazuh & Network
        WAZUH_SERVER_IP: values.WAZUH_SERVER_IP || '',
        WAZUH_SERVER_IP_FALLBACK: values.WAZUH_SERVER_IP_FALLBACK || '',
        AUTO_RECONCILE: autoReconcile ? '1' : '0',
        WAZUH_MANAGER_API_PORT: values.WAZUH_MANAGER_API_PORT || '55000',
        WAZUH_MANAGER_API_USER: values.WAZUH_MANAGER_API_USER || 'wazuh',
        WAZUH_MANAGER_API_VERIFY_TLS: wazuhVerifyTls ? 'true' : 'false',

        // WhatsApp Watchdog / Recovery
        WAHA_WATCHDOG_INTERVAL_SEC: values.WAHA_WATCHDOG_INTERVAL_SEC || '300',
        WAHA_RECOVERY_COOLDOWN_SEC: values.WAHA_RECOVERY_COOLDOWN_SEC || '300',
        WAHA_RECOVERY_MAX_WAIT_SEC: values.WAHA_RECOVERY_MAX_WAIT_SEC || '60',

        // Email Destinatario
        ADMIN_EMAIL: values.ADMIN_EMAIL || '',

        // AI
        OLLAMA_ENABLED: ollamaEnabled ? 'true' : 'false',
        OLLAMA_HOST: values.OLLAMA_HOST || 'http://localhost:11434',
        OLLAMA_MODEL: values.OLLAMA_MODEL || 'qwen2.5:0.5b',
        OLLAMA_TIMEOUT: values.OLLAMA_TIMEOUT || '10',
      };

      if (values.WAZUH_MANAGER_API_PASS) payload.WAZUH_MANAGER_API_PASS = values.WAZUH_MANAGER_API_PASS;

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

  const handleTestWazuh = async () => {
    setTestingWazuh(true);
    try {
      const res = await dashboardService.testWazuh();
      if (res.ok) {
        toast.success(
          `Conexión Wazuh OK. API (${res.api_port_ok ? '55000 ✓' : '55000 ✗'}), Agent (${res.agent_port_ok ? '1514 ✓' : '1514 ✗'})`
        );
      } else {
        toast.error(`Fallo al probar puertos Wazuh: ${res.detail}`);
      }
    } catch {
      toast.error('Error al conectar con el endpoint de test Wazuh');
    } finally {
      setTestingWazuh(false);
    }
  };

  const handleTestEmail = async () => {
    setTestingEmail(true);
    try {
      const res = await dashboardService.testEmail();
      if (res.ok) {
        toast.success(`Correo enviado: ${res.detail}`);
      } else {
        toast.error(`Fallo al enviar correo: ${res.detail}`);
      }
    } catch {
      toast.error('Error al conectar con el endpoint de test de correo');
    } finally {
      setTestingEmail(false);
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
              <span>Se modificaron parámetros del stack. Es recomendable reiniciar el servicio relay.</span>
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
              className={`settings-tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
              onClick={() => setActiveTab('logs')}
            >
              <Terminal size={14} />
              <span>Logs del Sistema</span>
            </button>
          </div>

          {/* Tab 1: Wazuh & Network */}
          {activeTab === 'wazuh' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Servidor Wazuh Manager & API</h3>
                <span className="block-tag">Core</span>
              </div>
              <p className="block-desc">
                Dirección IP y credenciales de acceso para el Manager Wazuh y el registro de agentes.
              </p>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>IP Principal del Manager (WAZUH_SERVER_IP)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="192.168.1.100"
                    value={values.WAZUH_SERVER_IP || ''}
                    onChange={(e) => handleChange('WAZUH_SERVER_IP', e.target.value)}
                  />
                  <span className="field-hint">IP donde escucha el demonio del Manager Wazuh</span>
                </div>

                <div className="field-group">
                  <label>IP Fallback (WAZUH_SERVER_IP_FALLBACK)</label>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="192.168.1.101,10.0.0.5"
                    value={values.WAZUH_SERVER_IP_FALLBACK || ''}
                    onChange={(e) => handleChange('WAZUH_SERVER_IP_FALLBACK', e.target.value)}
                  />
                  <span className="field-hint">IPs candidatas si la principal no responde</span>
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
                  Auto-reconciliar IP si se detecta drift (AUTO_RECONCILE)
                  <span className="field-hint">Actualiza ossec.conf automáticamente ante cambio de IP</span>
                </label>
              </div>

              <h4 className="sub-title">Credenciales API de Wazuh</h4>
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
                      placeholder={form?.wazuh_manager_api_pass_set ? '•••••••• (guardada)' : 'Nueva contraseña'}
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
                <h3>Auto-Recuperación y Watchdog de WhatsApp (WAHA)</h3>
                <span className="block-tag">Watchdog</span>
              </div>
              
              <div className="highlight-box" style={{ padding: '14px', marginBottom: '20px', display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <Info size={18} style={{ color: 'var(--cyan-accent)', flexShrink: 0, marginTop: '2px' }} />
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  <strong style={{ color: 'var(--text-primary)' }}>Control de Sesión Centralizado:</strong> El inicio, detención y escaneo del código QR de vinculación se gestionan de forma interactiva directamente desde la tarjeta de <strong style={{ color: 'var(--cyan-accent)' }}>WAHA en el panel principal</strong>.
                </div>
              </div>

              <h4 className="sub-title">Tiempos de Supervisión Automática</h4>
              <div className="field-grid-3">
                <div className="field-group">
                  <label>Intervalo de Watchdog (segundos)</label>
                  <input
                    type="number"
                    className="field-input"
                    placeholder="300"
                    value={values.WAHA_WATCHDOG_INTERVAL_SEC || ''}
                    onChange={(e) => handleChange('WAHA_WATCHDOG_INTERVAL_SEC', e.target.value)}
                  />
                  <span className="field-hint">Frecuencia del chequeo de salud de la sesión</span>
                </div>

                <div className="field-group">
                  <label>Cooldown de Recuperación (segundos)</label>
                  <input
                    type="number"
                    className="field-input"
                    placeholder="300"
                    value={values.WAHA_RECOVERY_COOLDOWN_SEC || ''}
                    onChange={(e) => handleChange('WAHA_RECOVERY_COOLDOWN_SEC', e.target.value)}
                  />
                  <span className="field-hint">Espera mínima entre intentos de reinicio</span>
                </div>

                <div className="field-group">
                  <label>Tiempo Máximo de Espera (segundos)</label>
                  <input
                    type="number"
                    className="field-input"
                    placeholder="60"
                    value={values.WAHA_RECOVERY_MAX_WAIT_SEC || ''}
                    onChange={(e) => handleChange('WAHA_RECOVERY_MAX_WAIT_SEC', e.target.value)}
                  />
                  <span className="field-hint">Límite para que la sesión pase a STARTING</span>
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Email Backup */}
          {activeTab === 'email' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Canal de Notificaciones por Correo</h3>
                <span className="block-tag">Destinatario</span>
              </div>
              <p className="block-desc">
                Ingresa la dirección de correo a la cual se despacharán los reportes, alertas de seguridad e incidentes de salud del stack.
              </p>

              <div className="field-group highlight-box" style={{ padding: '16px', marginBottom: '20px' }}>
                <label style={{ fontWeight: 700, color: 'var(--cyan-accent)', fontSize: '13px' }}>
                  Correo Destinatario del Administrador (ADMIN_EMAIL)
                </label>
                <input
                  type="email"
                  className="field-input"
                  placeholder="ejemplo@midominio.com"
                  style={{ marginTop: '8px', fontSize: '14px' }}
                  value={values.ADMIN_EMAIL || ''}
                  onChange={(e) => handleChange('ADMIN_EMAIL', e.target.value)}
                />
                <p className="field-hint" style={{ marginTop: '6px', fontSize: '12px' }}>
                  A esta dirección llegarán las alertas críticas y los mensajes de prueba del sistema.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <button
                  type="button"
                  className="nav-btn test-btn"
                  onClick={handleTestEmail}
                  disabled={testingEmail}
                  style={{ width: 'auto', padding: '8px 18px', fontWeight: 600 }}
                >
                  {testingEmail ? <Loader2 size={14} className="animate-spin" /> : <Mail size={14} />}
                  <span>{testingEmail ? 'Enviando correo de prueba...' : '📨 Enviar Correo de Prueba'}</span>
                </button>
              </div>
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
                  Habilitar resumen de alertas con IA Local (OLLAMA_ENABLED)
                  <span className="field-hint">Enriquece el mensaje de WhatsApp con un diagnóstico del incidente</span>
                </label>
              </div>

              <div className="field-grid-2">
                <div className="field-group">
                  <label>Host Ollama (OLLAMA_HOST)</label>
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

          {/* Tab 5: Logs */}
          {activeTab === 'logs' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Registros en Vivo del Servicio (journalctl)</h3>
                <span className="block-tag">Logs</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Últimas 100 líneas del servicio wazuh-waha</span>
                {loadingLogs && <span style={{ fontSize: '12px', color: 'var(--cyan-accent)' }}>Actualizando...</span>}
              </div>
              <pre className="logs-terminal" style={{
                background: '#090d16',
                padding: '12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                color: '#a5b4fc',
                fontSize: '11px',
                fontFamily: 'monospace',
                maxHeight: '380px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all'
              }}>
                {logsOutput}
              </pre>
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

              {activeTab === 'email' && (
                <button
                  type="button"
                  className="nav-btn test-btn"
                  onClick={handleTestEmail}
                  disabled={testingEmail}
                  title="Enviar correo de prueba al ADMIN_EMAIL"
                >
                  {testingEmail ? <Loader2 size={13} className="animate-spin" /> : <Mail size={13} />}
                  <span>{testingEmail ? 'Enviando...' : '📨 Test Correo'}</span>
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
                <span>{saving ? 'Guardando...' : 'Guardar en .env'}</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default SettingsSection;
