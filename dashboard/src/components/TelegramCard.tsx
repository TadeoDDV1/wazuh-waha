import React, { useState, useEffect, useCallback } from 'react';
import './ComponentCard.css';
import './TelegramCard.css';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  Send,
  CheckCircle2,
  Loader2,
  ExternalLink,
  RefreshCw,
  Bell,
  X,
  Radio,
  Terminal,
  Copy,
  Check,
  Search,
  HelpCircle,
  ShieldCheck,
  Settings,
  Bot,
  Hash,
} from 'lucide-react';

interface TelegramCardProps {
  onRefreshNeeded?: () => void;
}

interface BotCommand {
  cmd: string;
  category: 'agentes' | 'reportes' | 'red' | 'alertas' | 'waha' | 'config' | 'sistema';
  desc: string;
  example: string;
}

const BOT_COMMANDS: BotCommand[] = [
  // Agentes
  { cmd: '/agentes', category: 'agentes', desc: 'Lista de equipos conectados, IPs y estado de enlace', example: '/agentes' },
  { cmd: '/agente <id> [mod]', category: 'agentes', desc: 'Ficha forense profunda (hardware, red, sca, ps)', example: '/agente 000' },
  { cmd: '/analizar_agente <id>', category: 'agentes', desc: 'Dispara escaneos Wazuh y genera reporte de hardening', example: '/analizar_agente 000' },
  { cmd: '/agregar_agente <nom> [ip]', category: 'agentes', desc: 'Registrar nuevo endpoint en Wazuh Manager', example: '/agregar_agente web-01' },
  { cmd: '/eliminar_agente <id>', category: 'agentes', desc: 'Dar de baja un endpoint del cluster Wazuh', example: '/eliminar_agente 005' },
  { cmd: '/reiniciar_agente <id>', category: 'agentes', desc: 'Reiniciar remotamente el agente Wazuh en el host', example: '/reiniciar_agente 001' },
  { cmd: '/comando_agente <so>', category: 'agentes', desc: 'Script curl/bash listo para autoinstalar agente', example: '/comando_agente deb' },
  { cmd: '/sca <id>', category: 'agentes', desc: 'Auditoría CIS Benchmark con riesgo y remediación en español', example: '/sca 000' },
  { cmd: '/fim <id>', category: 'agentes', desc: 'Archivos monitoreados e historial de integridad FIM', example: '/fim 000' },
  { cmd: '/procesos <id>', category: 'agentes', desc: 'Procesos activos, consumo y usuarios ejecutores', example: '/procesos 000' },
  { cmd: '/paquetes <id> [filtro]', category: 'agentes', desc: 'Inventario de software SBOM instalado en el host', example: '/paquetes 000 ssh' },
  { cmd: '/puertos_agente <id>', category: 'agentes', desc: 'Sockets locales y puertos escuchando en el endpoint', example: '/puertos_agente 000' },
  { cmd: '/sitios_agente <id>', category: 'agentes', desc: 'Auditoría de sitios web externos navegados por el host', example: '/sitios_agente 000' },

  // Reportes
  { cmd: '/reporte <agent_id>', category: 'reportes', desc: 'Compilar y enviar el Informe Forense PDF SOC v2.0 oficial', example: '/reporte 000' },

  // Red
  { cmd: '/red', category: 'red', desc: 'Sockets activos del ecosistema, puertos y tráfico acumulado MB', example: '/red' },
  { cmd: '/sitios', category: 'red', desc: 'Auditoría de navegación y destinos web navegados por hosts', example: '/sitios' },
  { cmd: '/escanear_red', category: 'red', desc: 'Sondeo y barrido de puertos de red inmediato', example: '/escanear_red' },

  // Alertas
  { cmd: '/alertas [n]', category: 'alertas', desc: 'Últimas alertas de seguridad recibidas (default: 5)', example: '/alertas 5' },
  { cmd: '/buscar_alerta <txt>', category: 'alertas', desc: 'Búsqueda de eventos SIEM por palabra clave', example: '/buscar_alerta root' },
  { cmd: '/silenciar <rule_id>', category: 'alertas', desc: 'Silenciar regla temporalmente para no saturar canales', example: '/silenciar 5710' },
  { cmd: '/reactivar <rule_id>', category: 'alertas', desc: 'Reactivar regla de seguridad silenciada', example: '/reactivar 5710' },
  { cmd: '/reglas_silenciadas', category: 'alertas', desc: 'Consultar listado de reglas silenciadas activas', example: '/reglas_silenciadas' },
  { cmd: '/limpiar_cache', category: 'alertas', desc: 'Resetear caché de deduplicación de alertas (TTL)', example: '/limpiar_cache' },
  { cmd: '/reglas', category: 'alertas', desc: 'Listar reglas de seguridad locales activas en el Manager', example: '/reglas' },

  // WAHA
  { cmd: '/waha_status', category: 'waha', desc: 'Estado de conexión de la pasarela WhatsApp WAHA', example: '/waha_status' },
  { cmd: '/waha_restart', category: 'waha', desc: 'Reiniciar sesión de WhatsApp en el contenedor WAHA', example: '/waha_restart' },
  { cmd: '/waha_qr', category: 'waha', desc: 'Generar y recibir código QR en este chat para vincular', example: '/waha_qr' },
  { cmd: '/enviar_wa <tel> <msg>', category: 'waha', desc: 'Enviar un mensaje de WhatsApp directo vía WAHA', example: '/enviar_wa 521XXXXXXXXXX Test' },

  // Config
  { cmd: '/config', category: 'config', desc: 'Ver configuración activa de canales, umbrales y destinos', example: '/config' },
  { cmd: '/set_nivel <8-15>', category: 'config', desc: 'Ajustar nivel mínimo de severidad para alertar', example: '/set_nivel 8' },
  { cmd: '/set_canal <can> <on|off>', category: 'config', desc: 'Activar o pausar canal (whatsapp, telegram, email)', example: '/set_canal email on' },
  { cmd: '/set_phone <num>', category: 'config', desc: 'Actualizar teléfono destino de alertas por WhatsApp', example: '/set_phone 521XXXXXXXXXX' },
  { cmd: '/set_email <correo>', category: 'config', desc: 'Actualizar email destinatario de alertas SMTP', example: '/set_email soc@empresa.com' },
  { cmd: '/set_dedup <seg>', category: 'config', desc: 'Modificar ventana de deduplicación de alertas TTL', example: '/set_dedup 300' },
  { cmd: '/set_wazuh_ip <ip>', category: 'config', desc: 'Actualizar dirección IP del Wazuh Manager central', example: '/set_wazuh_ip 192.168.122.142' },
  { cmd: '/sync_comandos', category: 'config', desc: 'Sincronizar menú nativo con Telegram API (setMyCommands)', example: '/sync_comandos' },

  // Sistema
  { cmd: '/status', category: 'sistema', desc: 'Métricas del host (CPU Load, RAM, Disco y Uptime)', example: '/status' },
  { cmd: '/servicios', category: 'sistema', desc: 'Diagnóstico de salud de Wazuh, Relay, WAHA y Dashboard', example: '/servicios' },
  { cmd: '/reiniciar <servicio>', category: 'sistema', desc: 'Reiniciar servicio individual (waha, relay, wazuh)', example: '/reiniciar relay' },
  { cmd: '/logs [n]', category: 'sistema', desc: 'Ver últimas líneas de logs de auditoría del Relay', example: '/logs 15' },
  { cmd: '/audit [n]', category: 'sistema', desc: 'Historial de cambios y auditoría de la sesión SOC', example: '/audit 10' },
  { cmd: '/ip', category: 'sistema', desc: 'Consultar direcciones IP local y pública del host', example: '/ip' },
  { cmd: '/kpis', category: 'sistema', desc: 'Métricas de rendimiento, alertas procesadas y latencia', example: '/kpis' },
  { cmd: '/ping', category: 'sistema', desc: 'Prueba rápida de disponibilidad y latencia del bot', example: '/ping' },
];

export const TelegramCard: React.FC<TelegramCardProps> = ({ onRefreshNeeded }) => {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [pairing, setPairing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncingCommands, setSyncingCommands] = useState(false);
  const [activeMainTab, setActiveMainTab] = useState<'comandos' | 'configuracion'>('comandos');

  // Inputs de configuración
  const [botToken, setBotToken] = useState('');
  const [chatIdInput, setChatIdInput] = useState('');
  const [minAlertLevel, setMinAlertLevel] = useState('8');
  const [saving, setSaving] = useState(false);

  // Explorador de comandos
  const [activeCategory, setActiveCategory] = useState<'todos' | 'agentes' | 'reportes' | 'red' | 'alertas' | 'waha' | 'config' | 'sistema'>('todos');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCommand, setSelectedCommand] = useState<BotCommand>(BOT_COMMANDS[0]);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await dashboardService.getTelegramStatus();
      setStatus(data);
      if (data?.chat_id) {
        setChatIdInput(String(data.chat_id));
      }
      if (data?.min_alert_level) {
        setMinAlertLevel(String(data.min_alert_level));
      }
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30_000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const handlePair = async () => {
    setPairing(true);
    try {
      const res = await dashboardService.pairTelegram();
      if (res?.ok) {
        toast.success(res.detail || 'Chat de Telegram emparejado correctamente');
        fetchStatus();
        onRefreshNeeded?.();
      } else {
        toast.error(res?.detail || 'No se detectó mensaje /start reciente');
      }
    } catch (e: any) {
      toast.error('Error al emparejar: ' + (e.message || String(e)));
    } finally {
      setPairing(false);
    }
  };

  const handleTestNotification = async () => {
    setTesting(true);
    try {
      const res = await dashboardService.testTelegram();
      if (res?.ok) {
        toast.success(res.detail || 'Notificación de prueba enviada con éxito');
      } else {
        toast.error(res?.detail || 'Fallo al enviar notificación de prueba');
      }
    } catch (e: any) {
      toast.error('Error: ' + (e.message || String(e)));
    } finally {
      setTesting(false);
    }
  };

  const handleSyncCommands = async () => {
    setSyncingCommands(true);
    try {
      const res = await dashboardService.syncTelegramCommands();
      if (res?.ok) {
        toast.success(`✓ ${res.detail || 'Comandos sincronizados con Telegram'}`);
      } else {
        toast.error(res?.detail || 'No se pudieron sincronizar los comandos');
      }
    } catch (e: any) {
      toast.error('Error al sincronizar comandos: ' + (e.message || String(e)));
    } finally {
      setSyncingCommands(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload: any = {
        TELEGRAM_ENABLED: 'true',
      };
      if (botToken.trim()) payload.TELEGRAM_BOT_TOKEN = botToken.trim();
      if (chatIdInput.trim()) payload.TELEGRAM_CHAT_ID = chatIdInput.trim();
      if (minAlertLevel) payload.TELEGRAM_MIN_LEVEL = minAlertLevel;

      const res = await dashboardService.updateConfigBatch(payload);
      if (res?.ok) {
        toast.success('Configuración de Telegram guardada exitosamente');
        setBotToken('');
        fetchStatus();
        onRefreshNeeded?.();
      } else {
        toast.error(res?.result || 'Error al guardar la configuración');
      }
    } catch (e: any) {
      toast.error('Error al guardar: ' + (e.message || String(e)));
    } finally {
      setSaving(false);
    }
  };

  const handleCopyCommand = (cmdText: string) => {
    navigator.clipboard.writeText(cmdText);
    setCopiedCmd(cmdText);
    toast.success(`Comando ${cmdText} copiado al portapapeles`);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const isConfigured = Boolean(status?.configured);
  const hasChatId = Boolean(status?.has_chat_id || status?.chat_id);
  const isConnected = isConfigured && hasChatId;
  const botUsername = status?.bot_info?.username;
  const minLevel = status?.min_alert_level || 8;
  const health = isConnected ? 'healthy' : isConfigured ? 'warning' : 'disabled';
  const statusLabel = isConnected ? 'CONECTADO' : isConfigured ? 'TOKEN LISTO' : 'DESCONECTADO';

  // Filtrado de comandos para el explorador
  const filteredCommands = BOT_COMMANDS.filter((item) => {
    const matchesCategory = activeCategory === 'todos' || item.category === activeCategory;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch = !q || item.cmd.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q);
    return matchesCategory && matchesSearch;
  });

  return (
    <>
      <div className={`component-card telegram-card status-${health}`}>
        {/* Cabecera Estándar ComponentCard */}
        <div className="card-header">
          <div className="card-title-group">
            <div
              className="card-icon-wrapper"
              style={{
                background: 'rgba(56, 189, 248, 0.15)',
                borderColor: 'rgba(56, 189, 248, 0.35)',
              }}
            >
              <Send size={18} style={{ color: '#38bdf8' }} />
            </div>
            <div className="card-name-block">
              <h3 className="card-name">Telegram Bot SOC Gateway</h3>
              <span className="card-category-tag">MENSAJERÍA & SOC · CANAL BIDIRECCIONAL</span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div className={`status-badge-chip ${health}`}>
              <span className="status-dot" />
              <span>{statusLabel}</span>
            </div>
            <button
              type="button"
              className="card-action-btn"
              onClick={fetchStatus}
              disabled={loading}
              title="Refrescar estado del bot"
              style={{ padding: '0.35rem 0.55rem' }}
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Cuerpo de la Tarjeta */}
        <div className="card-body">
          <p className="card-description">
            Consola de comando remota para SOC: Alertas en tiempo real, auditoría forense y 39 comandos de control del ecosistema Wazuh-WAHA.
          </p>

          {/* Banner de Estado Visual */}
          {isConnected ? (
            <div className="telegram-banner-active">
              <CheckCircle2 size={16} />
              <span>BOT VINCULADO Y ACTIVO · Escuchando comandos del SOC y despachando alertas Nivel ≥ L{minLevel}</span>
            </div>
          ) : isConfigured ? (
            <div className="telegram-banner-warning">
              <Radio size={16} className="animate-pulse" />
              <span>TOKEN CONFIGURADO · Envía /start a @{botUsername || 'tu_bot'} o presiona "Emparejar Chat" para recibir alertas.</span>
            </div>
          ) : (
            <div className="telegram-banner-disabled">
              <HelpCircle size={16} />
              <span>Bot no configurado aún. Agrega el token generado en @BotFather para habilitar la consola de comandos.</span>
            </div>
          )}

          {/* Grilla de Métricas SOC (KPI Cards) */}
          <div className="soc-kpi-grid">
            <div className="soc-kpi-card">
              <span className="soc-kpi-label">
                <Bot size={12} style={{ color: '#38bdf8' }} />
                Bot ID
              </span>
              <span className="soc-kpi-value" style={{ color: isConnected ? '#38bdf8' : 'var(--text-secondary)' }}>
                {botUsername ? `@${botUsername}` : isConfigured ? 'Token Listo' : 'Sin Token'}
              </span>
              <span className="soc-kpi-sub">{isConfigured ? 'API Token Activo' : 'Inactivo'}</span>
            </div>

            <div className="soc-kpi-card">
              <span className="soc-kpi-label">
                <Hash size={12} style={{ color: 'var(--green-healthy)' }} />
                Chat Destino
              </span>
              <span className="soc-kpi-value" style={{ color: hasChatId ? 'var(--green-healthy)' : 'var(--yellow-warning)' }}>
                {status?.chat_id ? `${status.chat_id}` : 'Pendiente'}
              </span>
              <span className="soc-kpi-sub">{hasChatId ? 'Enlace Directo' : 'Requiere /start'}</span>
            </div>

            <div className="soc-kpi-card">
              <span className="soc-kpi-label">
                <ShieldCheck size={12} style={{ color: '#c084fc' }} />
                Filtro SIEM
              </span>
              <span className="soc-kpi-value" style={{ color: '#c084fc' }}>
                Nivel ≥ L{minLevel}
              </span>
              <span className="soc-kpi-sub">Severidad SOC</span>
            </div>

            <div className="soc-kpi-card">
              <span className="soc-kpi-label">
                <Terminal size={12} style={{ color: '#f59e0b' }} />
                Catálogo SOC
              </span>
              <span className="soc-kpi-value" style={{ color: '#f59e0b' }}>
                39 Comandos
              </span>
              <span className="soc-kpi-sub">7 Categorías</span>
            </div>
          </div>

          {/* Navegación por Sub-Pestañas */}
          <div className="soc-nav-tabs">
            <button
              type="button"
              className={`soc-tab-btn ${activeMainTab === 'comandos' ? 'active' : ''}`}
              onClick={() => setActiveMainTab('comandos')}
            >
              <Terminal size={14} />
              <span>Explorador de Comandos (39)</span>
            </button>
            <button
              type="button"
              className={`soc-tab-btn ${activeMainTab === 'configuracion' ? 'active' : ''}`}
              onClick={() => setActiveMainTab('configuracion')}
            >
              <Settings size={14} />
              <span>Ajustes & Credenciales</span>
            </button>
          </div>

          {/* Pestaña 1: Explorador Interactivo de Comandos */}
          {activeMainTab === 'comandos' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Barra de Filtros y Búsqueda */}
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                <div style={{ flex: '1 1 200px' }} className="soc-search-input-wrap">
                  <Search size={14} style={{ color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    className="soc-search-input"
                    placeholder="Buscar comando (ej. /agentes, /reporte, /red)..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery('')}
                      style={{ color: 'var(--text-muted)', cursor: 'pointer' }}
                    >
                      <X size={13} />
                    </button>
                  )}
                </div>

                <button
                  type="button"
                  className="card-action-btn"
                  onClick={handleSyncCommands}
                  disabled={syncingCommands || !isConfigured}
                  title="Registra los comandos en el menú nativo de Telegram mediante setMyCommands"
                >
                  <RefreshCw size={13} className={syncingCommands ? 'animate-spin' : ''} />
                  <span>{syncingCommands ? 'Sincronizando...' : 'Sincronizar Comandos'}</span>
                </button>
              </div>

              {/* Píldoras de Categorías */}
              <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '4px' }}>
                {[
                  { id: 'todos', label: 'Todos', count: 39 },
                  { id: 'agentes', label: 'Agentes', count: 13 },
                  { id: 'reportes', label: 'Reportes', count: 1 },
                  { id: 'red', label: 'Red', count: 3 },
                  { id: 'alertas', label: 'Alertas', count: 7 },
                  { id: 'waha', label: 'WAHA', count: 4 },
                  { id: 'config', label: 'Config', count: 8 },
                  { id: 'sistema', label: 'Sistema', count: 8 },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    type="button"
                    className={`category-pill ${activeCategory === cat.id ? 'active' : ''}`}
                    onClick={() => setActiveCategory(cat.id as any)}
                  >
                    <span>{cat.label}</span>
                    <span style={{ opacity: 0.65, fontSize: '10px' }}>({cat.count})</span>
                  </button>
                ))}
              </div>

              {/* Lista Scrollable de Comandos */}
              <div className="soc-commands-scroll">
                {filteredCommands.length === 0 ? (
                  <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                    No se encontraron comandos con "{searchQuery}"
                  </div>
                ) : (
                  filteredCommands.map((item) => {
                    const isSelected = selectedCommand.cmd === item.cmd;
                    const isCopied = copiedCmd === item.cmd;
                    return (
                      <div
                        key={item.cmd}
                        className="soc-command-card"
                        style={{
                          borderColor: isSelected ? 'rgba(56, 189, 248, 0.45)' : undefined,
                          background: isSelected ? 'var(--bg-card-hover)' : undefined,
                        }}
                        onClick={() => setSelectedCommand(item)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
                          <span className="soc-command-code">{item.cmd}</span>
                          <span className="soc-command-desc">{item.desc}</span>
                        </div>

                        <button
                          type="button"
                          className="soc-command-copy-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopyCommand(item.cmd);
                          }}
                          title="Copiar comando"
                        >
                          {isCopied ? <Check size={14} style={{ color: 'var(--green-healthy)' }} /> : <Copy size={14} />}
                        </button>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Terminal Preview del Comando Seleccionado */}
              {selectedCommand && (
                <div className="soc-terminal-box">
                  <div className="soc-terminal-header">
                    <div className="soc-terminal-dots">
                      <div className="soc-terminal-dot" style={{ background: '#ef4444' }} />
                      <div className="soc-terminal-dot" style={{ background: '#f59e0b' }} />
                      <div className="soc-terminal-dot" style={{ background: '#10b981' }} />
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Sintaxis oficial SOC: [{selectedCommand.category}]
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyCommand(selectedCommand.example)}
                      style={{ color: '#38bdf8', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
                    >
                      <Copy size={11} />
                      <span>Copiar Ejemplo</span>
                    </button>
                  </div>
                  <div className="soc-terminal-content">
                    <div>
                      <strong style={{ color: '#38bdf8' }}>$ telegram_bot</strong> {selectedCommand.example}
                    </div>
                    <div style={{ color: 'var(--text-secondary)', marginTop: '4px', fontSize: '11px' }}>
                      # {selectedCommand.desc}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Pestaña 2: Ajustes & Credenciales */}
          {activeMainTab === 'configuracion' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                    BOT TOKEN (Generado vía @BotFather en Telegram)
                  </label>
                  <input
                    type="password"
                    placeholder={isConfigured ? '•••••••••••••••••••••••• (Configurado)' : 'Ingresa el token 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11'}
                    value={botToken}
                    onChange={(e) => setBotToken(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      background: 'rgba(0,0,0,0.4)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: '#fff',
                      fontSize: '12px',
                      outline: 'none',
                    }}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                      CHAT ID / GRUPO DESTINO
                    </label>
                    <input
                      type="text"
                      placeholder="ej. 7627248612 o -100XXXXXXXXX"
                      value={chatIdInput}
                      onChange={(e) => setChatIdInput(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        background: 'rgba(0,0,0,0.4)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        color: '#fff',
                        fontSize: '12px',
                        outline: 'none',
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                      NIVEL MÍNIMO DE ALERTA (8-15)
                    </label>
                    <select
                      value={minAlertLevel}
                      onChange={(e) => setMinAlertLevel(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        background: 'rgba(0,0,0,0.4)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        color: '#fff',
                        fontSize: '12px',
                        outline: 'none',
                        cursor: 'pointer',
                      }}
                    >
                      <option value="8">Nivel 8 (Advertencias y Fallos de Autenticación)</option>
                      <option value="10">Nivel 10 (Ataques Relevantes e Inyecciones)</option>
                      <option value="12">Nivel 12 (Alta Severidad y Rootkits)</option>
                      <option value="14">Nivel 14 (Crítico / Ataques Confirmados)</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '6px' }}>
                  <button
                    type="button"
                    className="card-action-btn"
                    onClick={handleSaveConfig}
                    disabled={saving}
                    style={{
                      background: 'rgba(56, 189, 248, 0.2)',
                      borderColor: '#38bdf8',
                      color: '#38bdf8',
                      fontWeight: 700,
                    }}
                  >
                    {saving ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                    <span>{saving ? 'Guardando...' : 'Guardar Credenciales'}</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Estándar ComponentCard */}
        <div className="card-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              {status?.updated_at ? `Actualizado: ${new Date(status.updated_at * 1000).toLocaleTimeString()}` : 'Enlace en vivo'}
            </span>
          </div>

          <div className="card-actions">
            {botUsername && (
              <a
                href={`https://t.me/${botUsername}?start=pair`}
                target="_blank"
                rel="noreferrer"
                className="card-action-btn"
                style={{ textDecoration: 'none' }}
              >
                <ExternalLink size={13} />
                <span>Abrir @{botUsername}</span>
              </a>
            )}

            <button
              type="button"
              className="card-action-btn"
              onClick={handlePair}
              disabled={pairing || !isConfigured}
              title="Detecta automáticamente el Chat ID tras enviar /start al bot"
            >
              {pairing ? <Loader2 size={13} className="animate-spin" /> : <Radio size={13} />}
              <span>{pairing ? 'Detectando...' : 'Emparejar Chat'}</span>
            </button>

            <button
              type="button"
              className="card-action-btn"
              onClick={handleTestNotification}
              disabled={testing || !isConnected}
              title="Envía una alerta de prueba al chat configurado"
            >
              {testing ? <Loader2 size={13} className="animate-spin" /> : <Bell size={13} />}
              <span>{testing ? 'Enviando...' : 'Probar Notificación'}</span>
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
