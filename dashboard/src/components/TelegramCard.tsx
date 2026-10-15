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
  Terminal,
  Copy,
  Check,
  Search,
  Sparkles,
  HelpCircle,
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
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [tokenInput, setTokenInput] = useState('');
  const [savingToken, setSavingToken] = useState(false);
  const [showCommandsExplorer, setShowCommandsExplorer] = useState(false);
  const [activeTab, setActiveTab] = useState<'todos' | 'agentes' | 'reportes' | 'red' | 'alertas' | 'waha' | 'config' | 'sistema'>('todos');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

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

  const handleSyncCommands = async () => {
    setSyncingCommands(true);
    try {
      const res = await dashboardService.syncTelegramCommands();
      if (res?.ok) {
        toast.success(`¡Menú de Telegram actualizado! Se registraron ${res.count || 39} comandos en la API oficial.`);
      } else {
        toast.error(res?.detail || 'Error al sincronizar comandos con Telegram');
      }
    } catch (e: any) {
      toast.error('Error al sincronizar comandos: ' + (e.message || String(e)));
    } finally {
      setSyncingCommands(false);
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

  const handleCopyCommand = (cmdText: string) => {
    const rawCmd = cmdText.split(' ')[0];
    navigator.clipboard.writeText(rawCmd);
    setCopiedCmd(cmdText);
    toast.success(`Comando ${rawCmd} copiado al portapapeles`);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const isConfigured = Boolean(status?.configured);
  const botInfo = status?.bot_info;
  const isConnected = Boolean(botInfo?.ok);
  const botUsername = botInfo?.username;
  const hasChatId = Boolean(status?.chat_id);
  const minLevel = status?.min_level || 8;

  // Filtrado de comandos para el explorador
  const filteredCommands = BOT_COMMANDS.filter((item) => {
    const matchesCategory = activeTab === 'todos' || item.category === activeTab;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch = !q || item.cmd.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q);
    return matchesCategory && matchesSearch;
  });

  return (
    <div
      className="component-card healthy"
      style={{
        borderColor: isConnected ? 'rgba(34, 158, 217, 0.45)' : undefined,
        background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%)',
      }}
    >
      {/* Cabecera */}
      <div className="card-top-row">
        <div className="card-identity">
          <div
            className="service-icon-box"
            style={{
              background: 'linear-gradient(135deg, rgba(34, 158, 217, 0.25), rgba(2, 132, 199, 0.15))',
              color: '#38bdf8',
              border: '1px solid rgba(56, 189, 248, 0.3)',
            }}
          >
            <Send size={20} />
          </div>
          <div>
            <div className="card-title-line">
              <span className="card-title">Telegram SOC Bot & Comandos Interactivos</span>
              <span
                className="status-pill healthy"
                style={{
                  background: isConnected
                    ? 'rgba(46, 204, 113, 0.18)'
                    : isConfigured
                    ? 'rgba(255, 179, 0, 0.18)'
                    : 'rgba(239, 68, 68, 0.18)',
                  color: isConnected
                    ? 'var(--green-healthy)'
                    : isConfigured
                    ? 'var(--yellow-warning)'
                    : 'var(--red-error)',
                  border: isConnected
                    ? '1px solid rgba(46, 204, 113, 0.3)'
                    : undefined,
                }}
              >
                {isConnected ? '✓ BOT ACTIVO & ENLACE ESTABLECIDO' : isConfigured ? '⚠️ TOKEN CONFIGURADO (SIN VINCULAR)' : '⚪ NO CONFIGURADO'}
              </span>
            </div>
            <div className="card-category">
              Consola de comando remota para SOC: Alertas en tiempo real, auditoría forense y 39 comandos de control del ecosistema.
            </div>
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

      {/* Grid de Métricas y Estado */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '10px',
          marginTop: '16px',
        }}
      >
        <div className="waha-metric-box" style={{ background: 'rgba(255, 255, 255, 0.02)', borderColor: 'rgba(255, 255, 255, 0.07)' }}>
          <span className="waha-metric-label">Identificador del Bot</span>
          <span className="waha-metric-value" style={{ color: isConnected ? '#38bdf8' : 'var(--text-secondary)' }}>
            {botUsername ? `@${botUsername}` : isConfigured ? 'Token Establecido' : 'Sin Token'}
          </span>
        </div>

        <div className="waha-metric-box" style={{ background: 'rgba(255, 255, 255, 0.02)', borderColor: 'rgba(255, 255, 255, 0.07)' }}>
          <span className="waha-metric-label">Chat ID Destino</span>
          <span className="waha-metric-value" style={{ color: hasChatId ? 'var(--green-healthy)' : 'var(--yellow-warning)' }}>
            {status?.chat_id ? `ID: ${status.chat_id}` : 'Pendiente /start'}
          </span>
        </div>

        <div className="waha-metric-box" style={{ background: 'rgba(255, 255, 255, 0.02)', borderColor: 'rgba(255, 255, 255, 0.07)' }}>
          <span className="waha-metric-label">Filtro de Alertas SIEM</span>
          <span className="waha-metric-value" style={{ color: '#c084fc' }}>
            Nivel ≥ L{minLevel} (Crítico/Alto)
          </span>
        </div>

        <div className="waha-metric-box" style={{ background: 'rgba(255, 255, 255, 0.02)', borderColor: 'rgba(255, 255, 255, 0.07)' }}>
          <span className="waha-metric-label">Capacidad Operativa</span>
          <span className="waha-metric-value" style={{ color: '#f59e0b' }}>
            39 Comandos Oficiales
          </span>
        </div>
      </div>

      {/* Barra de Acciones Principales */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '16px', alignItems: 'center' }}>
        {botUsername ? (
          <a
            href={`https://t.me/${botUsername}?start=pair`}
            target="_blank"
            rel="noreferrer"
            className="action-pill-btn"
            style={{
              background: 'linear-gradient(135deg, rgba(34, 158, 217, 0.25), rgba(2, 132, 199, 0.2))',
              borderColor: 'rgba(56, 189, 248, 0.5)',
              color: '#38bdf8',
              textDecoration: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600,
            }}
          >
            <ExternalLink size={13} />
            <span>Abrir @{botUsername}</span>
          </a>
        ) : null}

        <button
          type="button"
          className="action-pill-btn"
          onClick={handlePair}
          disabled={pairing || !isConfigured}
          style={{
            background: 'rgba(0, 229, 255, 0.12)',
            borderColor: 'rgba(0, 229, 255, 0.35)',
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
          onClick={handleSyncCommands}
          disabled={syncingCommands || !isConfigured}
          style={{
            background: 'rgba(168, 85, 247, 0.15)',
            borderColor: 'rgba(168, 85, 247, 0.4)',
            color: '#c084fc',
          }}
          title="Sincroniza el catálogo de comandos con la API oficial de Telegram (setMyCommands)"
        >
          {syncingCommands ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          <span>{syncingCommands ? 'Sincronizando...' : '🔄 Sincronizar Menú Nativo'}</span>
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
          <span>{testing ? 'Enviando...' : '📩 Probar Alerta'}</span>
        </button>

        <button
          type="button"
          className="action-pill-btn"
          onClick={() => setShowTokenModal(true)}
          style={{ marginLeft: 'auto', background: 'rgba(255, 255, 255, 0.05)', borderColor: 'rgba(255, 255, 255, 0.15)' }}
        >
          <KeyRound size={13} />
          <span>{isConfigured ? 'Cambiar Token' : 'Configurar Token'}</span>
        </button>
      </div>

      {/* Botón para desplegar el Explorador de Comandos */}
      <div style={{ marginTop: '16px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '14px' }}>
        <button
          type="button"
          onClick={() => setShowCommandsExplorer(!showCommandsExplorer)}
          style={{
            background: showCommandsExplorer ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.04)',
            border: '1px solid ' + (showCommandsExplorer ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.1)'),
            borderRadius: '8px',
            color: showCommandsExplorer ? '#38bdf8' : '#e2e8f0',
            fontSize: '12px',
            fontWeight: 700,
            cursor: 'pointer',
            padding: '8px 14px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.2s ease',
          }}
        >
          <Terminal size={14} />
          <span>{showCommandsExplorer ? 'Ocultar Directorio de Comandos' : 'Explorar Catálogo de 39 Comandos SOC'}</span>
          <span
            style={{
              fontSize: '11px',
              padding: '2px 6px',
              borderRadius: '10px',
              background: 'rgba(56, 189, 248, 0.2)',
              color: '#38bdf8',
            }}
          >
            39
          </span>
        </button>

        {showCommandsExplorer && (
          <div
            style={{
              marginTop: '12px',
              padding: '16px',
              background: 'rgba(0, 0, 0, 0.35)',
              borderRadius: '10px',
              border: '1px solid rgba(56, 189, 248, 0.2)',
            }}
          >
            {/* Buscador y Pestañas */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ position: 'relative', width: '240px' }}>
                <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-secondary)' }} />
                <input
                  type="text"
                  placeholder="Buscar comando o función..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '7px 10px 7px 32px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    background: 'rgba(255, 255, 255, 0.05)',
                    color: '#fff',
                    fontSize: '12px',
                    outline: 'none',
                  }}
                />
              </div>

              {/* Categorías en Pills */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {(['todos', 'agentes', 'reportes', 'red', 'alertas', 'waha', 'config', 'sistema'] as const).map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setActiveTab(cat)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '14px',
                      fontSize: '11px',
                      fontWeight: 600,
                      border: '1px solid',
                      borderColor: activeTab === cat ? '#38bdf8' : 'rgba(255, 255, 255, 0.08)',
                      background: activeTab === cat ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.02)',
                      color: activeTab === cat ? '#38bdf8' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textTransform: 'capitalize',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Listado de Comandos */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(290px, 1fr))',
                gap: '8px',
                maxHeight: '380px',
                overflowY: 'auto',
                paddingRight: '4px',
              }}
            >
              {filteredCommands.length === 0 ? (
                <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '20px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                  No se encontraron comandos con el criterio de búsqueda.
                </div>
              ) : (
                filteredCommands.map((item) => (
                  <div
                    key={item.cmd}
                    style={{
                      padding: '10px 12px',
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      borderRadius: '8px',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      transition: 'border-color 0.2s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                      <code
                        style={{
                          color: '#38bdf8',
                          fontFamily: 'monospace',
                          fontSize: '12px',
                          fontWeight: 700,
                          background: 'rgba(56, 189, 248, 0.08)',
                          padding: '2px 6px',
                          borderRadius: '4px',
                        }}
                      >
                        {item.cmd}
                      </code>
                      <button
                        type="button"
                        onClick={() => handleCopyCommand(item.example)}
                        title="Copiar comando"
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: copiedCmd === item.example ? 'var(--green-healthy)' : 'var(--text-secondary)',
                          cursor: 'pointer',
                          padding: '2px',
                          display: 'flex',
                        }}
                      >
                        {copiedCmd === item.example ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    </div>
                    <p style={{ fontSize: '11px', color: '#94a3b8', margin: '6px 0 0 0', lineHeight: 1.35 }}>
                      {item.desc}
                    </p>
                  </div>
                ))
              )}
            </div>

            <div
              style={{
                marginTop: '12px',
                padding: '8px 12px',
                background: 'rgba(56, 189, 248, 0.05)',
                border: '1px solid rgba(56, 189, 248, 0.15)',
                borderRadius: '6px',
                fontSize: '11px',
                color: '#94a3b8',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <HelpCircle size={14} style={{ color: '#38bdf8', flexShrink: 0 }} />
              <span>
                <strong>Tip SOC:</strong> En Telegram escribe <code>/comandos</code> para explorar el catálogo en el chat, o <code>/</code> para desplegar el autocompletado nativo.
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Modal para configurar Token de Telegram */}
      {showTokenModal && (
        <div className="qr-modal-overlay" onClick={() => setShowTokenModal(false)}>
          <div className="qr-modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
            <div className="qr-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <KeyRound size={18} style={{ color: '#38bdf8' }} />
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

export default TelegramCard;
