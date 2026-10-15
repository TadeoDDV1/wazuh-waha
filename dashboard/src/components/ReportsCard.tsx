import React, { useState, useEffect, useCallback } from 'react';
import './ComponentCard.css';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  FileText,
  Download,
  Loader2,
  RefreshCw,
  Server,
  ShieldCheck,
  Cpu,
  Activity,
  Network,
  Package,
  Layers,
  FileCode,
  Terminal,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Info,
  Scan,
  Send,
  Copy,
  Check,
} from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  ip?: string;
  status?: string;
}

interface AgentPreview {
  name: string;
  ip: string;
  status: string;
  os_desc: string;
  arch: string;
  kernel: string;
  ram_total_mb: number;
  ram_used_mb: number;
  ram_usage_pct: number;
  sca_score: number;
  sca_pass: number;
  sca_fail: number;
  sca_total: number;
  sockets_count: number;
  recent_alerts_count: number;
  critical_alerts_count: number;
  total_packages: number;
}

interface ReportSection {
  num: string;
  title: string;
  category: 'general' | 'red' | 'cumplimiento' | 'siem';
  icon: any;
  color: string;
  desc: string;
  detail: string;
}

const REPORT_SECTIONS: ReportSection[] = [
  {
    num: '01',
    title: 'Identificación y Enlace',
    category: 'general',
    icon: Server,
    color: '#0284c7',
    desc: 'ID, hostname, IP de enlace, versión de agente y vigencia de sincronización con el Manager (keep-alive).',
    detail: 'Garantiza que el canal criptográfico esté sincronizado y que el endpoint no haya sido desconectado o aislado.',
  },
  {
    num: '02',
    title: 'Hardware y Recursos',
    category: 'general',
    icon: Cpu,
    color: '#0284c7',
    desc: 'Microprocesador (CPU, núcleos, MHz), memoria RAM (total, usada, % y libre) y serial de placa madre.',
    detail: 'Permite detectar saturación por ataques DoS o minería no autorizada, y valida números de serie contra activos inventariados.',
  },
  {
    num: '03',
    title: 'Sistema Operativo y Kernel',
    category: 'general',
    icon: Layers,
    color: '#059669',
    desc: 'Distribución, arquitectura, hostname y versión exacta del kernel en ejecución.',
    detail: 'Delimita la superficie de ataque inicial y permite evaluar la exposición frente a exploits locales de escalamiento (LPE).',
  },
  {
    num: '04',
    title: 'Interfaces de Red y Tráfico',
    category: 'red',
    icon: Network,
    color: '#0891b2',
    desc: 'Adaptadores físicos y virtuales, IPv4, MAC address, MTU y volumen acumulado de tráfico RX y TX.',
    detail: 'Descubre adaptadores en modo promiscuo, interfaces bridge sospechosas o volúmenes anómalos de exfiltración de datos.',
  },
  {
    num: '05',
    title: 'Destinos de Red & Sockets',
    category: 'red',
    icon: Activity,
    color: '#0284c7',
    desc: 'Sockets activos hacia IPs remotas, puertos, procesos locales asociados y categorización de dominio.',
    detail: 'Primera línea de defensa para identificar balizas de Command & Control (C2), troyanos o navegación indebida.',
  },
  {
    num: '06',
    title: 'Procesos en Ejecución',
    category: 'red',
    icon: Terminal,
    color: '#059669',
    desc: 'Listado de binarios en memoria con su PID, nombre ejecutable, usuario y estado de ejecución.',
    detail: 'Permite descubrir scripts ocultos, procesos sospechosos corriendo como root/SYSTEM o ejecutables desde rutas temporales.',
  },
  {
    num: '07',
    title: 'Software y Paquetería',
    category: 'cumplimiento',
    icon: Package,
    color: '#ea580c',
    desc: 'Inventario SBOM de paquetes y aplicaciones registradas por el módulo Syscollector de Wazuh.',
    detail: 'Base para la gestión de vulnerabilidades conocidas (CVEs), control de parches y detección de software no homologado.',
  },
  {
    num: '08',
    title: 'Seguridad SCA (CIS Benchmark)',
    category: 'cumplimiento',
    icon: ShieldCheck,
    color: '#10b981',
    desc: 'Score global de cumplimiento frente a normas CIS, controles aprobados, fallidos y remediaciones.',
    detail: 'Audita directrices de hardening del sistema (permisos, contraseñas, servicios seguros) con comandos técnicos de solución.',
  },
  {
    num: '09',
    title: 'Integridad de Archivos (FIM)',
    category: 'cumplimiento',
    icon: FileCode,
    color: '#a855f7',
    desc: 'Auditoría Syscheck de archivos modificados, eliminados o creados con hashes criptográficos MD5/SHA256.',
    detail: 'Detecta manipulación de ficheros críticos de autenticación (/etc/passwd) o sustitución maliciosa de binarios del sistema.',
  },
  {
    num: '10',
    title: 'Detecciones SIEM Wazuh',
    category: 'siem',
    icon: AlertTriangle,
    color: '#ef4444',
    desc: 'Incidentes y alertas correlacionadas por reglas Wazuh, clasificadas por severidad (L1 a L15).',
    detail: 'Evidencia directa de ataques e intrusiones (fuerza bruta, escaneo de puertos, inyecciones) para respuesta inmediata del SOC.',
  },
];

export const ReportsCard: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [auditing, setAuditing] = useState(false);
  const [showGuide, setShowGuide] = useState(false);
  const [activeGuideCategory, setActiveGuideCategory] = useState<'todos' | 'general' | 'red' | 'cumplimiento' | 'siem'>('todos');
  const [preview, setPreview] = useState<AgentPreview | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [copiedTelegramCmd, setCopiedTelegramCmd] = useState(false);

  const fetchAgents = useCallback(async () => {
    setLoadingAgents(true);
    try {
      const data = await dashboardService.getWazuhAgents();
      const list: Agent[] = data?.agents || [];
      setAgents(list);
      if (list.length > 0 && !selectedAgentId) {
        setSelectedAgentId(list[0].id);
      }
    } catch (err) {
      console.error('Error fetching agents for reports:', err);
      toast.error('No se pudo cargar la lista de agentes.');
    } finally {
      setLoadingAgents(false);
    }
  }, [selectedAgentId]);

  useEffect(() => {
    fetchAgents();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Cargar vista previa del agente seleccionado
  const fetchPreview = useCallback(async (agentId: string) => {
    if (!agentId) return;
    setLoadingPreview(true);
    try {
      const data = await dashboardService.getAgentReportPreview(agentId);
      if (data?.ok) {
        setPreview(data);
      } else {
        setPreview(null);
      }
    } catch {
      setPreview(null);
    } finally {
      setLoadingPreview(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAgentId) {
      fetchPreview(selectedAgentId);
    }
  }, [selectedAgentId, fetchPreview]);

  const handleDownload = async () => {
    if (!selectedAgentId) {
      toast.warning('Seleccioná un agente para generar el reporte.');
      return;
    }
    setDownloading(true);
    try {
      const blob = await dashboardService.getAgentReportBlob(selectedAgentId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const now = new Date();
      const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
      a.download = `reporte_agente_${selectedAgentId}_${ts}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Informe Forense PDF [${selectedAgentId}] generado y descargado exitosamente.`);
    } catch (err: any) {
      console.error('Error downloading agent report:', err);
      const status = err?.response?.status;
      if (status === 401) {
        toast.error('Sesión expirada. Volvé a iniciar sesión para descargar el reporte.');
      } else if (status === 403) {
        toast.error('Permisos insuficientes para descargar reportes.');
      } else if (err?.message?.includes('Network Error')) {
        toast.error('Sin conexión con el relay. Verificá que esté activo.');
      } else {
        toast.error('Error al generar el reporte PDF. Reintenta en unos segundos.');
      }
    } finally {
      setDownloading(false);
    }
  };

  const handleAuditScan = async () => {
    if (!selectedAgentId) return;
    setAuditing(true);
    toast.info(`Disparando escaneo de integridad Wazuh para el agente [${selectedAgentId}]...`);
    try {
      const res = await dashboardService.auditAgentBeforeReport(selectedAgentId);
      if (res?.ok) {
        toast.success(res.detail || 'Escaneo Syscheck/FIM disparado exitosamente');
        // Refrescar preview
        setTimeout(() => fetchPreview(selectedAgentId), 2500);
      } else {
        toast.warning(res?.detail || 'El manager no pudo iniciar el escaneo');
      }
    } catch (err: any) {
      toast.error('Error al solicitar escaneo: ' + (err.message || String(err)));
    } finally {
      setAuditing(false);
    }
  };

  const handleCopyTelegramShortcut = () => {
    const cmd = `/reporte ${selectedAgentId || '000'}`;
    navigator.clipboard.writeText(cmd);
    setCopiedTelegramCmd(true);
    toast.success(`Comando ${cmd} copiado para Telegram`);
    setTimeout(() => setCopiedTelegramCmd(false), 2000);
  };

  // Filtrado de apartados para la guía
  const filteredSections = REPORT_SECTIONS.filter(
    (s) => activeGuideCategory === 'todos' || s.category === activeGuideCategory
  );

  return (
    <div
      className="component-card healthy"
      style={{
        borderColor: 'rgba(168, 85, 247, 0.45)',
        background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%)',
      }}
    >
      {/* Cabecera */}
      <div className="card-top-row">
        <div className="card-identity">
          <div
            className="service-icon-box"
            style={{
              background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25), rgba(147, 51, 234, 0.15))',
              color: '#c084fc',
              border: '1px solid rgba(192, 132, 252, 0.3)',
            }}
          >
            <FileText size={20} />
          </div>
          <div>
            <div className="card-title-line">
              <span className="card-title">Generador de Reportes Forenses SOC</span>
              <span
                className="status-pill healthy"
                style={{
                  background: 'rgba(168, 85, 247, 0.18)',
                  color: '#c084fc',
                  border: '1px solid rgba(192, 132, 252, 0.3)',
                }}
              >
                PDF SOC v2.0 • 10 SECCIONES
              </span>
            </div>
            <div className="card-category">
              Expedientes forenses ejecutivos con foliado institucional dinámico, evaluación CIS Benchmark y auditoría profunda por host.
            </div>
          </div>
        </div>

        <button
          type="button"
          className="icon-tool-btn"
          onClick={fetchAgents}
          disabled={loadingAgents}
          title="Refrescar lista de agentes"
        >
          <RefreshCw size={14} className={loadingAgents ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Selector de Agente y Botones de Acción */}
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '12px', marginTop: '16px', flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 280px', minWidth: '220px' }}>
          <label
            htmlFor="report-agent-select"
            style={{
              display: 'block',
              fontSize: '11px',
              fontWeight: 700,
              color: 'var(--text-secondary)',
              marginBottom: '6px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
            }}
          >
            <Server size={12} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '5px', color: '#c084fc' }} />
            Seleccionar Endpoint a Auditar
          </label>
          <select
            id="report-agent-select"
            value={selectedAgentId}
            onChange={(e) => setSelectedAgentId(e.target.value)}
            disabled={loadingAgents || agents.length === 0}
            style={{
              width: '100%',
              padding: '10px 12px',
              borderRadius: '8px',
              border: '1px solid rgba(168, 85, 247, 0.3)',
              background: 'rgba(0, 0, 0, 0.4)',
              color: '#fff',
              fontSize: '13px',
              fontWeight: 600,
              outline: 'none',
              cursor: loadingAgents || agents.length === 0 ? 'not-allowed' : 'pointer',
              appearance: 'auto',
            }}
          >
            {loadingAgents ? (
              <option value="">Cargando endpoints del cluster...</option>
            ) : agents.length === 0 ? (
              <option value="">Sin endpoints disponibles</option>
            ) : (
              agents.map((a) => (
                <option key={a.id} value={a.id}>
                  [{a.id}] {a.name}{a.ip ? ` • IP: ${a.ip}` : ''} {a.status ? `(${a.status.toUpperCase()})` : ''}
                </option>
              ))
            )}
          </select>
        </div>

        {/* Botón Disparar Escaneo previo */}
        <button
          type="button"
          onClick={handleAuditScan}
          disabled={auditing || !selectedAgentId}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '10px 14px',
            borderRadius: '8px',
            border: '1px solid rgba(56, 189, 248, 0.35)',
            background: 'rgba(56, 189, 248, 0.12)',
            color: '#38bdf8',
            fontSize: '12px',
            fontWeight: 600,
            cursor: auditing || !selectedAgentId ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s ease',
            whiteSpace: 'nowrap',
          }}
          title="Fuerza un escaneo Syscheck/FIM antes de compilar el informe"
        >
          {auditing ? <Loader2 size={14} className="animate-spin" /> : <Scan size={14} />}
          <span>{auditing ? 'Escaneando...' : '🔍 Escaneo Pre-Reporte'}</span>
        </button>

        {/* Botón Descargar Reporte */}
        <button
          type="button"
          onClick={handleDownload}
          disabled={downloading || !selectedAgentId}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 20px',
            borderRadius: '8px',
            border: '1px solid rgba(168, 85, 247, 0.6)',
            background: downloading || !selectedAgentId
              ? 'rgba(168, 85, 247, 0.1)'
              : 'linear-gradient(135deg, rgba(168, 85, 247, 0.35), rgba(99, 102, 241, 0.35))',
            color: downloading || !selectedAgentId ? 'var(--text-secondary)' : '#f1f5f9',
            fontSize: '13px',
            fontWeight: 700,
            cursor: downloading || !selectedAgentId ? 'not-allowed' : 'pointer',
            whiteSpace: 'nowrap',
            boxShadow: '0 4px 12px rgba(168, 85, 247, 0.2)',
            transition: 'all 0.2s ease',
          }}
        >
          {downloading ? (
            <>
              <Loader2 size={15} className="animate-spin" />
              <span>Compilando PDF SOC v2.0...</span>
            </>
          ) : (
            <>
              <Download size={15} />
              <span>Descargar Informe PDF</span>
            </>
          )}
        </button>
      </div>

      {/* Snapshot Ejecutivo en Vivo del Endpoint */}
      {preview && (
        <div
          style={{
            marginTop: '16px',
            padding: '14px 16px',
            borderRadius: '10px',
            background: 'rgba(0, 0, 0, 0.3)',
            border: '1px solid rgba(168, 85, 247, 0.25)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9' }}>
                Ficha Previa: [{selectedAgentId}] {preview.name}
              </span>
              {loadingPreview && <Loader2 size={12} className="animate-spin" style={{ color: '#a855f7' }} />}
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  background: preview.status === 'active' ? 'rgba(46, 204, 113, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                  color: preview.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)',
                }}
              >
                {preview.status.toUpperCase()}
              </span>
            </div>

            <span style={{ fontSize: '11px', color: '#94a3b8' }}>
              SO: <strong style={{ color: '#e2e8f0' }}>{preview.os_desc}</strong> ({preview.arch})
            </span>
          </div>

          {/* Tarjetas de postura rápida */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '10px',
            }}
          >
            {/* CIS SCA */}
            <div
              style={{
                padding: '8px 10px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderRadius: '6px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
              }}
            >
              <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '2px' }}>
                POSTURA CIS SCA
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                <span
                  style={{
                    fontSize: '15px',
                    fontWeight: 800,
                    color: preview.sca_score >= 80 ? 'var(--green-healthy)' : preview.sca_score >= 60 ? 'var(--yellow-warning)' : 'var(--red-error)',
                  }}
                >
                  {preview.sca_score.toFixed(1)}%
                </span>
                <span style={{ fontSize: '10px', color: '#64748b' }}>
                  ({preview.sca_pass} / {preview.sca_total})
                </span>
              </div>
            </div>

            {/* Sockets Activos */}
            <div
              style={{
                padding: '8px 10px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderRadius: '6px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
              }}
            >
              <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '2px' }}>
                SOCKETS DE RED
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: '#38bdf8' }}>
                {preview.sockets_count} activos
              </div>
            </div>

            {/* Paquetes SBOM */}
            <div
              style={{
                padding: '8px 10px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderRadius: '6px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
              }}
            >
              <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '2px' }}>
                SOFTWARE (SBOM)
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: '#f59e0b' }}>
                {preview.total_packages} paquetes
              </div>
            </div>

            {/* Alertas SIEM */}
            <div
              style={{
                padding: '8px 10px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderRadius: '6px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
              }}
            >
              <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '2px' }}>
                ALERTAS CRÍTICAS
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: preview.critical_alerts_count > 0 ? '#ef4444' : 'var(--green-healthy)' }}>
                {preview.critical_alerts_count} (L10+)
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Atajo con Telegram Bot */}
      <div
        style={{
          marginTop: '12px',
          padding: '10px 14px',
          borderRadius: '8px',
          background: 'rgba(56, 189, 248, 0.04)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: '#94a3b8' }}>
          <Send size={14} style={{ color: '#38bdf8' }} />
          <span>
            ¿Estás en tu móvil? Puedes pedir este mismo reporte en Telegram enviando: <code style={{ color: '#38bdf8', fontWeight: 700 }}>/reporte {selectedAgentId || '000'}</code>
          </span>
        </div>

        <button
          type="button"
          onClick={handleCopyTelegramShortcut}
          style={{
            background: 'transparent',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: '6px',
            color: copiedTelegramCmd ? 'var(--green-healthy)' : '#38bdf8',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer',
            padding: '4px 10px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
          }}
        >
          {copiedTelegramCmd ? <Check size={12} /> : <Copy size={12} />}
          <span>{copiedTelegramCmd ? 'Copiado' : 'Copiar Comando'}</span>
        </button>
      </div>

      {/* Explorador de los 10 Apartados Forenses */}
      <div style={{ marginTop: '14px' }}>
        <button
          type="button"
          onClick={() => setShowGuide(!showGuide)}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#c084fc',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 0',
          }}
        >
          <Info size={14} />
          {showGuide ? 'Ocultar desglose de los 10 apartados forenses' : 'Ver apartados, evidencias y objetivos del informe oficial'}
          {showGuide ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showGuide && (
          <div
            style={{
              marginTop: '10px',
              padding: '14px',
              borderRadius: '8px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid rgba(168, 85, 247, 0.2)',
            }}
          >
            {/* Pestañas de categorías */}
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
              {(['todos', 'general', 'red', 'cumplimiento', 'siem'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setActiveGuideCategory(cat)}
                  style={{
                    padding: '3px 10px',
                    borderRadius: '12px',
                    fontSize: '11px',
                    fontWeight: 600,
                    border: '1px solid',
                    borderColor: activeGuideCategory === cat ? '#c084fc' : 'rgba(255, 255, 255, 0.08)',
                    background: activeGuideCategory === cat ? 'rgba(168, 85, 247, 0.2)' : 'rgba(255, 255, 255, 0.02)',
                    color: activeGuideCategory === cat ? '#c084fc' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    textTransform: 'capitalize',
                  }}
                >
                  {cat === 'todos' ? 'Todos los 10 Apartados' : cat}
                </button>
              ))}
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
                gap: '10px',
              }}
            >
              {filteredSections.map((sec) => {
                const IconComp = sec.icon;
                return (
                  <div
                    key={sec.num}
                    style={{
                      padding: '10px 12px',
                      borderRadius: '8px',
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <div
                        style={{
                          padding: '5px',
                          borderRadius: '5px',
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: sec.color,
                          display: 'flex',
                        }}
                      >
                        <IconComp size={14} />
                      </div>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: '#f1f5f9' }}>
                        <span style={{ color: sec.color, marginRight: '4px' }}>{sec.num}.</span>
                        {sec.title}
                      </span>
                    </div>
                    <p style={{ fontSize: '11px', color: '#94a3b8', margin: '3px 0 5px 0', lineHeight: 1.35 }}>
                      {sec.desc}
                    </p>
                    <p style={{ fontSize: '10px', color: '#64748b', margin: 0, fontStyle: 'italic', lineHeight: 1.3 }}>
                      💡 {sec.detail}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {agents.length === 0 && !loadingAgents && (
        <div
          style={{
            marginTop: '14px',
            padding: '16px',
            textAlign: 'center',
            color: 'var(--text-secondary)',
            fontSize: '12px',
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: '8px',
          }}
        >
          No se encontraron endpoints registrados en Wazuh. Verificá la conectividad con el Manager.
        </div>
      )}
    </div>
  );
};

export default ReportsCard;
