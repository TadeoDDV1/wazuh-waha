import React, { useState, useEffect, useCallback } from 'react';
import './ComponentCard.css';
import './ReportsCard.css';
import { dashboardService } from '../services/api';
import { toast } from 'sonner';
import {
  FileText,
  Download,
  Loader2,
  RefreshCw,
  Server,
  Activity,
  Layers,
  FileCode,
  Terminal,
  AlertTriangle,
  Scan,
  Send,
  CheckCircle2,
  FileCheck,
  HardDrive,
  Cpu,
  Globe,
  Lock,
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

interface ReportSectionInfo {
  num: string;
  title: string;
  category: 'general' | 'red' | 'cumplimiento' | 'siem';
  icon: React.ReactNode;
  source: string;
  desc: string;
  details: string;
}

const REPORT_SECTIONS: ReportSectionInfo[] = [
  {
    num: '§01',
    title: 'Portada y Metadatos del Expediente',
    category: 'general',
    icon: <FileText size={14} />,
    source: 'Metadata Relay / Wazuh API',
    desc: 'Foliado institucional único, fecha ISO, autor del informe y alcance forense.',
    details: 'Incluye folio dinámico SOC-REP-ID-TS, hash de integridad, datos de la organización y sellado de tiempo de emisión.',
  },
  {
    num: '§02',
    title: 'Resumen Ejecutivo y Estado del Host',
    category: 'general',
    icon: <Cpu size={14} />,
    source: 'wazuh-manager syscollector_os',
    desc: 'Postura global del endpoint, hardware, uptime y distribución Linux/Windows.',
    details: 'Detalla nombre del host, IP de conexión, sistema operativo, versión del kernel, arquitectura CPU y memoria RAM asignada.',
  },
  {
    num: '§03',
    title: 'Topología e Interfaces de Red',
    category: 'red',
    icon: <Globe size={14} />,
    source: 'syscollector_netiface',
    desc: 'Direcciones IP asignadas, máscaras de subred, puertas de enlace y MACs.',
    details: 'Mapea adaptadores Ethernet, Wi-Fi y Loopback con direcciones IPv4, IPv6, MTU y métricas de transmisión de paquetes.',
  },
  {
    num: '§04',
    title: 'Puertos de Red y Sockets Activos',
    category: 'red',
    icon: <Globe size={14} />,
    source: 'syscollector_ports',
    desc: 'Servicios en escucha (LISTEN) en protocolos TCP/UDP y procesos asociados.',
    details: 'Inventario de superficie de ataque externa con números de puerto, IP de enlace local y PID del proceso en ejecución.',
  },
  {
    num: '§05',
    title: 'Inventario de Software Instalado (SBOM)',
    category: 'general',
    icon: <HardDrive size={14} />,
    source: 'syscollector_packages',
    desc: 'Catálogo de paquetería de software detectada para análisis de CVEs.',
    details: 'Listado exhaustivo de aplicaciones instaladas (apt, dpkg, rpm, pacman o MSI) con versión exacta y vendor para auditoría de vulnerabilidades.',
  },
  {
    num: '§06',
    title: 'Procesos Activos y Consumo de Recursos',
    category: 'general',
    icon: <Activity size={14} />,
    source: 'syscollector_processes',
    desc: 'Árbol de procesos en ejecución, consumo de CPU/RAM y usuario titular.',
    details: 'Forense de procesos activos identificando PIDs anómalos, rutas de binarios y comandos completos de inicialización.',
  },
  {
    num: '§07',
    title: 'Auditoría de Configuración de Seguridad (CIS SCA)',
    category: 'cumplimiento',
    icon: <Lock size={14} />,
    source: 'sca_checks_eval',
    desc: 'Puntaje de cumplimiento CIS Benchmark con fallos de hardening específicos.',
    details: 'Porcentaje de cumplimiento de seguridad del sistema, pruebas aprobadas vs falladas, con archivo de políticas y remediación recomendada.',
  },
  {
    num: '§08',
    title: 'Monitoreo de Integridad de Archivos (FIM / Syscheck)',
    category: 'cumplimiento',
    icon: <FileCheck size={14} />,
    source: 'syscheck_database',
    desc: 'Archivos críticos del sistema monitoreados con hashes MD5/SHA256.',
    details: 'Rastreo de modificaciones no autorizadas en archivos binarios, directorios de configuración `/etc` y registros del sistema.',
  },
  {
    num: '§09',
    title: 'Alertas Recientes y Eventos SIEM Correlacionados',
    category: 'siem',
    icon: <AlertTriangle size={14} />,
    source: 'wazuh_alerts_log',
    desc: 'Últimos incidentes de seguridad registrados por el motor de análisis de reglas.',
    details: 'Historial de alertas SIEM con ID de regla, nivel de severidad (8-15), descripción de la anomalía y MITRE ATT&CK ID asociado.',
  },
  {
    num: '§10',
    title: 'Conclusiones y Recomendaciones de Hardening',
    category: 'siem',
    icon: <CheckCircle2 size={14} />,
    source: 'Motor Forense SOC',
    desc: 'Veredicto de riesgo, acciones de mitigación prioritarias y sello del SOC.',
    details: 'Dictamen de seguridad ejecutivo con matriz de acciones preventivas, cierre criptográfico y sello de autenticidad institucional.',
  },
];

export const ReportsCard: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [auditing, setAuditing] = useState(false);
  const [activeTab, setActiveTab] = useState<'secciones' | 'guia' | 'telegram'>('secciones');
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
    } catch {
      setAgents([]);
    } finally {
      setLoadingAgents(false);
    }
  }, [selectedAgentId]);

  useEffect(() => {
    fetchAgents();
  }, [fetchAgents]);

  const fetchPreview = useCallback(async (aid: string) => {
    if (!aid) return;
    setLoadingPreview(true);
    try {
      const data = await dashboardService.getAgentReportPreview(aid);
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
      toast.warning('Selecciona un agente para generar el reporte forense.');
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
      toast.success(`Informe Forense PDF del Agente [${selectedAgentId}] descargado exitosamente`);
    } catch (e: any) {
      toast.error('Error al generar el reporte: ' + (e.message || String(e)));
    } finally {
      setDownloading(false);
    }
  };

  const handleAuditScan = async () => {
    if (!selectedAgentId) return;
    setAuditing(true);
    try {
      const res = await dashboardService.auditAgentBeforeReport(selectedAgentId);
      if (res?.ok) {
        toast.success(`✓ ${res.detail || 'Escaneo FIM disparado correctamente'}`);
        fetchPreview(selectedAgentId);
      } else {
        toast.error(res?.detail || 'No se pudo iniciar el escaneo de auditoría');
      }
    } catch (e: any) {
      toast.error('Error al iniciar auditoría: ' + (e.message || String(e)));
    } finally {
      setAuditing(false);
    }
  };

  const handleCopyTelegramCommand = () => {
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
    <div className="component-card reports-card status-healthy">
      {/* Cabecera Estándar ComponentCard */}
      <div className="card-header">
        <div className="card-title-group">
          <div
            className="card-icon-wrapper"
            style={{
              background: 'rgba(168, 85, 247, 0.15)',
              borderColor: 'rgba(168, 85, 247, 0.35)',
            }}
          >
            <FileText size={18} style={{ color: '#c084fc' }} />
          </div>
          <div className="card-name-block">
            <h3 className="card-name">Centro de Reportes Forenses & Auditoría SOC</h3>
            <span className="card-category-tag">EXPEDIENTES OFICIALES · PDF VECTORIAL v2.0</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div className="status-badge-chip healthy">
            <span className="status-dot" />
            <span>10 SECCIONES ACTIVAS</span>
          </div>
          <button
            type="button"
            className="card-action-btn"
            onClick={fetchAgents}
            disabled={loadingAgents}
            title="Refrescar lista de agentes"
            style={{ padding: '0.35rem 0.55rem' }}
          >
            <RefreshCw size={13} className={loadingAgents ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Cuerpo de la Tarjeta */}
      <div className="card-body">
        <p className="card-description">
          Expedientes forenses ejecutivos con foliado institucional dinámico, evaluación CIS Benchmark y auditoría profunda por host.
        </p>

        {/* Panel de Control y Selección de Endpoint */}
        <div className="reports-control-panel">
          <div className="reports-agent-selector-wrap">
            <label htmlFor="report-agent-select" className="reports-select-label">
              <Server size={12} style={{ color: '#c084fc' }} />
              <span>Seleccionar Endpoint a Auditar</span>
            </label>
            <select
              id="report-agent-select"
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              disabled={loadingAgents || agents.length === 0}
              className="reports-select-control"
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

          <button
            type="button"
            onClick={handleAuditScan}
            disabled={auditing || !selectedAgentId}
            className="reports-btn-scan"
            title="Fuerza un escaneo Syscheck/FIM antes de compilar el informe"
          >
            {auditing ? <Loader2 size={14} className="animate-spin" /> : <Scan size={14} />}
            <span>{auditing ? 'Escaneando...' : 'Escaneo Pre-Reporte'}</span>
          </button>

          <button
            type="button"
            onClick={handleDownload}
            disabled={downloading || !selectedAgentId}
            className="reports-btn-download"
          >
            {downloading ? <Loader2 size={15} className="animate-spin" /> : <Download size={15} />}
            <span>{downloading ? 'Compilando PDF SOC v2.0...' : 'Descargar Informe PDF'}</span>
          </button>

          <button
            type="button"
            onClick={handleCopyTelegramCommand}
            className="card-action-btn"
            title="Copia el comando para solicitar el PDF directamente en Telegram"
            style={{ padding: '0.6rem 0.85rem' }}
          >
            <Send size={13} style={{ color: '#38bdf8' }} />
            <span>{copiedTelegramCmd ? '¡Copiado!' : `/reporte ${selectedAgentId || '000'}`}</span>
          </button>
        </div>

        {/* Snapshot Ejecutivo en Vivo del Endpoint */}
        {preview && (
          <div className="reports-snapshot-panel">
            <div className="reports-snapshot-header">
              <div className="reports-snapshot-host">
                <span className="reports-host-tag">
                  [{selectedAgentId}] {preview.name}
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

              <span className="reports-host-os">
                SO: <strong style={{ color: '#e2e8f0' }}>{preview.os_desc}</strong> ({preview.arch}) · Kernel: {preview.kernel}
              </span>
            </div>

            {/* Grilla Forense de 4 Widgets */}
            <div className="reports-kpi-grid">
              {/* CIS SCA */}
              <div className="reports-kpi-box">
                <span className="reports-kpi-title">Postura CIS SCA</span>
                <span
                  className="reports-kpi-metric"
                  style={{
                    color: preview.sca_score >= 80 ? 'var(--green-healthy)' : preview.sca_score >= 60 ? 'var(--yellow-warning)' : 'var(--red-error)',
                  }}
                >
                  {preview.sca_score.toFixed(1)}%
                </span>
                <div className="reports-progress-track">
                  <div
                    className="reports-progress-fill"
                    style={{
                      width: `${Math.min(Math.max(preview.sca_score, 5), 100)}%`,
                      background: preview.sca_score >= 80 ? 'var(--green-healthy)' : preview.sca_score >= 60 ? 'var(--yellow-warning)' : 'var(--red-error)',
                    }}
                  />
                </div>
                <span className="reports-kpi-detail">
                  {preview.sca_pass} ok / {preview.sca_fail} fail ({preview.sca_total} eval)
                </span>
              </div>

              {/* Inventario SBOM */}
              <div className="reports-kpi-box">
                <span className="reports-kpi-title">Inventario SBOM</span>
                <span className="reports-kpi-metric" style={{ color: '#38bdf8' }}>
                  {preview.total_packages.toLocaleString()}
                </span>
                <span className="reports-kpi-detail">
                  Paquetes y bibliotecas en Syscollector
                </span>
              </div>

              {/* Alertas SIEM */}
              <div className="reports-kpi-box">
                <span className="reports-kpi-title">Alertas SIEM Host</span>
                <span className="reports-kpi-metric" style={{ color: preview.critical_alerts_count > 0 ? 'var(--red-error)' : '#c084fc' }}>
                  {preview.recent_alerts_count}
                </span>
                <span className="reports-kpi-detail">
                  {preview.critical_alerts_count > 0 ? `${preview.critical_alerts_count} Críticas correlacionadas` : 'Sin eventos críticos recientes'}
                </span>
              </div>

              {/* Hardware & Sockets */}
              <div className="reports-kpi-box">
                <span className="reports-kpi-title">Memoria & Sockets</span>
                <span className="reports-kpi-metric" style={{ color: '#f59e0b' }}>
                  {preview.ram_usage_pct}% RAM
                </span>
                <span className="reports-kpi-detail">
                  {preview.sockets_count} Sockets activos ({Math.round(preview.ram_used_mb)} / {Math.round(preview.ram_total_mb)} MB)
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Sub-Pestañas de Navegación del Centro de Reportes */}
        <div className="soc-nav-tabs" style={{ marginTop: '16px' }}>
          <button
            type="button"
            className={`soc-tab-btn ${activeTab === 'secciones' ? 'active' : ''}`}
            onClick={() => setActiveTab('secciones')}
          >
            <Layers size={14} />
            <span>Estructura del Expediente (10 Secciones)</span>
          </button>
          <button
            type="button"
            className={`soc-tab-btn ${activeTab === 'guia' ? 'active' : ''}`}
            onClick={() => setActiveTab('guia')}
          >
            <FileCode size={14} />
            <span>Guía Técnica & Normativas</span>
          </button>
          <button
            type="button"
            className={`soc-tab-btn ${activeTab === 'telegram' ? 'active' : ''}`}
            onClick={() => setActiveTab('telegram')}
          >
            <Terminal size={14} />
            <span>Comandos Móviles Telegram</span>
          </button>
        </div>

        {/* Pestaña 1: Estructura de las 10 Secciones Forenses */}
        {activeTab === 'secciones' && (
          <div className="reports-sections-grid">
            {REPORT_SECTIONS.map((sec) => (
              <div key={sec.num} className="reports-section-card">
                <div className="reports-section-head">
                  <div className="reports-section-title">
                    <span style={{ color: '#c084fc' }}>{sec.icon}</span>
                    <span>{sec.title}</span>
                  </div>
                  <span
                    className="reports-section-badge"
                    style={{
                      background: 'rgba(168, 85, 247, 0.15)',
                      color: '#c084fc',
                      border: '1px solid rgba(168, 85, 247, 0.3)',
                    }}
                  >
                    {sec.num}
                  </span>
                </div>

                <p className="reports-section-desc">{sec.desc}</p>

                <div className="reports-section-source">
                  <FileText size={11} />
                  <span>{sec.source}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pestaña 2: Guía Técnica con Filtro */}
        {activeTab === 'guia' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '4px' }}>
              {[
                { id: 'todos', label: 'Todos los Apartados', count: 10 },
                { id: 'general', label: 'General & Sistema', count: 4 },
                { id: 'red', label: 'Red & Sockets', count: 2 },
                { id: 'cumplimiento', label: 'Cumplimiento CIS', count: 2 },
                { id: 'siem', label: 'SIEM & Mitigación', count: 2 },
              ].map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={`category-pill ${activeGuideCategory === c.id ? 'active' : ''}`}
                  onClick={() => setActiveGuideCategory(c.id as any)}
                >
                  <span>{c.label}</span>
                  <span style={{ opacity: 0.65, fontSize: '10px' }}>({c.count})</span>
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {filteredSections.map((s) => (
                <div
                  key={s.num}
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ color: '#c084fc', fontSize: '12px', fontWeight: 800 }}>{s.num}</span>
                      <strong style={{ color: '#f8fafc', fontSize: '13px' }}>{s.title}</strong>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {s.source}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                    {s.details}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Pestaña 3: Automatización Móvil vía Telegram */}
        {activeTab === 'telegram' && (
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Send size={16} style={{ color: '#38bdf8' }} />
              <h4 style={{ margin: 0, fontSize: '14px', color: '#f8fafc' }}>
                Solicitud y Despacho Automatizado de Reportes desde Telegram
              </h4>
            </div>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Puedes solicitar informes forenses completos desde tu teléfono móvil. El Bot compila el PDF vectorial en el servidor en tiempo real y te envía el archivo directamente por el chat.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
              <div
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#38bdf8', fontWeight: 700 }}>
                  /reporte {selectedAgentId || '000'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Compila y descarga el PDF forense completo de 10 secciones en el chat.
                </div>
              </div>

              <div
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#38bdf8', fontWeight: 700 }}>
                  /analizar_agente {selectedAgentId || '000'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Dispara escaneos Wazuh FIM/SCA y entrega resumen de hardening inmediato.
                </div>
              </div>

              <div
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#38bdf8', fontWeight: 700 }}>
                  /sca {selectedAgentId || '000'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Consulta inmediata de la evaluación de cumplimiento CIS Benchmark.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer Estándar ComponentCard */}
      <div className="card-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Foliado Institucional: SOC-REP-{selectedAgentId || '000'}-v2
          </span>
        </div>

        <div className="card-actions">
          <button
            type="button"
            className="card-action-btn"
            onClick={handleDownload}
            disabled={downloading || !selectedAgentId}
          >
            {downloading ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
            <span>{downloading ? 'Descargando...' : 'Descargar PDF'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReportsCard;
