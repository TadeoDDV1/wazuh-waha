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
} from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  ip?: string;
  status?: string;
}

const REPORT_SECTIONS = [
  {
    num: '01',
    title: 'Identificación y Enlace',
    icon: Server,
    color: '#0284c7',
    desc: 'ID, hostname, IP de enlace, versión de agente y vigencia de sincronización con el Manager (keep-alive).',
    detail: 'Garantiza que el canal criptográfico esté sincronizado y que el endpoint no haya sido desconectado o aislado.',
  },
  {
    num: '02',
    title: 'Hardware y Recursos',
    icon: Cpu,
    color: '#0284c7',
    desc: 'Microprocesador (CPU, núcleos, MHz), memoria RAM (total, usada, % y libre) y serial de placa madre.',
    detail: 'Permite detectar saturación por ataques DoS o minería no autorizada, y valida números de serie contra activos inventariados.',
  },
  {
    num: '03',
    title: 'Sistema Operativo y Kernel',
    icon: Layers,
    color: '#059669',
    desc: 'Distribución, arquitectura, hostname y versión exacta del kernel en ejecución.',
    detail: 'Delimita la superficie de ataque inicial y permite evaluar la exposición frente a exploits locales de escalamiento (LPE).',
  },
  {
    num: '04',
    title: 'Interfaces de Red y Tráfico',
    icon: Network,
    color: '#0891b2',
    desc: 'Adaptadores físicos y virtuales, IPv4, MAC address, MTU y volumen acumulado de tráfico RX y TX.',
    detail: 'Descubre adaptadores en modo promiscuo, interfaces bridge sospechosas o volúmenes anómalos de exfiltración de datos.',
  },
  {
    num: '05',
    title: 'Destinos de Red & Sockets',
    icon: Activity,
    color: '#0284c7',
    desc: 'Sockets activos hacia IPs remotas, puertos, procesos locales asociados y categorización de dominio.',
    detail: 'Primera línea de defensa para identificar balizas de Command & Control (C2), troyanos o navegación indebida.',
  },
  {
    num: '06',
    title: 'Procesos en Ejecución',
    icon: Terminal,
    color: '#059669',
    desc: 'Listado de binarios en memoria con su PID, nombre ejecutable, usuario y estado de ejecución.',
    detail: 'Permite descubrir scripts ocultos, procesos sospechosos corriendo como root/SYSTEM o ejecutables desde rutas temporales.',
  },
  {
    num: '07',
    title: 'Software y Paquetería',
    icon: Package,
    color: '#ea580c',
    desc: 'Inventario SBOM de paquetes y aplicaciones registradas por el módulo Syscollector de Wazuh.',
    detail: 'Base para la gestión de vulnerabilidades conocidas (CVEs), control de parches y detección de software no homologado.',
  },
  {
    num: '08',
    title: 'Seguridad SCA (CIS Benchmark)',
    icon: ShieldCheck,
    color: '#059669',
    desc: 'Score global de cumplimiento frente a normas CIS, controles aprobados, fallidos y remediaciones.',
    detail: 'Audita directrices de hardening del sistema (permisos, contraseñas, servicios seguros) con comandos técnicos de solución.',
  },
  {
    num: '09',
    title: 'Integridad de Archivos (FIM)',
    icon: FileCode,
    color: '#7c3aed',
    desc: 'Auditoría Syscheck de archivos modificados, eliminados o creados con hashes criptográficos MD5/SHA256.',
    detail: 'Detecta manipulación de ficheros críticos de autenticación (/etc/passwd) o sustitución maliciosa de binarios del sistema.',
  },
  {
    num: '10',
    title: 'Detecciones SIEM Wazuh',
    icon: AlertTriangle,
    color: '#dc2626',
    desc: 'Incidentes y alertas correlacionadas por reglas Wazuh, clasificadas por severidad (L1 a L15).',
    detail: 'Evidencia directa de ataques e intrusiones (fuerza bruta, escaneo de puertos, inyecciones) para respuesta inmediata del SOC.',
  },
];

export const ReportsCard: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [showGuide, setShowGuide] = useState(false);

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
      toast.success(`Reporte PDF del agente [${selectedAgentId}] descargado exitosamente.`);
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

  const selectedAgent = agents.find((a) => a.id === selectedAgentId);

  return (
    <div className="component-card healthy" style={{ borderColor: 'rgba(168, 85, 247, 0.35)' }}>
      <div className="card-top-row">
        <div className="card-identity">
          <div className="service-icon-box" style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>
            <FileText size={20} />
          </div>
          <div>
            <div className="card-title-line">
              <span className="card-title">Reportes Forenses & Auditoría de Seguridad</span>
              <span
                className="status-pill healthy"
                style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}
              >
                PDF SOC v2.0
              </span>
            </div>
            <div className="card-category">
              Generá y descargá un informe forense con diseño ejecutivo, KPIs de postura, explicaciones técnicas por sección y foliado institucional para cualquier agente Wazuh.
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

      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '14px', marginTop: '16px', flexWrap: 'wrap' }}>
        {/* Selector de agente */}
        <div style={{ flex: '1 1 260px', minWidth: '220px' }}>
          <label
            htmlFor="report-agent-select"
            style={{
              display: 'block',
              fontSize: '11px',
              fontWeight: 600,
              color: 'var(--text-secondary)',
              marginBottom: '5px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
            }}
          >
            <Server size={12} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '4px' }} />
            Seleccionar Agente Wazuh
          </label>
          <select
            id="report-agent-select"
            value={selectedAgentId}
            onChange={(e) => setSelectedAgentId(e.target.value)}
            disabled={loadingAgents || agents.length === 0}
            style={{
              width: '100%',
              padding: '9px 12px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              background: 'rgba(0, 0, 0, 0.3)',
              color: '#fff',
              fontSize: '13px',
              outline: 'none',
              cursor: loadingAgents || agents.length === 0 ? 'not-allowed' : 'pointer',
              appearance: 'auto',
            }}
          >
            {loadingAgents ? (
              <option value="">Cargando agentes...</option>
            ) : agents.length === 0 ? (
              <option value="">Sin agentes disponibles</option>
            ) : (
              agents.map((a) => (
                <option key={a.id} value={a.id}>
                  [{a.id}] {a.name}{a.ip ? ` (${a.ip})` : ''} {a.status ? `— ${a.status}` : ''}
                </option>
              ))
            )}
          </select>
        </div>

        {/* Botón descargar */}
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
            border: '1px solid rgba(168, 85, 247, 0.5)',
            background: downloading || !selectedAgentId
              ? 'rgba(168, 85, 247, 0.1)'
              : 'linear-gradient(135deg, rgba(168, 85, 247, 0.25), rgba(59, 130, 246, 0.25))',
            color: downloading || !selectedAgentId ? 'var(--text-secondary)' : '#c084fc',
            fontSize: '13px',
            fontWeight: 700,
            cursor: downloading || !selectedAgentId ? 'not-allowed' : 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.2s ease',
          }}
        >
          {downloading ? (
            <>
              <Loader2 size={15} className="animate-spin" />
              Compilando Informe PDF...
            </>
          ) : (
            <>
              <Download size={15} />
              Descargar Informe Forense PDF
            </>
          )}
        </button>
      </div>

      {/* Info del agente seleccionado */}
      {selectedAgent && (
        <div
          style={{
            marginTop: '14px',
            padding: '10px 14px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            display: 'flex',
            gap: '20px',
            alignItems: 'center',
            flexWrap: 'wrap',
          }}
        >
          <span>
            Endpoint: <strong style={{ color: '#fff' }}>[{selectedAgent.id}] {selectedAgent.name}</strong>
          </span>
          {selectedAgent.ip && (
            <span>
              IP: <code style={{ color: '#38bdf8' }}>{selectedAgent.ip}</code>
            </span>
          )}
          {selectedAgent.status && (
            <span>
              Enlace:{' '}
              <strong style={{ color: selectedAgent.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)' }}>
                {selectedAgent.status.toUpperCase()}
              </strong>
            </span>
          )}
          <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span
              style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '12px',
                background: 'rgba(56, 189, 248, 0.1)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.2)',
              }}
            >
              10 Secciones Forenses
            </span>
          </span>
        </div>
      )}

      {/* Botón para expandir guía explicativa de apartados */}
      <div style={{ marginTop: '12px' }}>
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
          {showGuide ? 'Ocultar estructura de apartados' : 'Ver apartados y objetivos explicados en el informe'}
          {showGuide ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showGuide && (
          <div
            style={{
              marginTop: '10px',
              padding: '14px',
              borderRadius: '8px',
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid rgba(168, 85, 247, 0.2)',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: '10px',
            }}
          >
            {REPORT_SECTIONS.map((sec) => {
              const IconComp = sec.icon;
              return (
                <div
                  key={sec.num}
                  style={{
                    padding: '10px',
                    borderRadius: '6px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <div
                      style={{
                        padding: '4px',
                        borderRadius: '4px',
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
                  <p style={{ fontSize: '11px', color: '#94a3b8', margin: '2px 0 4px 0', lineHeight: 1.35 }}>
                    {sec.desc}
                  </p>
                  <p style={{ fontSize: '10px', color: '#64748b', margin: 0, fontStyle: 'italic', lineHeight: 1.3 }}>
                    💡 {sec.detail}
                  </p>
                </div>
              );
            })}
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
          No se encontraron agentes Wazuh. Verificá la conexión con el manager.
        </div>
      )}
    </div>
  );
};

export default ReportsCard;
