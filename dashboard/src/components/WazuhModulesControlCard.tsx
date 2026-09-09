import React, { useEffect, useState, useCallback } from 'react';
import { dashboardService } from '../services/api';
import {
  Sliders,
  CheckCircle2,
  XCircle,
  RotateCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  HardDrive,
  Search,
  Zap,
  Save,
  Undo2,
  ExternalLink,
  Radio,
  Server,
  ChevronDown,
  ChevronRight,
  FileSearch,
  Cpu,
  Info,
  AlertTriangle,
  Copy,
  Check,
  Activity,
  Layers,
  FileText,
  Lock,
  Terminal,
  FileCheck,
} from 'lucide-react';
import { toast } from 'sonner';

/* ─── Types ─── */
interface ScopeOption {
  id: string;
  name: string;
  status: string;
  ip?: string;
  os?: string;
}

interface ModuleMeta {
  id: string;
  group_id?: string;
  name: string;
  icon: string;
  directive: string;
  description: string;
}

interface ModuleGroup {
  id: string;
  title: string;
  icon: string;
  description: string;
  module_ids: string[];
}

interface SecurityRecommendation {
  module_id: string;
  module_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  issue: string;
  remediation: string;
  impact: string;
}

interface AgentHealthInfo {
  connected: boolean;
  status: string;
  badge: string;
  color: string;
  last_sync: string;
}

/* ─── Default Groups Definition ─── */
const DEFAULT_GROUPS: ModuleGroup[] = [
  {
    id: 'audit',
    title: 'AUDITORÍA Y CONFIGURACIÓN DEL SISTEMA',
    icon: '🛡️',
    description: 'Evaluación continua de seguridad, auditorías CIS benchmark, detección de malware/rootkits y monitoreo de integridad de archivos.',
    module_ids: ['sca', 'rootcheck', 'fim'],
  },
  {
    id: 'endpoint',
    title: 'SEGURIDAD DE LOS PUNTOS FINALES',
    icon: '🎯',
    description: 'Caza proactiva de amenazas, respuesta activa automatizada, detección de vulnerabilidades conocidas (CVEs) y correlación MITRE ATT&CK.',
    module_ids: ['threat_hunting', 'vulnerabilities', 'mitre'],
  },
  {
    id: 'threat_intel',
    title: 'INTELIGENCIA SOBRE AMENAZAS Y CUMPLIMIENTO',
    icon: '📜',
    description: 'Higiene informática (inventario de hardware, SO, paquetes y puertos) y evaluación de marcos de cumplimiento regulatorio global.',
    module_ids: ['syscollector', 'pci_dss', 'gdpr', 'hipaa', 'nist_800_53', 'tsc'],
  },
];

/* ─── Wazuh rule reference table per module ─── */
const MODULE_RULES: Record<string, { id: string; event: string; condition: string }[]> = {
  fim: [
    { id: '550', event: 'Archivo Creado', condition: 'Nuevo archivo detectado en directorio monitorizado (/etc, /usr/bin)' },
    { id: '553', event: 'Archivo Modificado', condition: 'Hash MD5/SHA256 difiere del baseline guardado en Wazuh DB' },
    { id: '554', event: 'Archivo Eliminado', condition: 'Archivo crítico monitoreado ya no está presente en el disco' },
    { id: '552', event: 'Permisos Cambiados', condition: 'Cambio de permisos (chmod) detectado sobre binario o conf del sistema' },
    { id: '551', event: 'Propietario Cambiado', condition: 'chown detectado sobre archivo monitorizado por el daemon syscheck' },
  ],
  sca: [
    { id: '19001', event: 'Inicio de Escaneo SCA', condition: 'Evaluación CIS benchmark comenzada para la distribución del agente' },
    { id: '19002', event: 'Control CIS Fallido', condition: 'Control de seguridad no cumple el estándar de endurecimiento CIS' },
    { id: '19003', event: 'Control CIS Pasado', condition: 'Control de seguridad cumple satisfactoriamente el benchmark' },
    { id: '19004', event: 'Nueva Política SCA', condition: 'Nueva política de auditoría YAML/XML sincronizada con el agente' },
    { id: '19005', event: 'Regresión de Seguridad', condition: 'Un control CIS que pasaba anteriormente ahora se encuentra fallando' },
  ],
  rootcheck: [
    { id: '510', event: 'Rootkit Detectado', condition: 'Archivo oculto, proceso fantasma o binario en /proc anómalo detectado' },
    { id: '511', event: 'Firma de Troyano', condition: 'Firma de rootkit o troyano conocido encontrada en firmas ossec rootcheck' },
    { id: '512', event: 'Anomalía de Kernel', condition: 'Llamadas al sistema interceptadas o inconsistencia en tabla de syscalls' },
    { id: '513', event: 'Puerto Oculto en Red', condition: 'Puerto de red abierto no listado por las utilidades estándar del SO' },
  ],
  threat_hunting: [
    { id: '601', event: 'Respuesta Activa Disparada', condition: 'Script de contención automática ejecutado por alerta de severidad alta' },
    { id: '602', event: 'IP Bloqueada en Firewall', condition: 'IP hostil bloqueada vía iptables/nftables por detección de fuerza bruta' },
    { id: '603', event: 'Usuario Suspendido', condition: 'Cuenta local deshabilitada preventivamente por anomalía de inicio de sesión' },
    { id: '5712', event: 'Fuerza Bruta SSH', condition: 'Múltiples intentos fallidos de autenticación SSH dentro de la ventana de tiempo' },
  ],
  vulnerabilities: [
    { id: '23501', event: 'Vulnerabilidad Detectada', condition: 'Paquete instalado coincide con CVE reportado en National Vulnerability Database' },
    { id: '23502', event: 'CVE de Severidad Crítica', condition: 'Vulnerabilidad con puntuación CVSSv3 >= 9.0 encontrada en el agente' },
    { id: '23503', event: 'CVE de Severidad Alta', condition: 'Vulnerabilidad con puntuación CVSSv3 entre 7.0 y 8.9 encontrada' },
    { id: '23504', event: 'Vulnerabilidad Resuelta', condition: 'El paquete vulnerable fue actualizado a una versión con parche de seguridad' },
  ],
  mitre: [
    { id: '100002', event: 'T1078 - Cuentas Válidas', condition: 'Uso anómalo o fuera de horario de credenciales legítimas en el sistema' },
    { id: '100003', event: 'T1059 - Intérprete de Comandos', condition: 'Ejecución de scripts sospechosos en bash, python o sh en segundo plano' },
    { id: '100004', event: 'T1110 - Fuerza Bruta', condition: 'Intentos reiterados de adivinanza de credenciales en servicios de red' },
    { id: '100005', event: 'T1053 - Tareas Programadas', condition: 'Nueva entrada no autorizada en crontab o timers de systemd' },
  ],
  syscollector: [
    { id: '5501', event: 'Inventario de Hardware', condition: 'CPU, memoria RAM, discos e interfaces recolectados por wodle syscollector' },
    { id: '5502', event: 'Inventario de SO', condition: 'Versión de kernel, arquitectura y release del sistema operativo reportada' },
    { id: '5503', event: 'Inventario de Paquetes', condition: 'Lista de paquetes deb/rpm instalados actualizada en Wazuh DB' },
    { id: '5504', event: 'Inventario de Procesos', condition: 'Procesos en ejecución sincronizados con la base de datos de telemetría' },
    { id: '5505', event: 'Inventario de Puertos', condition: 'Puertos TCP/UDP en estado LISTEN reportados en el agente' },
  ],
  pci_dss: [
    { id: '106', event: 'PCI DSS Req 10.2', condition: 'Registro de accesos y acciones tomadas por usuarios con privilegios root' },
    { id: '5710', event: 'PCI DSS Req 8.1', condition: 'Monitoreo de políticas de autenticación y control de accesos de usuario' },
    { id: '5712', event: 'PCI DSS Req 11.4', condition: 'Detección y prevención de intrusiones en entornos de tarjetahabientes' },
  ],
  gdpr: [
    { id: '1002', event: 'RGPD Art. 32', condition: 'Medidas técnicas y organizativas para garantizar la seguridad del tratamiento' },
    { id: '1003', event: 'RGPD Art. 33', condition: 'Detección temprana y registro de incidentes de seguridad que afecten datos personales' },
    { id: '550', event: 'RGPD Trazabilidad', condition: 'Trazabilidad de modificaciones sobre directorios con almacenamiento de datos' },
  ],
  hipaa: [
    { id: '106', event: 'HIPAA 164.312.b', condition: 'Controles de auditoría para examinar actividad en sistemas con registros ePHI' },
    { id: '5710', event: 'HIPAA 164.312.a.1', condition: 'Control de acceso mediante identificadores únicos para cada operador' },
    { id: '550', event: 'HIPAA Integridad', condition: 'Mecanismos para corroborar que la información médica no sea alterada indebidamente' },
  ],
  nist_800_53: [
    { id: '5710', event: 'NIST AC-2', condition: 'Gestión de cuentas y control de accesos a componentes del sistema' },
    { id: '5712', event: 'NIST AC-7', condition: 'Manejo de intentos infructuosos de inicio de sesión con bloqueo temporal' },
    { id: '550', event: 'NIST SI-7', condition: 'Supervisión continua de la integridad de componentes de software y firmware' },
  ],
  tsc: [
    { id: '106', event: 'TSC CC6.1', condition: 'Restricción de acceso lógico a activos de información y funciones de administración' },
    { id: '550', event: 'TSC CC6.6', condition: 'Protección contra intrusiones no autorizadas y alteraciones a datos esenciales' },
    { id: '5710', event: 'TSC CC7.2', condition: 'Monitoreo de eventos del sistema para detectar vulnerabilidades y comportamientos anómalos' },
  ],
};

const MODULE_ICONS_JSX: Record<string, React.ReactNode> = {
  fim: <HardDrive size={18} style={{ color: 'var(--cyan-accent)' }} />,
  sca: <ShieldCheck size={18} style={{ color: 'var(--green-healthy)' }} />,
  syscollector: <Cpu size={18} style={{ color: 'var(--wazuh-blue)' }} />,
  rootcheck: <Search size={18} style={{ color: 'var(--yellow-warning)' }} />,
  threat_hunting: <Zap size={18} style={{ color: 'var(--red-error)' }} />,
  vulnerabilities: <AlertTriangle size={18} style={{ color: '#ff5722' }} />,
  mitre: <Activity size={18} style={{ color: '#9c27b0' }} />,
  pci_dss: <Lock size={18} style={{ color: '#00bcd4' }} />,
  gdpr: <FileCheck size={18} style={{ color: '#4caf50' }} />,
  hipaa: <FileText size={18} style={{ color: '#03a9f4' }} />,
  nist_800_53: <Layers size={18} style={{ color: '#ff9800' }} />,
  tsc: <ShieldAlert size={18} style={{ color: '#e91e63' }} />,
};

/* ─── RulesTable ─── */
const RulesTable: React.FC<{ moduleId: string }> = ({ moduleId }) => {
  const rules = MODULE_RULES[moduleId] || [];
  if (!rules.length) {
    return (
      <div style={{ padding: '8px 0', fontSize: '12px', color: 'var(--text-muted)' }}>
        <span>No se encontraron reglas predeterminadas para este apartado.</span>
      </div>
    );
  }
  return (
    <div style={{ marginTop: '8px' }}>
      <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Info size={12} />
        <span>Reglas y Disparadores Wazuh Asociados</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left' }}>
              <th style={{ padding: '6px 8px', color: 'var(--text-secondary)', fontWeight: 600, whiteSpace: 'nowrap' }}><span>Regla ID</span></th>
              <th style={{ padding: '6px 8px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Evento Disparador</span></th>
              <th style={{ padding: '6px 8px', color: 'var(--text-secondary)', fontWeight: 600 }}><span>Condición de Detección</span></th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <td style={{ padding: '6px 8px' }}>
                  <code style={{ background: 'rgba(52,152,219,0.12)', color: 'var(--cyan-accent)', padding: '2px 6px', borderRadius: '4px', fontWeight: 700, fontSize: '11px' }}>
                    <span>{r.id}</span>
                  </code>
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text-primary)', fontWeight: 500 }}><span>{r.event}</span></td>
                <td style={{ padding: '6px 8px', color: 'var(--text-secondary)' }}><span>{r.condition}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

/* ─── RecommendationsPanel ─── */
const RecommendationsPanel: React.FC<{
  moduleId: string;
  selectedAgent: string;
  recommendations: SecurityRecommendation[];
  loading: boolean;
  onRefresh: () => void;
}> = ({ moduleId, selectedAgent, recommendations, loading, onRefresh }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const filtered = recommendations.filter((r) => r.module_id === moduleId);

  const handleCopy = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    toast.success('Comando de remediación copiado al portapapeles');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '16px 0', color: 'var(--text-secondary)', fontSize: '12px' }}>
        <Loader2 size={15} className="animate-spin" />
        <span>Analizando telemetría y checks de seguridad del agente {selectedAgent}...</span>
      </div>
    );
  }

  return (
    <div style={{ marginTop: '8px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <ShieldAlert size={13} style={{ color: filtered.length > 0 ? 'var(--yellow-warning)' : 'var(--green-healthy)' }} />
          <span>Recomendaciones de Seguridad y Endurecimiento ({filtered.length})</span>
        </span>
        <button
          type="button"
          onClick={onRefresh}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
          title="Reanalizar agente"
        >
          <RotateCw size={11} />
          <span>Reanalizar</span>
        </button>
      </div>

      {filtered.length === 0 ? (
        <div style={{
          background: 'rgba(46, 204, 113, 0.08)',
          border: '1px solid rgba(46, 204, 113, 0.25)',
          borderRadius: '8px',
          padding: '12px 14px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
        }}>
          <CheckCircle2 size={16} style={{ color: 'var(--green-healthy)', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--green-healthy)' }}>
              <span>Sin anomalías críticas reportadas para este apartado en el agente {selectedAgent}.</span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
              El agente se encuentra operando bajo los parámetros normales de supervisión y no reporta fallos abiertos en este módulo.
            </p>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {filtered.map((rec, idx) => {
            const isCrit = rec.severity === 'critical';
            const isHigh = rec.severity === 'high';
            const isMed = rec.severity === 'medium';
            const badgeBg = isCrit
              ? 'rgba(231, 76, 60, 0.2)'
              : isHigh
              ? 'rgba(230, 126, 34, 0.2)'
              : isMed
              ? 'rgba(241, 196, 15, 0.2)'
              : 'rgba(52, 152, 219, 0.2)';
            const badgeColor = isCrit
              ? 'var(--red-error)'
              : isHigh
              ? '#ff793f'
              : isMed
              ? 'var(--yellow-warning)'
              : 'var(--cyan-accent)';

            return (
              <div
                key={`rec-${moduleId}-${idx}`}
                style={{
                  background: 'var(--bg-card)',
                  borderRadius: '8px',
                  padding: '12px 14px',
                  border: isCrit ? '1px solid rgba(231, 76, 60, 0.35)' : '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      background: badgeBg,
                      color: badgeColor,
                      textTransform: 'uppercase',
                    }}>
                      <span>{rec.severity}</span>
                    </span>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      <span>{rec.title}</span>
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  <strong style={{ color: 'var(--text-primary)' }}><span>Falla detectada: </span></strong>
                  <span>{rec.issue}</span>
                </div>

                {rec.remediation && (
                  <div style={{
                    background: 'rgba(0,0,0,0.3)',
                    borderRadius: '6px',
                    padding: '8px 10px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '10px',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
                      <Terminal size={13} style={{ color: 'var(--cyan-accent)', flexShrink: 0 }} />
                      <code style={{ fontSize: '11px', color: 'var(--cyan-accent)', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        <span>{rec.remediation}</span>
                      </code>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopy(rec.remediation, idx)}
                      style={{
                        background: 'rgba(255,255,255,0.08)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '4px',
                        padding: '4px 8px',
                        cursor: 'pointer',
                        color: 'var(--text-primary)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontSize: '11px',
                        flexShrink: 0,
                      }}
                      title="Copiar comando de solución"
                    >
                      {copiedIndex === idx ? <Check size={12} style={{ color: 'var(--green-healthy)' }} /> : <Copy size={12} />}
                      <span>{copiedIndex === idx ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                )}

                {rec.impact && (
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    <strong style={{ color: 'var(--text-secondary)' }}><span>Impacto de seguridad: </span></strong>
                    <span>{rec.impact}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

/* ─── LiveDataPanel ─── */
const LiveDataPanel: React.FC<{ moduleId: string; selectedAgent: string }> = ({ moduleId, selectedAgent }) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      if (moduleId === 'fim') {
        const res = await dashboardService.getWazuhFim(selectedAgent);
        setData(res?.fim || []);
      } else if (moduleId === 'sca') {
        const res = await dashboardService.getWazuhSca(selectedAgent);
        setData(res?.sca || []);
      } else if (moduleId === 'rootcheck') {
        const res = await dashboardService.getWazuhRootcheck(selectedAgent);
        setData(res?.items || []);
      } else if (moduleId === 'syscollector') {
        const res = await dashboardService.getWazuhSyscollector(selectedAgent);
        setData(res || {});
      } else {
        setData({ status: 'Módulo operativo en daemon del agente', agent: selectedAgent });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [moduleId, selectedAgent]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px 0', color: 'var(--text-secondary)', fontSize: '12px' }}>
        <Loader2 size={14} className="animate-spin" />
        <span>Consultando telemetría en tiempo real...</span>
      </div>
    );
  }

  if (moduleId === 'fim') {
    const list = Array.isArray(data) ? data : [];
    return (
      <div style={{ marginTop: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <FileSearch size={12} />
            <span>Integridad de Archivos FIM (agente {selectedAgent})</span>
          </span>
          <button type="button" onClick={fetchData} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Refrescar">
            <RotateCw size={12} />
          </button>
        </div>
        {list.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '6px 0' }}>
            <span>Sin eventos recientes de FIM registrados para este agente.</span>
          </p>
        ) : (
          <div style={{ overflowX: 'auto', maxHeight: '200px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left' }}>
                  <th style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}><span>Archivo</span></th>
                  <th style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}><span>Permisos</span></th>
                  <th style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}><span>Usuario</span></th>
                  <th style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}><span>Última Mod.</span></th>
                </tr>
              </thead>
              <tbody>
                {list.slice(0, 25).map((f: any, i: number) => (
                  <tr key={f.file ? `${f.file}-${i}` : `fim-${i}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all', color: 'var(--text-primary)', maxWidth: '240px' }}>
                      <span>{f.file}</span>
                    </td>
                    <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}><span>{f.perm || '-'}</span></td>
                    <td style={{ padding: '5px 8px' }}><span>{f.uname || 'root'}</span></td>
                    <td style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}><span>{f.mtime ? new Date(f.mtime).toLocaleDateString() : '-'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  if (moduleId === 'sca') {
    const list = Array.isArray(data) ? data : [];
    return (
      <div style={{ marginTop: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldCheck size={12} />
            <span>Auditorías CIS Benchmark SCA (agente {selectedAgent})</span>
          </span>
          <button type="button" onClick={fetchData} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Refrescar">
            <RotateCw size={12} />
          </button>
        </div>
        {list.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '6px 0' }}>
            <span>Sin reportes SCA para este agente.</span>
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {list.map((s: any, i: number) => (
              <div key={s.name ? `${s.name}-${i}` : `sca-${i}`} style={{ background: 'var(--bg-card)', borderRadius: '8px', padding: '10px 14px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <span style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}><span>{s.name}</span></span>
                  <span style={{ fontWeight: 700, fontSize: '13px', color: s.score >= 70 ? 'var(--green-healthy)' : 'orange' }}>
                    <span>{s.score}% Cumplimiento</span>
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '16px', marginTop: '6px', fontSize: '11px' }}>
                  <span style={{ color: 'var(--green-healthy)' }}><span>✓ {s.pass || 0} pasados</span></span>
                  <span style={{ color: s.fail > 0 ? 'var(--red-error)' : 'var(--text-muted)' }}><span>✗ {s.fail || 0} fallidos</span></span>
                  <span style={{ color: 'var(--text-muted)' }}><span>{s.total_checks || '-'} total checks</span></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (moduleId === 'syscollector') {
    const os = data?.os || {};
    const ports = Array.isArray(data?.ports) ? data.ports : [];
    return (
      <div style={{ marginTop: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Cpu size={12} />
            <span>Inventario de Activos y Puertos (agente {selectedAgent})</span>
          </span>
          <button type="button" onClick={fetchData} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Refrescar">
            <RotateCw size={12} />
          </button>
        </div>
        <div style={{ background: 'var(--bg-card)', borderRadius: '8px', padding: '10px 12px', border: '1px solid var(--border-subtle)', marginBottom: '8px', fontSize: '11px' }}>
          <div><strong style={{ color: 'var(--text-primary)' }}><span>SO: </span></strong><span style={{ color: 'var(--cyan-accent)' }}>{os.os_name || os.name || 'Linux'} ({os.version || os.architecture || 'x86_64'})</span></div>
          <div style={{ marginTop: '4px' }}><strong style={{ color: 'var(--text-primary)' }}><span>Hostname: </span></strong><span style={{ color: 'var(--text-secondary)' }}>{os.hostname || selectedAgent}</span></div>
        </div>
        <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
          <span>Puertos Abiertos en Escucha ({ports.length}):</span>
        </div>
        <div style={{ overflowX: 'auto', maxHeight: '160px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left' }}>
                <th style={{ padding: '4px 6px', color: 'var(--text-secondary)' }}><span>Protocolo</span></th>
                <th style={{ padding: '4px 6px', color: 'var(--text-secondary)' }}><span>Dirección Local</span></th>
                <th style={{ padding: '4px 6px', color: 'var(--text-secondary)' }}><span>Puerto</span></th>
                <th style={{ padding: '4px 6px', color: 'var(--text-secondary)' }}><span>Estado</span></th>
              </tr>
            </thead>
            <tbody>
              {ports.slice(0, 15).map((p: any, idx: number) => (
                <tr key={`p-${idx}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                  <td style={{ padding: '4px 6px', color: 'var(--cyan-accent)', fontWeight: 600 }}><span>{p.protocol || 'tcp'}</span></td>
                  <td style={{ padding: '4px 6px' }}><span>{p.local?.ip || '0.0.0.0'}</span></td>
                  <td style={{ padding: '4px 6px', fontWeight: 600 }}><span>{p.local?.port || '-'}</span></td>
                  <td style={{ padding: '4px 6px', color: 'var(--green-healthy)' }}><span>{p.state || 'listening'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (moduleId === 'rootcheck') {
    const list = Array.isArray(data) ? data : [];
    return (
      <div style={{ marginTop: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Search size={12} />
            <span>Detecciones y Auditoría Rootcheck (agente {selectedAgent})</span>
          </span>
          <button type="button" onClick={fetchData} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Refrescar">
            <RotateCw size={12} />
          </button>
        </div>
        {list.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '6px 0' }}>
            <span>Sin rootkits o anomalías de malware detectadas por el daemon.</span>
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px', overflowY: 'auto' }}>
            {list.map((it: any, idx: number) => (
              <div key={`rc-${idx}`} style={{ background: 'var(--bg-card)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '11px' }}>
                <div style={{ fontWeight: 600, color: it.status === 'solved' ? 'var(--green-healthy)' : 'var(--yellow-warning)' }}>
                  <span>{it.status === 'solved' ? '✓ Resuelto' : '⚠️ Anomalía detectada'}</span>
                </div>
                <div style={{ color: 'var(--text-primary)', marginTop: '2px' }}><span>{it.log || it.event}</span></div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ marginTop: '8px', padding: '10px 12px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border-subtle)', fontSize: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--green-healthy)' }}>
        <CheckCircle2 size={14} />
        <span>Supervisión activa en agente {selectedAgent}</span>
      </div>
      <p style={{ margin: '6px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
        Las alertas y eventos de este módulo son capturados continuamente por el motor de análisis y correlacionadas en tiempo real.
      </p>
    </div>
  );
};

/* ─── ApartadoItem (Submódulo individual) ─── */
interface ApartadoItemProps {
  m: ModuleMeta;
  isEnabled: boolean;
  isModified: boolean;
  isApplying: boolean;
  selectedAgent: string;
  agentHealth?: AgentHealthInfo;
  recommendations: SecurityRecommendation[];
  recsLoading: boolean;
  onToggle: () => void;
  onRefreshRecs: () => void;
}

const ApartadoItem: React.FC<ApartadoItemProps> = ({
  m,
  isEnabled,
  isModified,
  isApplying,
  selectedAgent,
  agentHealth,
  recommendations,
  recsLoading,
  onToggle,
  onRefreshRecs,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<'recs' | 'telemetry' | 'rules'>('recs');

  const recCount = recommendations.filter((r) => r.module_id === m.id).length;
  const isHealthy = agentHealth ? agentHealth.connected && isEnabled : isEnabled;

  return (
    <div
      className="notranslate"
      translate="no"
      style={{
        background: 'var(--bg-surface)',
        borderRadius: '10px',
        border: isModified
          ? '1px solid var(--yellow-warning)'
          : isEnabled
          ? '1px solid rgba(52, 152, 219, 0.25)'
          : '1px solid var(--border-subtle)',
        transition: 'all 0.2s ease',
        boxShadow: isModified ? '0 0 10px rgba(241, 196, 15, 0.12)' : 'none',
        overflow: 'hidden',
      }}
    >
      {/* Row Header */}
      <div style={{ padding: '12px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '220px' }}>
          <div style={{
            padding: '8px',
            borderRadius: '8px',
            background: isEnabled ? 'rgba(52, 152, 219, 0.12)' : 'rgba(255, 255, 255, 0.04)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            {MODULE_ICONS_JSX[m.id] || <ShieldAlert size={18} />}
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h5 style={{ margin: 0, fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                <span>{m.name}</span>
              </h5>
              {isModified && (
                <span style={{
                  fontSize: '9px', fontWeight: 700, padding: '1px 5px', borderRadius: '4px',
                  background: 'rgba(241, 196, 15, 0.2)', color: 'var(--yellow-warning)',
                  border: '1px solid rgba(241, 196, 15, 0.4)',
                }}>
                  <span>MODIFICADO</span>
                </span>
              )}
              {recCount > 0 && (
                <span style={{
                  fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '10px',
                  background: 'rgba(231, 76, 60, 0.2)', color: 'var(--red-error)',
                  border: '1px solid rgba(231, 76, 60, 0.4)',
                  display: 'flex', alignItems: 'center', gap: '4px',
                }}>
                  <AlertTriangle size={10} />
                  <span>{recCount} {recCount === 1 ? 'falla' : 'fallas'}</span>
                </span>
              )}
            </div>
            <p style={{ margin: '2px 0 0', fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.3 }}>
              <span>{m.description}</span>
            </p>
          </div>
        </div>

        {/* Right: Health Badge + Toggle Switch + Expand Details */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          {/* Health Badge */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '5px',
            padding: '3px 8px', borderRadius: '12px',
            background: isHealthy ? 'rgba(46, 204, 113, 0.12)' : 'rgba(231, 76, 60, 0.12)',
            border: `1px solid ${isHealthy ? 'rgba(46, 204, 113, 0.3)' : 'rgba(231, 76, 60, 0.3)'}`,
            fontSize: '11px', fontWeight: 600,
            color: isHealthy ? 'var(--green-healthy)' : 'var(--red-error)',
          }}>
            <span style={{
              width: '6px', height: '6px', borderRadius: '50%',
              background: isHealthy ? 'var(--green-healthy)' : 'var(--red-error)',
              display: 'inline-block',
            }} />
            <span>{isHealthy ? 'Levantado' : !isEnabled ? 'Desactivado' : 'Desconectado'}</span>
          </div>

          {/* Switch */}
          <label className="cyber-switch" title={isEnabled ? 'Desactivar este apartado' : 'Activar este apartado'}>
            <input
              type="checkbox"
              checked={isEnabled}
              disabled={isApplying}
              onChange={onToggle}
            />
            <span className="cyber-slider round"></span>
          </label>

          {/* Expand Button */}
          <button
            type="button"
            className="notranslate"
            translate="no"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setExpanded((prev) => !prev);
            }}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              padding: '4px 6px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 600,
            }}
            title={expanded ? 'Colapsar detalles' : 'Ver recomendaciones y reglas'}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center' }}>
              {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </span>
            <span>{expanded ? 'Ocultar' : 'Detalles'}</span>
          </button>
        </div>
      </div>

      {/* Expanded Accordion */}
      <div
        className="notranslate"
        translate="no"
        style={{
          display: expanded ? 'block' : 'none',
          borderTop: '1px solid var(--border-subtle)',
          padding: '12px 14px 16px',
          background: 'rgba(0,0,0,0.18)',
        }}
      >
        {expanded && (
          <div key={`apartado-body-${m.id}`}>
            {/* Tabs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => setActiveTab('recs')}
                style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  background: activeTab === 'recs' ? 'var(--cyan-accent)' : 'var(--bg-card)',
                  color: activeTab === 'recs' ? '#000' : 'var(--text-secondary)',
                  border: activeTab === 'recs' ? 'none' : '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                }}
              >
                <span>🛡️ Recomendaciones</span>
                {recCount > 0 && (
                  <span style={{
                    background: activeTab === 'recs' ? '#000' : 'var(--red-error)',
                    color: activeTab === 'recs' ? 'var(--cyan-accent)' : '#fff',
                    borderRadius: '8px',
                    fontSize: '9px',
                    padding: '0 5px',
                    fontWeight: 700,
                  }}>
                    <span>{recCount}</span>
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('telemetry')}
                style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  background: activeTab === 'telemetry' ? 'var(--cyan-accent)' : 'var(--bg-card)',
                  color: activeTab === 'telemetry' ? '#000' : 'var(--text-secondary)',
                  border: activeTab === 'telemetry' ? 'none' : '1px solid var(--border-subtle)',
                }}
              >
                <span>📡 Telemetría en Vivo</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('rules')}
                style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  background: activeTab === 'rules' ? 'var(--cyan-accent)' : 'var(--bg-card)',
                  color: activeTab === 'rules' ? '#000' : 'var(--text-secondary)',
                  border: activeTab === 'rules' ? 'none' : '1px solid var(--border-subtle)',
                }}
              >
                <span>📋 Reglas Wazuh</span>
              </button>
            </div>

            {/* Tab Contents */}
            {activeTab === 'recs' && (
              <RecommendationsPanel
                moduleId={m.id}
                selectedAgent={selectedAgent}
                recommendations={recommendations}
                loading={recsLoading}
                onRefresh={onRefreshRecs}
              />
            )}
            {activeTab === 'telemetry' && (
              <LiveDataPanel moduleId={m.id} selectedAgent={selectedAgent} />
            )}
            {activeTab === 'rules' && (
              <RulesTable moduleId={m.id} />
            )}
          </div>
        )}
      </div>
    </div>
  );
};

/* ─── ModuleGroupCard (Módulo principal colapsable) ─── */
interface ModuleGroupCardProps {
  group: ModuleGroup;
  modules: ModuleMeta[];
  currentDraftScope: Record<string, boolean>;
  currentServerScope: Record<string, boolean>;
  isApplying: boolean;
  selectedAgent: string;
  agentHealthMap?: Record<string, AgentHealthInfo>;
  recommendations: SecurityRecommendation[];
  recsLoading: boolean;
  onToggleModule: (moduleId: string) => void;
  onRefreshRecs: () => void;
}

const ModuleGroupCard: React.FC<ModuleGroupCardProps> = ({
  group,
  modules,
  currentDraftScope,
  currentServerScope,
  isApplying,
  selectedAgent,
  agentHealthMap,
  recommendations,
  recsLoading,
  onToggleModule,
  onRefreshRecs,
}) => {
  const [expanded, setExpanded] = useState(true);

  const groupModules = modules.filter((m) => group.module_ids.includes(m.id));
  const activeCount = groupModules.filter((m) => currentDraftScope[m.id] ?? true).length;
  const totalCount = groupModules.length;
  const isAllActive = activeCount === totalCount && totalCount > 0;

  // Total recommendations for this group
  const groupRecCount = recommendations.filter((r) => group.module_ids.includes(r.module_id)).length;

  return (
    <div
      className="notranslate"
      translate="no"
      style={{
        background: 'var(--bg-surface)',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)',
        boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
        overflow: 'hidden',
        transition: 'all 0.3s ease',
      }}
    >
      {/* Group Header */}
      <div
        onClick={() => setExpanded((prev) => !prev)}
        style={{
          padding: '16px 20px',
          background: expanded ? 'rgba(255,255,255,0.03)' : 'transparent',
          borderBottom: expanded ? '1px solid var(--border-subtle)' : 'none',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '12px',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <span style={{ fontSize: '20px' }}>{group.icon}</span>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                <span>{group.title}</span>
              </h3>
              <span style={{
                fontSize: '11px',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '10px',
                background: isAllActive ? 'rgba(46, 204, 113, 0.15)' : 'rgba(241, 196, 15, 0.15)',
                color: isAllActive ? 'var(--green-healthy)' : 'var(--yellow-warning)',
                border: `1px solid ${isAllActive ? 'rgba(46, 204, 113, 0.3)' : 'rgba(241, 196, 15, 0.3)'}`,
              }}>
                <span>{activeCount}/{totalCount} Activos</span>
              </span>
              {groupRecCount > 0 && (
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  background: 'rgba(231, 76, 60, 0.2)',
                  color: 'var(--red-error)',
                  border: '1px solid rgba(231, 76, 60, 0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  <AlertTriangle size={11} />
                  <span>{groupRecCount} {groupRecCount === 1 ? 'falla de seguridad' : 'fallas de seguridad'}</span>
                </span>
              )}
            </div>
            <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              <span>{group.description}</span>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>
            <span>{expanded ? 'Plegar' : 'Ampliar módulo'}</span>
          </span>
          {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
        </div>
      </div>

      {/* Group Apartados List */}
      <div
        className="notranslate"
        translate="no"
        style={{
          display: expanded ? 'flex' : 'none',
          flexDirection: 'column',
          gap: '10px',
          padding: '16px 20px',
          background: 'rgba(0,0,0,0.08)',
        }}
      >
        {groupModules.map((m) => {
          const isEnabled = currentDraftScope[m.id] ?? true;
          const isModified = currentDraftScope[m.id] !== currentServerScope[m.id];
          const health = agentHealthMap ? agentHealthMap[m.id] : undefined;
          return (
            <ApartadoItem
              key={m.id}
              m={m}
              isEnabled={isEnabled}
              isModified={isModified}
              isApplying={isApplying}
              selectedAgent={selectedAgent}
              agentHealth={health}
              recommendations={recommendations}
              recsLoading={recsLoading}
              onToggle={() => onToggleModule(m.id)}
              onRefreshRecs={onRefreshRecs}
            />
          );
        })}
      </div>
    </div>
  );
};

/* ─── Main Component ─── */
export const WazuhModulesControlCard: React.FC = () => {
  const [scopes, setScopes] = useState<ScopeOption[]>([]);
  const [selectedScope, setSelectedScope] = useState<string>('global');
  const [selectedAgent, setSelectedAgent] = useState<string>('000');
  const [serverConfig, setServerConfig] = useState<Record<string, Record<string, boolean>>>({});
  const [draftConfig, setDraftConfig] = useState<Record<string, Record<string, boolean>>>({});
  const [modulesMeta, setModulesMeta] = useState<ModuleMeta[]>([]);
  const [groups, setGroups] = useState<ModuleGroup[]>(DEFAULT_GROUPS);
  const [agentHealth, setAgentHealth] = useState<Record<string, Record<string, AgentHealthInfo>>>({});
  const [recommendations, setRecommendations] = useState<SecurityRecommendation[]>([]);
  const [recsLoading, setRecsLoading] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [isApplying, setIsApplying] = useState<boolean>(false);
  const [applyStep, setApplyStep] = useState<number>(0);

  const fetchModules = async () => {
    try {
      setLoading(true);
      const res = await dashboardService.getWazuhModules();
      if (res && res.ok) {
        setScopes(res.scopes || []);
        setServerConfig(res.modules_config || {});
        setDraftConfig(JSON.parse(JSON.stringify(res.modules_config || {})));
        if (res.modules_meta && res.modules_meta.length) {
          setModulesMeta(res.modules_meta);
        }
        if (res.groups && res.groups.length) {
          setGroups(res.groups);
        }
        if (res.agent_health) {
          setAgentHealth(res.agent_health);
        }
      }
    } catch (err: any) {
      console.error('Error fetching Wazuh modules:', err);
      toast.error('Error al consultar configuración centralizada de Wazuh');
    } finally {
      setLoading(false);
    }
  };

  const fetchRecommendations = useCallback(async (agentId: string) => {
    setRecsLoading(true);
    try {
      const res = await dashboardService.getWazuhRecommendations(agentId);
      if (res && res.ok && res.recommendations) {
        setRecommendations(res.recommendations);
      } else {
        setRecommendations([]);
      }
    } catch (err) {
      console.error('Error fetching recommendations:', err);
      setRecommendations([]);
    } finally {
      setRecsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchModules();
  }, []);

  useEffect(() => {
    const agToFetch = selectedScope !== 'global' ? selectedScope : (selectedAgent || '000');
    fetchRecommendations(agToFetch);
  }, [selectedScope, selectedAgent, fetchRecommendations]);

  const currentServerScope = serverConfig[selectedScope] || serverConfig['global'] || {};
  const currentDraftScope = draftConfig[selectedScope] || draftConfig['global'] || {};

  const changedModules = Object.keys(currentDraftScope).filter(
    (key) => currentDraftScope[key] !== currentServerScope[key]
  );
  const hasPendingChanges = changedModules.length > 0;

  const handleToggleDraft = (moduleId: string) => {
    setDraftConfig((prev) => ({
      ...prev,
      [selectedScope]: {
        ...(prev[selectedScope] || currentServerScope),
        [moduleId]: !(currentDraftScope[moduleId] ?? true),
      },
    }));
  };

  const handleDraftBulk = (enabled: boolean) => {
    const updated: Record<string, boolean> = {};
    modulesMeta.forEach((m) => { updated[m.id] = enabled; });
    setDraftConfig((prev) => ({ ...prev, [selectedScope]: updated }));
  };

  const handleDiscardChanges = () => {
    setDraftConfig(JSON.parse(JSON.stringify(serverConfig)));
    toast.info('Cambios descartados. Se restableció el estado actual del Manager.');
  };

  const handleSaveAndRestart = async () => {
    setIsApplying(true);
    setApplyStep(1);
    try {
      setApplyStep(2);
      const res = await dashboardService.applyWazuhModulesConfig(selectedScope, currentDraftScope);
      if (res && res.ok) {
        setApplyStep(3);
        setTimeout(() => {
          setApplyStep(4);
          setServerConfig(res.modules_config || draftConfig);
          setTimeout(() => {
            setIsApplying(false);
            setApplyStep(0);
            toast.success(res.message || 'Configuración guardada en agent.conf y reinicio aplicado.');
          }, 1200);
        }, 1200);
      } else {
        setIsApplying(false);
        setApplyStep(0);
        toast.error(res?.detail || 'Error al aplicar cambios en el Manager');
      }
    } catch (err: any) {
      setIsApplying(false);
      setApplyStep(0);
      toast.error(err.message || 'Fallo de conexión al aplicar cambios');
    }
  };

  const totalActive = Object.values(currentDraftScope).filter(Boolean).length;
  const totalModules = modulesMeta.length || 12;

  // Selected agent for health display
  const activeAgentKey = selectedScope !== 'global' ? selectedScope : selectedAgent;
  const currentAgentHealth = agentHealth[activeAgentKey] || agentHealth['000'] || agentHealth['global'];

  return (
    <div
      className="notranslate"
      translate="no"
      style={{
        margin: '0 24px 28px',
        background: 'var(--bg-card)',
        borderRadius: '14px',
        border: hasPendingChanges ? '1px solid rgba(241, 196, 15, 0.4)' : '1px solid var(--border-subtle)',
        padding: '22px',
        boxShadow: hasPendingChanges ? '0 0 25px rgba(241, 196, 15, 0.15)' : '0 4px 20px rgba(0, 0, 0, 0.25)',
        position: 'relative',
        transition: 'all 0.3s ease',
      }}
    >
      {/* ── Top Header ── */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        flexWrap: 'wrap', gap: '16px',
        borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px', marginBottom: '20px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', background: 'rgba(52, 152, 219, 0.15)', color: 'var(--cyan-accent)', display: 'flex' }}>
            <Sliders size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                <span>Módulos de Seguridad y Auditoría Wazuh</span>
              </h2>
              <span style={{
                fontSize: '12px', fontWeight: 600, padding: '3px 10px', borderRadius: '12px',
                background: totalActive === totalModules ? 'rgba(46, 204, 113, 0.15)' : 'rgba(241, 196, 15, 0.15)',
                color: totalActive === totalModules ? 'var(--green-healthy)' : 'var(--yellow-warning)',
                border: `1px solid ${totalActive === totalModules ? 'rgba(46, 204, 113, 0.3)' : 'rgba(241, 196, 15, 0.3)'}`,
              }}>
                <span>{totalActive}/{totalModules} Apartados Activos</span>
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
              <span>Amplía cada módulo para inspeccionar sus apartados, verificar su salud, gestionarlos por agente o globalmente y ver recomendaciones ante fallas.</span>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <a
            href="https://192.168.122.142/app/management#/groups"
            target="_blank"
            rel="noreferrer"
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              background: 'rgba(52, 152, 219, 0.12)', color: 'var(--cyan-accent)',
              border: '1px solid rgba(52, 152, 219, 0.3)', borderRadius: '8px',
              padding: '7px 12px', fontSize: '12px', fontWeight: 600, textDecoration: 'none',
            }}
          >
            <ExternalLink size={13} />
            <span>Wazuh Management</span>
          </a>

          <button
            type="button"
            onClick={() => {
              fetchModules();
              fetchRecommendations(selectedScope !== 'global' ? selectedScope : selectedAgent);
            }}
            disabled={loading || isApplying}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              background: 'var(--bg-card-hover)', color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)', borderRadius: '8px',
              padding: '7px 12px', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
            }}
          >
            <RotateCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refrescar</span>
          </button>
        </div>
      </div>

      {/* ── Scope + Agent Selector Bar ── */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        flexWrap: 'wrap', gap: '12px',
        background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
        borderRadius: '10px', padding: '12px 16px', marginBottom: '20px',
      }}>
        {/* Left: scope tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Server size={15} style={{ color: 'var(--cyan-accent)' }} />
            <span>Ámbito de Configuración:</span>
          </span>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {scopes.map((s) => {
              const isSelected = selectedScope === s.id;
              return (
                <button
                  key={s.id}
                  onClick={() => {
                    setSelectedScope(s.id);
                    if (s.id !== 'global') {
                      setSelectedAgent(s.id);
                    }
                  }}
                  disabled={isApplying}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    padding: '6px 14px', borderRadius: '8px', fontSize: '12px', fontWeight: 600,
                    cursor: 'pointer',
                    background: isSelected ? 'var(--cyan-accent)' : 'var(--bg-card)',
                    color: isSelected ? '#000' : 'var(--text-primary)',
                    border: isSelected ? '1px solid var(--cyan-accent)' : '1px solid var(--border-subtle)',
                    transition: 'all 0.2s ease',
                  }}
                >
                  <Radio size={12} style={{ opacity: isSelected ? 1 : 0.4 }} />
                  <span>{s.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: bulk actions + agent selector for global */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {selectedScope === 'global' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}><span>Agente auditado:</span></span>
              <select
                value={selectedAgent}
                onChange={(e) => setSelectedAgent(e.target.value)}
                style={{
                  background: 'var(--bg-card-hover)', color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)', borderRadius: '6px',
                  padding: '4px 8px', fontSize: '12px',
                }}
              >
                {scopes.filter((s) => s.id !== 'global').map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={() => handleDraftBulk(true)}
            disabled={loading || isApplying}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              background: 'rgba(46, 204, 113, 0.12)', color: 'var(--green-healthy)',
              border: '1px solid rgba(46, 204, 113, 0.25)', borderRadius: '7px',
              padding: '5px 10px', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
            }}
          >
            <CheckCircle2 size={13} />
            <span>Activar Todo</span>
          </button>

          <button
            onClick={() => handleDraftBulk(false)}
            disabled={loading || isApplying}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              background: 'rgba(231, 76, 60, 0.12)', color: 'var(--red-error)',
              border: '1px solid rgba(231, 76, 60, 0.25)', borderRadius: '7px',
              padding: '5px 10px', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
            }}
          >
            <XCircle size={13} />
            <span>Desactivar Todo</span>
          </button>
        </div>
      </div>

      {/* ── Pending changes bar ── */}
      {hasPendingChanges && (
        <div style={{
          background: 'linear-gradient(90deg, rgba(241, 196, 15, 0.15), rgba(230, 126, 34, 0.15))',
          border: '1px solid rgba(241, 196, 15, 0.5)', borderRadius: '10px',
          padding: '12px 18px', marginBottom: '18px',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          flexWrap: 'wrap', gap: '12px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--yellow-warning)', display: 'inline-block' }} />
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--yellow-warning)' }}>
              <span>{changedModules.length} cambio(s) pendiente(s) para {selectedScope === 'global' ? 'Todos los Agentes' : `Agente ${selectedScope}`}</span>
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              onClick={handleDiscardChanges}
              disabled={isApplying}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                background: 'rgba(255,255,255,0.08)', color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)', borderRadius: '8px',
                padding: '6px 14px', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Undo2 size={13} />
              <span>Descartar</span>
            </button>
            <button
              type="button"
              onClick={handleSaveAndRestart}
              disabled={isApplying}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                background: 'var(--cyan-accent)', color: '#000', border: 'none',
                borderRadius: '8px', padding: '7px 18px', fontSize: '13px', fontWeight: 700,
                cursor: 'pointer', boxShadow: '0 0 15px rgba(0, 229, 255, 0.4)',
              }}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                {isApplying ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
              </span>
              <span>Guardar y Reiniciar Agente(s)</span>
            </button>
          </div>
        </div>
      )}

      {/* ── Main Modules Group List (Cards) ── */}
      {loading && !modulesMeta.length ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px', gap: '10px', color: 'var(--text-secondary)' }}>
          <Loader2 size={24} className="animate-spin" />
          <span>Consultando módulos y estado de salud en Wazuh Manager...</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {groups.map((grp) => (
            <ModuleGroupCard
              key={grp.id}
              group={grp}
              modules={modulesMeta}
              currentDraftScope={currentDraftScope}
              currentServerScope={currentServerScope}
              isApplying={isApplying}
              selectedAgent={selectedScope !== 'global' ? selectedScope : selectedAgent}
              agentHealthMap={currentAgentHealth}
              recommendations={recommendations}
              recsLoading={recsLoading}
              onToggleModule={handleToggleDraft}
              onRefreshRecs={() => fetchRecommendations(selectedScope !== 'global' ? selectedScope : selectedAgent)}
            />
          ))}
        </div>
      )}

      {/* ── Apply Progress Modal ── */}
      {isApplying && (
        <div style={{
          position: 'absolute', inset: 0,
          background: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(6px)',
          borderRadius: '14px', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', padding: '20px', zIndex: 10,
        }}>
          <div style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border-glow)',
            borderRadius: '12px', padding: '24px 30px', maxWidth: '440px', width: '100%',
            boxShadow: '0 0 30px rgba(0, 229, 255, 0.2)', textAlign: 'center',
          }}>
            <Loader2 size={36} className="animate-spin" style={{ color: 'var(--cyan-accent)', margin: '0 auto 14px' }} />
            <h3 style={{ margin: '0 0 8px', fontSize: '16px', color: 'var(--text-primary)' }}>
              <span>Sincronizando con Wazuh Manager</span>
            </h3>
            <p style={{ margin: '0 0 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>
              <span>Aplicando configuración en <code>agent.conf</code> y reiniciando demonios...</span>
            </p>
            <div style={{ textAlign: 'left', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div style={{ color: applyStep >= 1 ? 'var(--green-healthy)' : 'var(--text-muted)' }}>
                <span>{applyStep >= 1 ? '✓' : '○'} 1. Generación de directivas XML</span>
              </div>
              <div style={{ color: applyStep >= 2 ? 'var(--green-healthy)' : 'var(--text-muted)' }}>
                <span>{applyStep >= 2 ? '✓' : '○'} 2. Escritura en grupo <code>default</code></span>
              </div>
              <div style={{ color: applyStep >= 3 ? 'var(--green-healthy)' : 'var(--text-muted)' }}>
                <span>{applyStep >= 3 ? '✓' : '○'} 3. Reinicio de agentes (<code>PUT /agents/restart</code>)</span>
              </div>
              <div style={{ color: applyStep >= 4 ? 'var(--green-healthy)' : 'var(--text-muted)' }}>
                <span>{applyStep >= 4 ? '✓' : '○'} 4. Confirmación de telemetría</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WazuhModulesControlCard;
