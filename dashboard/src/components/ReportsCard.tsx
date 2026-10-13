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
} from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  ip?: string;
  status?: string;
}

export const ReportsCard: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [downloading, setDownloading] = useState(false);

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
              <span className="card-title">Reportes de Actividad por Agente</span>
              <span
                className="status-pill healthy"
                style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}
              >
                PDF
              </span>
            </div>
            <div className="card-category">
              Generá y descargá un reporte PDF con la ficha forense completa de cualquier agente Wazuh: hardware, SO, red, SCA, FIM, software, procesos y detecciones.
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
            Seleccionar Agente
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
              Generando PDF...
            </>
          ) : (
            <>
              <Download size={15} />
              Descargar Reporte PDF
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
            flexWrap: 'wrap',
          }}
        >
          <span>
            Agente: <strong style={{ color: '#fff' }}>[{selectedAgent.id}] {selectedAgent.name}</strong>
          </span>
          {selectedAgent.ip && (
            <span>
              IP: <code style={{ color: '#38bdf8' }}>{selectedAgent.ip}</code>
            </span>
          )}
          {selectedAgent.status && (
            <span>
              Estado:{' '}
              <strong style={{ color: selectedAgent.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)' }}>
                {selectedAgent.status}
              </strong>
            </span>
          )}
          <span style={{ color: 'var(--text-secondary)' }}>
            El reporte incluye: identificación, hardware, SO, interfaces de red, destinos activos, SCA CIS, FIM, software, procesos y alertas Wazuh.
          </span>
        </div>
      )}

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
