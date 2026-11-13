import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { dashboardService } from '../services/api';
import { Loader2, RefreshCw, ShieldAlert, Search, Server, ChevronDown, ChevronRight } from 'lucide-react';
import { WazuhControlPanel } from './WazuhControlPanel';
import { EnrichmentPanel } from './enrichment/EnrichmentPanel';
import './DetectionsView.css';

type ModuleId = 'alerts' | 'fim' | 'sca' | 'rootcheck' | 'vulnerabilities' | 'syscollector' | 'mitre';

const MODULES: { id: ModuleId; label: string }[] = [
  { id: 'alerts', label: 'Alertas SIEM' },
  { id: 'fim', label: 'Integridad (FIM)' },
  { id: 'sca', label: 'CIS / SCA' },
  { id: 'rootcheck', label: 'Malware / Rootcheck' },
  { id: 'vulnerabilities', label: 'Vulnerabilidades' },
  { id: 'syscollector', label: 'Inventario (Syscollector)' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
];

function levelClass(level: number): string {
  if (level >= 12) return 'crit';
  if (level >= 8) return 'high';
  if (level >= 4) return 'med';
  return 'low';
}

export const DetectionsView: React.FC = () => {
  const [module, setModule] = useState<ModuleId>('alerts');
  const [agents, setAgents] = useState<any[]>([]);
  const [agent, setAgent] = useState<string>('all');
  const [items, setItems] = useState<any[]>([]);
  const [overview, setOverview] = useState<any>(null);
  const [levelMin, setLevelMin] = useState<number>(0);
  const [query, setQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    dashboardService.getWazuhControlOverview()
      .then((res) => {
        setOverview(res);
        setAgents(res.agents || []);
      })
      .catch(() => setOverview(null));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (module === 'alerts') {
        const res = await dashboardService.getWazuhDetections({
          agent_id: agent, level_min: levelMin, q: query, limit: 300,
        });
        setItems(res.items || []);
      } else {
        const aid = agent === 'all' ? '000' : agent;
        const res = await dashboardService.getWazuhDetectionsModule(module, aid, 200);
        setItems(res.items || []);
      }
    } catch (err: any) {
      setItems([]);
      setError(err?.response?.data?.detail || err?.message || 'Error consultando Wazuh');
    } finally {
      setLoading(false);
    }
  }, [module, agent, levelMin, query]);

  useEffect(() => { load(); }, [load]);

  const daemons = useMemo(() => {
    const st = overview?.manager?.status || {};
    return Object.entries(st).filter(([k]) => k.startsWith('wazuh-'));
  }, [overview]);

  return (
    <div className="detections-view">
      <div className="detections-head">
        <div>
          <h2><ShieldAlert size={20} /> Detecciones reales de Wazuh</h2>
          <p>Consulta directa al manager y a syscollector. Sin datos sintéticos.</p>
        </div>
        <button className="det-refresh" onClick={load} disabled={loading}>
          {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          Actualizar
        </button>
      </div>

      {overview && (
        <div className="det-overview">
          <div className="det-overview-card">
            <Server size={16} />
            <div>
              <strong>{overview.manager?.info?.version || 'Wazuh'}</strong>
              <span>{overview.manager?.info?.type || 'manager'} · {overview.manager?.info?.path || '-'}</span>
            </div>
          </div>
          <div className="det-daemons">
            {daemons.map(([name, status]) => (
              <span key={name} className={String(status) === 'running' ? 'up' : 'down'}>
                {name.replace('wazuh-', '')}: {String(status)}
              </span>
            ))}
          </div>
          <div className="det-overview-card">
            <ShieldAlert size={16} />
            <div>
              <strong>{overview.agents?.length || 0} agentes</strong>
              <span>{overview.agents?.filter((a: any) => a.status === 'active').length || 0} activos</span>
            </div>
          </div>
        </div>
      )}

      <WazuhControlPanel />

      <div className="det-tabs">
        {MODULES.map((m) => (
          <button
            key={m.id}
            className={module === m.id ? 'active' : ''}
            onClick={() => { setModule(m.id); setExpanded(null); }}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="det-filters">
        <select value={agent} onChange={(e) => setAgent(e.target.value)}>
          <option value="all">Todos los agentes</option>
          {agents.map((a) => (
            <option key={a.id} value={a.id}>
              [{a.id}] {a.name} ({a.status})
            </option>
          ))}
        </select>
        {module === 'alerts' && (
          <>
            <select value={levelMin} onChange={(e) => setLevelMin(Number(e.target.value))}>
              <option value={0}>Nivel ≥ 0</option>
              <option value={4}>Nivel ≥ 4</option>
              <option value={8}>Nivel ≥ 8</option>
              <option value={12}>Nivel ≥ 12</option>
            </select>
            <div className="det-search">
              <Search size={14} />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Buscar regla, agente o log..."
              />
            </div>
          </>
        )}
        <span className="det-count">{items.length} resultados</span>
      </div>

      {error && <div className="det-error">{error}</div>}

      <div className="det-table-wrap">
        {loading ? (
          <div className="det-empty"><Loader2 size={22} className="animate-spin" /> Consultando Wazuh...</div>
        ) : items.length === 0 ? (
          <div className="det-empty">Sin registros para el módulo/agente seleccionado.</div>
        ) : (
          <table className="det-table">
            <thead>
              <tr>
                <th></th>
                <th>Hora</th>
                <th>Agente</th>
                <th>{module === 'alerts' ? 'Nivel / Regla' : 'Detalle'}</th>
                <th>Qué pasó</th>
                <th>Qué hacer</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item, idx) => {
                const isAlert = module === 'alerts';
                const level = Number(item.level || 0);
                const raw = isAlert ? item.raw : item;
                return (
                  <React.Fragment key={`${item.id || item.rule_id || idx}-${idx}`}>
                    <tr onClick={() => setExpanded(expanded === idx ? null : idx)}>
                      <td>{expanded === idx ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                      <td className="mono">{item.timestamp || item.scan?.time || '-'}</td>
                      <td className="mono">[{item.agent_id || item.agent_id || '000'}] {item.agent_name || '-'}</td>
                      <td>
                        {isAlert ? (
                          <span className={`det-level ${levelClass(level)}`}>L{level} · #{item.rule_id}</span>
                        ) : (
                          <span className="mono">{String(item.file || item.name || item.title || item.event || item.package || item.local?.port || item.id || '-').slice(0, 60)}</span>
                        )}
                      </td>
                      <td>
                        {isAlert
                          ? (item.description_es || item.description)
                          : (item.description || item.title || item.rationale || item.event || '-')}
                      </td>
                      <td className="det-action">
                        {isAlert && item.enrichment?.remediation?.[0]?.action
                          ? item.enrichment.remediation[0].action
                          : '-'}
                      </td>
                    </tr>
                    {expanded === idx && (
                      <tr className="det-raw-row">
                        <td colSpan={6}>
                          <EnrichmentPanel enrichment={item.enrichment} raw={raw} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default DetectionsView;
