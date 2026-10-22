import React, { useCallback, useEffect, useState } from 'react';
import { dashboardService } from '../services/api';
import { Loader2, Sliders, ShieldCheck, ShieldOff, Save } from 'lucide-react';
import './WazuhControlPanel.css';

const AGENT_MODULE_LABELS: Record<string, string> = {
  fim: 'FIM / Syscheck',
  sca: 'SCA / CIS',
  rootcheck: 'Rootcheck / Malware',
  syscollector: 'Syscollector / Inventario',
  threat_hunting: 'Active Response',
};

export const WazuhControlPanel: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [group, setGroup] = useState('default');
  const [scope, setScope] = useState('global');
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const res = await dashboardService.getWazuhControlModules();
      setData(res);
      const st = res.state?.[group]?.[scope] || res.state?.[group]?.global || {};
      setDraft(st);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e?.message || 'Error consultando módulos');
    } finally {
      setLoading(false);
    }
  }, [group, scope]);

  useEffect(() => { load(); }, [load]);

  const changeScope = (next: string) => {
    setScope(next);
    const st = data?.state?.[group]?.[next] || data?.state?.[group]?.global || {};
    setDraft(st);
  };

  const apply = async () => {
    setSaving(true); setErr(null); setMsg(null);
    try {
      const res = await dashboardService.applyWazuhModulesConfig(group, scope, draft);
      setMsg(`Aplicado. Cambiados: ${(res.changed || []).join(', ') || 'ninguno'}`);
      await load();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e?.message || 'Error aplicando cambios');
    } finally {
      setSaving(false);
    }
  };

  const hasState = Boolean(data?.state?.[group]);
  const manager = data?.manager?.modules || {};
  const managerWrite = Boolean(data?.manager?.write_enabled);

  const toggleManager = async (module: string, enabled: boolean) => {
    setErr(null); setMsg(null);
    try {
      await dashboardService.toggleWazuhManagerModule(module, enabled);
      setMsg(`${module}: ${enabled ? 'activado' : 'desactivado'} en ossec.conf`);
      await load();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e?.message || 'No se pudo cambiar el manager');
    }
  };

  return (
    <div className="wz-control">
      <div className="wz-control-head">
        <div>
          <h3><Sliders size={17} /> Control real de apartados Wazuh</h3>
          <p>Los cambios de agente se aplican a agent.conf preservando el resto del XML. Los del manager requieren habilitación explícita.</p>
        </div>
        <div className="wz-control-actions">
          <select value={group} onChange={(e) => { setGroup(e.target.value); setScope('global'); }}>
            {(data?.groups || []).map((g: any) => (
              <option key={g.name} value={g.name}>Grupo: {g.name}</option>
            ))}
          </select>
          <select value={scope} onChange={(e) => changeScope(e.target.value)}>
            <option value="global">Global (todos)</option>
            {(data?.agents || []).map((a: any) => (
              <option key={a.id} value={a.id}>[{a.id}] {a.name}</option>
            ))}
          </select>
          <button className="wz-btn primary" onClick={apply} disabled={saving || loading || !hasState}>
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
            Guardar agent.conf
          </button>
        </div>
      </div>

      {err && <div className="wz-msg error">{err}</div>}
      {msg && <div className="wz-msg ok">{msg}</div>}
      {loading ? (
        <div className="wz-loading"><Loader2 size={18} className="animate-spin" /> Cargando estado real...</div>
      ) : (
        <>
          <div className="wz-section-title">Módulos de agente — grupo <code>{group}</code>, scope <code>{scope}</code></div>
          <div className="wz-grid">
            {Object.keys(AGENT_MODULE_LABELS).map((mid) => {
              const enabled = draft[mid] !== false;
              return (
                <label key={mid} className={`wz-module ${enabled ? 'on' : 'off'}`}>
                  <span>{AGENT_MODULE_LABELS[mid]}</span>
                  <button
                    type="button"
                    className={`wz-switch ${enabled ? 'on' : ''}`}
                    onClick={() => setDraft((d) => ({ ...d, [mid]: !enabled }))}
                    title={enabled ? 'Activo' : 'Desactivado'}
                  >
                    {enabled ? <ShieldCheck size={14} /> : <ShieldOff size={14} />}
                  </button>
                </label>
              );
            })}
          </div>

          <div className="wz-section-title">Módulos del manager (ossec.conf)</div>
          <div className="wz-grid">
            <label className="wz-module">
              <span>Vulnerability Detector</span>
              <span className={manager.vulnerabilities ? 'wz-state on' : 'wz-state off'}>
                {manager.vulnerabilities == null ? 'no detectado' : manager.vulnerabilities ? 'activo' : 'desactivado'}
              </span>
            </label>
            <label className="wz-module">
              <span>logall_json</span>
              <span className={manager.logall_json ? 'wz-state on' : 'wz-state off'}>
                {manager.logall_json ? 'activo' : 'desactivado'}
              </span>
            </label>
          </div>
          <div className="wz-note">
            {managerWrite
              ? 'La edición de ossec.conf está habilitada (sudo -n requerido).'
              : 'La edición de ossec.conf está deshabilitada por seguridad. Activar WAZUH_MANAGER_CONFIG_WRITE_ENABLED=true y sudoers sin password.'}
          </div>
          <div className="wz-manager-toggle">
            <span>Vulnerability Detector</span>
            <button
              className="wz-btn"
              disabled={!managerWrite}
              onClick={() => toggleManager('vulnerabilities', !(manager.vulnerabilities))}
            >
              {manager.vulnerabilities ? 'Desactivar' : 'Activar'}
            </button>
          </div>

          <div className="wz-section-title">Grupos de reglas / cumplimiento</div>
          <div className="wz-note">
            PCI DSS, GDPR, HIPAA, NIST, TSC y MITRE no son módulos: se controlan silenciando sus grupos de reglas
            desde las tarjetas de alertas del dashboard o con <code>/silenciar</code>.
          </div>
        </>
      )}
    </div>
  );
};

export default WazuhControlPanel;
