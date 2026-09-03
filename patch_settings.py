import re

with open("dashboard/src/components/SettingsSection.tsx", "r") as f:
    content = f.read()

# Add to TabType
content = re.sub(
    r"(type TabType = 'wazuh' \| 'whatsapp' \| 'email' \| 'ai' \| 'relay' \| 'logs');",
    r"\1 | 'wazuh_agents';",
    content
)

# Add icon import
content = re.sub(
    r"  Terminal,\n} from 'lucide-react';",
    r"  Terminal,\n  Activity,\n  Users,\n} from 'lucide-react';",
    content
)

# Add tab button
tab_btn_code = """
            <button
              type="button"
              className={`settings-tab-btn ${activeTab === 'wazuh_agents' ? 'active' : ''}`}
              onClick={() => setActiveTab('wazuh_agents')}
            >
              <Users size={14} />
              <span>Agentes & Procesos</span>
            </button>
          </div>
"""
content = re.sub(
    r"              <span>Logs del Sistema</span>\n            </button>\n          </div>",
    r"              <span>Logs del Sistema</span>\n            </button>\n" + tab_btn_code,
    content
)

# Add states for agents
state_vars = """
  const [logsOutput, setLogsOutput] = useState<string>('');
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [wazuhAgents, setWazuhAgents] = useState<any[]>([]);
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [localServices, setLocalServices] = useState<any[]>([]);
"""
content = content.replace("  const [logsOutput, setLogsOutput] = useState<string>('');\n  const [loadingLogs, setLoadingLogs] = useState(false);", state_vars)


# Add useEffect for agents
effect_code = """
  useEffect(() => {
    if (activeTab === 'wazuh_agents') {
      const fetchData = async () => {
        setLoadingAgents(true);
        try {
          const agentsRes = await dashboardService.getWazuhAgents();
          if (agentsRes && agentsRes.agents) {
            setWazuhAgents(agentsRes.agents);
          }
          const statusRes = await dashboardService.getStatus();
          if (statusRes && statusRes.components) {
            setLocalServices(statusRes.components.filter(c => c.status_type === 'systemd_service' || c.status_type === 'systemd_timer'));
          }
        } catch (err) {
          console.error(err);
        } finally {
          setLoadingAgents(false);
        }
      };
      fetchData();
    }
  }, [activeTab]);
"""

content = content.replace("  const togglePasswordVisibility = (field: string) => {", effect_code + "\n  const togglePasswordVisibility = (field: string) => {")

# Add the Tab view
tab_view = """
          {/* Tab 7: Wazuh Agents & Processes */}
          {activeTab === 'wazuh_agents' && (
            <div className="settings-block">
              <div className="block-header">
                <h3>Control de Agentes y Procesos Locales</h3>
                <span className="block-tag">Wazuh API & Systemd</span>
              </div>
              
              <h4 className="sub-title">Agentes Conectados al Manager</h4>
              {loadingAgents ? (
                <p>Cargando agentes...</p>
              ) : (
                <div style={{ overflowX: 'auto', marginBottom: '20px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left' }}>
                        <th style={{ padding: '8px' }}>ID</th>
                        <th style={{ padding: '8px' }}>Nombre</th>
                        <th style={{ padding: '8px' }}>IP</th>
                        <th style={{ padding: '8px' }}>Estado</th>
                      </tr>
                    </thead>
                    <tbody>
                      {wazuhAgents.length > 0 ? wazuhAgents.map(a => (
                        <tr key={a.id} style={{ borderBottom: '1px solid var(--bg-card)' }}>
                          <td style={{ padding: '8px' }}>{a.id}</td>
                          <td style={{ padding: '8px', color: 'var(--cyan-accent)' }}>{a.name}</td>
                          <td style={{ padding: '8px' }}>{a.ip || '-'}</td>
                          <td style={{ padding: '8px' }}>
                            <span style={{
                              padding: '2px 6px',
                              borderRadius: '4px',
                              background: a.status === 'active' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                              color: a.status === 'active' ? 'var(--green-healthy)' : 'var(--red-error)',
                            }}>
                              {a.status}
                            </span>
                          </td>
                        </tr>
                      )) : (
                        <tr><td colSpan={4} style={{ padding: '8px' }}>No hay agentes o hubo un error.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              <h4 className="sub-title">Procesos Locales de Wazuh</h4>
              <div className="field-grid-2">
                {localServices.map(svc => (
                  <div key={svc.id} className="field-group highlight-box" style={{ padding: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <strong>{svc.name}</strong>
                      <span style={{ fontSize: '11px', color: svc.health === 'healthy' ? 'var(--green-healthy)' : 'var(--text-muted)' }}>
                        {svc.health === 'healthy' ? 'En ejecución' : 'Detenido/Inactivo'}
                      </span>
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>{svc.unit}</p>
                    
                    {svc.toggleable && (
                      <button
                        type="button"
                        onClick={async () => {
                          const action = { target: svc.id, enabled: !svc.current_state };
                          await dashboardService.toggleComponent(action);
                          toast.success(`Orden enviada a ${svc.name}`);
                          // Refrescar para ver el estado real tras un breve retraso
                          setTimeout(async () => {
                             const statusRes = await dashboardService.getStatus();
                             if (statusRes && statusRes.components) {
                               setLocalServices(statusRes.components.filter(c => c.status_type === 'systemd_service' || c.status_type === 'systemd_timer'));
                             }
                          }, 1500);
                        }}
                        style={{
                          padding: '6px 12px',
                          borderRadius: '4px',
                          border: 'none',
                          background: svc.current_state ? 'var(--red-error)' : 'var(--green-healthy)',
                          color: 'white',
                          cursor: 'pointer',
                          fontSize: '12px'
                        }}
                      >
                        {svc.current_state ? 'Deshabilitar Proceso' : 'Habilitar Proceso'}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Footer Actions */}
"""

content = content.replace("          {/* Footer Actions */}", tab_view)

with open("dashboard/src/components/SettingsSection.tsx", "w") as f:
    f.write(content)

