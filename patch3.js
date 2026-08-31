const fs = require('fs');
let file = fs.readFileSync('dashboard/src/components/SettingsSection.tsx', 'utf8');

const target = `<option value="none">Desactivado (Solo WhatsApp)</option>\n                </select>\n              </div>`;
const replacement = target + `\n\n              <div className="field-group" style={{ marginTop: '15px', marginBottom: '15px' }}>\n                <label>Correo de Notificaciones (ADMIN_EMAIL)</label>\n                <input\n                  type="text"\n                  className="field-input"\n                  placeholder="admin@tudominio.com"\n                  value={values.ADMIN_EMAIL || ''}\n                  onChange={(e) => handleChange('ADMIN_EMAIL', e.target.value)}\n                />\n                <p className="field-hint" style={{ marginTop: '5px', fontSize: '12px', color: '#666' }}>A este correo llegarán todas las notificaciones, sin importar el proveedor que elijas arriba.</p>\n              </div>`;

file = file.replace(target, replacement);
fs.writeFileSync('dashboard/src/components/SettingsSection.tsx', file);
