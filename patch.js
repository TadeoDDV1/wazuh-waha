const fs = require('fs');
let file = fs.readFileSync('dashboard/src/components/SettingsSection.tsx', 'utf8');

// Remove ADMIN_EMAIL from smtp block
file = file.replace(/<div className="field-group">\s*<label>Email Destino \(To\)<\/label>\s*<input\s*type="text"\s*className="field-input"\s*placeholder="admin@tudominio.com"\s*value=\{values\.ADMIN_EMAIL \|\| ''\}\s*onChange=\{\(e\) => handleChange\('ADMIN_EMAIL', e\.target\.value\)\}\s*\/>\s*<\/div>/g, '');

// Insert ADMIN_EMAIL right after Email Provider selection
const target = `<option value="hyvor_relay">Hyvor Relay (API Serverless)</option>\n                  </select>\n                </div>`;
const replacement = target + `\n\n                <div className="field-group" style={{ marginTop: '15px' }}>\n                  <label>Correo de Notificaciones (ADMIN_EMAIL)</label>\n                  <input\n                    type="text"\n                    className="field-input"\n                    placeholder="admin@tudominio.com"\n                    value={values.ADMIN_EMAIL || ''}\n                    onChange={(e) => handleChange('ADMIN_EMAIL', e.target.value)}\n                  />\n                  <p className="field-hint">A este correo llegarán todas las notificaciones, sin importar el proveedor que elijas arriba.</p>\n                </div>`;

file = file.replace(target, replacement);

fs.writeFileSync('dashboard/src/components/SettingsSection.tsx', file);
