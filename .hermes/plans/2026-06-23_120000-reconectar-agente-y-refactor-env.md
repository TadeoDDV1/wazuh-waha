# Plan: reconectar agente Wazuh a 172.44.30.12 + refactor `.env` centralizado

**Fecha:** 2026-06-23
**Workspace:** `/home/tadeo/Desktop/wazuh-waha/`
**Branch:** `main` (HEAD: `a6a4598`)

## Goal

1. **Reconectar el wazuh-agent local (este host Arch)** al nuevo manager Wazuh en `172.44.30.12`.
2. **Refactorizar el código** para que la IP del server Wazuh viva en **una sola variable del `.env`** (`WAZUH_SERVER_IP=172.44.30.12`) y se refleje automáticamente en todos los archivos commiteables del repo que hoy tienen la IP hardcodeada o como placeholder (`REEMPLAZAR_RELAY_HOST`).
3. **Preservar** los cambios sin commit actuales (templates + threshold + level 10→8 + reglas locales) — son trabajo previo de Tadeo, **no son parte de este plan**.

## Current context / assumptions

- El nuevo manager `172.44.30.12` **YA tiene Wazuh all-in-one instalado** con la misma API key / password SSH que el viejo `172.44.30.11`. Asumimos misma configuración de `ossec.conf` (no se toca nada del lado del manager salvo actualizar el `<hook_url>` si el relay también se muda).
- El `wazuh-agent` ya está instalado en este host (Arch). Su `ossec.conf` apunta a `172.44.30.11` (manager viejo).
- El relay `wazuh-waha` corre en este host (`172.44.30.9:8765`). **No cambia de host**, sigue aquí. Solo cambia la IP del **manager Wazuh**, no la del relay.
- Topología después del cambio:
  ```
  Manager Wazuh:  172.44.30.12  (VM, antes era .11)
  Relay wazuh-waha: 172.44.30.9:8765  (este host Arch, sin cambios)
  Agente Wazuh:    este host Arch, ahora reporta a 172.44.30.12
  WAHA Docker:     este host Arch :3000  (sin cambios)
  ```
- **Cambios sin commit en HEAD** que **NO se tocan** (decisión explícita de preservar):
  - `.env.example` (línea nueva `RELAY_MIN_LEVEL_UNKNOWN`)
  - `manager/ossec.conf.snippet.xml` (level 10→8, sin `--script`, symlink note)
  - `manager/rules/local_rules.xml` (reglas con `<if_sid>` en vez de `<if_group>+<match>`)
  - `wazuh-waha/wazuh_waha/config.py` (`relay_min_level_unknown: int = 10`)
  - `wazuh-waha/wazuh_waha/formatter.py` (decision `below_threshold`)
  - `wazuh-waha/wazuh_waha/templates.py` (más campos en templates 57100-57105)
- **Variables del `.env` actuales** que ya son parametrizables vía `pydantic-settings` (en `config.py`):
  - `RELAY_*` (puerto, bind, api_key, dedup_ttl, log_dir, lib_dir, workers, lifespan_timeout, **min_level_unknown**)
  - `WAHA_*` (api_key, host, session, log_level, hook_url)
  - `OLLAMA_*` (host, model, timeout, enabled)
  - `ADMIN_PHONE`
- **Variables del `.env` actuales que se usan en scripts de shell** (no Python):
  - `WAZUH_MANAGER_HOST`, `WAZUH_MANAGER_API_USER`, `WAZUH_MANAGER_API_PASS`
  - `WAZUH_VM_SSH_USER`, `WAZUH_VM_SSH_HOST`, `WAZUH_VM_SSH_PORT`

## Proposed approach

### Principio rector

Una sola variable: `WAZUH_SERVER_IP`. Vive en `.env` (real, gitignored) y `.env.example` (commiteable, con valor placeholder o el actual `172.44.30.12`). El resto de archivos commiteables la consumen así:

| Archivo commiteable | Cómo consume `WAZUH_SERVER_IP` |
|---|---|
| `manager/ossec.conf.snippet.xml` | Sigue con `REEMPLAZAR_RELAY_HOST` literal (es un template, no se procesa). Pero también dejamos comentario indicando que al subir a la VM se debe sustituir con `$WAZUH_SERVER_IP` o el valor de la nueva IP. |
| `manager/wsl-relay.conf.example` | Mismo: placeholder literal + instrucción de sustituir con `WAZUH_SERVER_IP`. |
| `manager/ossec.conf.snippet.md` | Documentación: aclara que `REEMPLAZAR_RELAY_HOST` se sustituye con el valor de `WAZUH_SERVER_IP` del `.env` del host del relay. |
| `scripts/diagnose.sh` | `${WAZUH_SERVER_IP:-172.44.30.12}` como default; si está en env (sourced del `.env`), pisa el default. Eliminar `WAZUH_MANAGER_HOST` y `WAZUH_VM_SSH_HOST` separados — colapsar en `WAZUH_SERVER_IP`. |
| `scripts/diag-vbox.sh` (si existe) | Mismo tratamiento. |
| `scripts/install-wazuh-waha.sh` (si existe) | Mismo. |
| `.env.example` | Agregar bloque "Server" arriba, con `WAZUH_SERVER_IP=172.44.30.12` destacado como fuente única. |
| `manager/ossec.conf.snippet.xml` + script helper | Generar un **`scripts/render-manager-snippet.py`** que lee `.env` y produce el snippet con la IP ya sustituida (output a `stdout` o a `/tmp/snippet.xml` para hacer `scp` directo a la VM). |

### Decisiones de diseño

1. **NO eliminar `WAZUH_MANAGER_HOST` y `WAZUH_VM_SSH_HOST` del `.env.example` por ahora** — son aliases para no romper usuarios que ya los usaban. Marcar como **deprecated** en comentario, mantenerlos en `.env.example`, pero el script helper (`render-manager-snippet.py`) prioriza `WAZUH_SERVER_IP` y cae al alias si no está.
2. **Las IPs en `docs/PLAN-*.md` y `CHANGELOG.md` NO se tocan** — son registros históricos. Solo `README.md` y `ARCHITECTURE.md` (documentación viva) se actualizan si tienen IPs hardcodeadas en la sección "Topología actual".
3. **El `manager/wsl-relay.conf.example` mantiene el `REEMPLAZAR_RELAY_HOST`** literal porque es un archivo que se sube a una VM remota sin acceso al `.env` local. La sustitución se hace manualmente o con el helper.
4. **El `docker-compose.yml` NO se toca** — WAHA no tiene la IP del manager.
5. **El `wazuh-waha/wazuh_waha/` (código Python) NO se toca** — el relay no necesita conocer la IP del manager, solo recibe POSTs de él.

### Cambio en el flujo del manager (lo más crítico)

Hoy el flujo es:
1. Tadeo edita manualmente `manager/ossec.conf.snippet.xml`, sustituye `REEMPLAZAR_RELAY_HOST` con `172.44.30.9`.
2. scp a la VM, pegar en `/var/ossec/etc/ossec.conf`.

Después del refactor:
1. Tadeo asegura que `WAZUH_SERVER_IP=172.44.30.12` está en `.env`.
2. Corre `python scripts/render-manager-snippet.py > /tmp/integration.xml` (o `bash scripts/install-manager-files.sh` que hace todo de una).
3. El script lee `WAZUH_SERVER_IP` del `.env`, lo sustituye en el snippet, **y además lee la API key del `.env`** para rellenar `<api_key>`.
4. Tadeo scp el resultado a la VM y lo pega.

## Step-by-step plan

### FASE A — Refactor del repo (commiteable, sin tocar VM)

#### A1. Centralizar IP en `.env.example`
- **Archivo:** `/home/tadeo/Desktop/wazuh-waha/.env.example`
- **Cambio:** agregar bloque arriba (después del comentario inicial):
  ```bash
  # --- Server Wazuh (manager) ---
  # IP UNICA del manager Wazuh. Cambiar acá y todo el repo se actualiza.
  # Esta es la fuente de verdad. WAZUH_MANAGER_HOST y WAZUH_VM_SSH_HOST son
  # aliases deprecated; si están seteados, tienen prioridad por compat.
  WAZUH_SERVER_IP=172.44.30.12
  ```
- Renombrar las líneas `WAZUH_MANAGER_HOST=172.44.30.11` y `WAZUH_VM_SSH_HOST=172.44.30.11` → marcarlas como `# DEPRECATED: use WAZUH_SERVER_IP`. (Mantenerlas para no romper consumidores viejos.)
- Verificar con `grep -nE '^(WAZUH_)' .env.example`.

#### A2. Render helper script
- **Archivo nuevo:** `/home/tadeo/Desktop/wazuh-waha/scripts/render_manager_snippet.py`
- **Qué hace:**
  1. Carga `.env` del cwd o `~/Desktop/wazuh-waha/.env`.
  2. Resuelve `WAZUH_SERVER_IP` (con fallback a `WAZUH_MANAGER_HOST`/`WAZUH_VM_SSH_HOST` deprecated).
  3. Lee `manager/ossec.conf.snippet.xml`, sustituye `REEMPLAZAR_RELAY_HOST` → `WAZUH_SERVER_IP`.
  4. Lee `RELAY_API_KEY` del `.env`, sustituye `REEMPLAZAR_RELAY_API_KEY` → valor real (solo si se pasa `--with-key`, default off por seguridad).
  5. Imprime a stdout el XML listo para `scp` a la VM.
- **Por qué `--with-key` flag:** por default el snippet se imprime con `REEMPLAZAR_RELAY_API_KEY` literal (commiteable); con `--with-key` se le inyecta el secret del `.env` local para generar el archivo que va a la VM. Esto evita filtrar la key en logs o en el repo.
- **Tests:** script es trivial, validar con `python3 -c "import ast; ast.parse(open('scripts/render_manager_snippet.py').read())"`.

#### A3. Diagnose script usa `WAZUH_SERVER_IP`
- **Archivo:** `/home/tadeo/Desktop/wazuh-waha/scripts/diagnose.sh`
- **Cambios:**
  - Línea 20-26: cambiar defaults de `WAZUH_VM_SSH_HOST` y `WAZUH_MANAGER_API_HOST` para que ambos usen `${WAZUH_SERVER_IP:-172.44.30.12}` (en vez de IP literal).
  - Comentarios líneas 6 y 13: actualizar para reflejar que la IP sale del `.env`.
  - Líneas 36-40 (carga del `.env`): ya está OK, no tocar.
- **Diff esperado:** ~10 líneas modificadas. No cambia comportamiento si `.env` ya tiene `WAZUH_SERVER_IP`.

#### A4. Documentar el patrón en `manager/ossec.conf.snippet.md`
- **Archivo:** `/home/tadeo/Desktop/wazuh-waha/manager/ossec.conf.snippet.md`
- **Cambio:** agregar nota arriba: "Para sustituir el placeholder, podés usar el helper `scripts/render_manager_snippet.py` (recomendado) o hacerlo a mano con el valor de `WAZUH_SERVER_IP` del `.env`."
- NO cambiar el contenido de las variantes (siguen con `REEMPLAZAR_RELAY_HOST` literal porque son ejemplos).

#### A5. README + ARCHITECTURE — topología actual
- **Archivos:** `README.md` y `ARCHITECTURE.md`.
- **Cambio:** reemplazar la IP del manager en la sección "Topología" o similar con la indicación "ver `WAZUH_SERVER_IP` en `.env.example`".
- `ARCHITECTURE.md` línea 11 y 28: actualizar la IP del manager. Si tiene un diagrama ASCII con la IP, regenerar.

### FASE B — Reconectar el agente Wazuh local a 172.44.30.12

> **Pitfall conocido (skill `wazuh-deployment` §"No valid server IP found" error 4105):** el bloque `<server><address>` DEBE estar bien formado en `/var/ossec/etc/ossec.conf` del agente. No usar comentarios viejos diciendo "se resuelve desde client.keys" — eso es incorrecto en Wazuh 4.x.

#### B1. Verificar estado actual del agente
```bash
# Estado del servicio
sudo systemctl is-active wazuh-agent
sudo systemctl is-enabled wazuh-agent

# IP actual a la que apunta
sudo grep -A2 '<server>' /var/ossec/etc/ossec.conf
sudo grep -E '<address>' /var/ossec/etc/ossec.conf

# Procesos
ps -eo pid,user,comm | grep wazuh-

# Conectividad TCP al manager nuevo (debe estar cerrado o abierto, no filtrado)
timeout 2 bash -c 'exec 3<>/dev/tcp/172.44.30.12/1514 && echo open || echo closed'
timeout 2 bash -c 'exec 3<>/dev/tcp/172.44.30.12/1515 && echo open || echo closed'
```

#### B2. Backup del ossec.conf del agente
```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%s)
```
(**Nota:** el sandbox bloquea `sudo` con pipe, así que esto va como comando suelto para que Tadeo lo pegue en su TTY.)

#### B3. Editar `/var/ossec/etc/ossec.conf` del agente
Cambiar el bloque `<server>`:
```xml
<server>
  <address>172.44.30.12</address>   <!-- antes: 172.44.30.11 -->
  <port>1514</port>
  <protocol>tcp</protocol>
</server>
```
- Editar con `sudo nano /var/ossec/etc/ossec.conf` o `sudo vim`.
- **Crítico:** validar XML antes de reiniciar:
  ```bash
  sudo python3 -c "import xml.etree.ElementTree as ET; ET.parse('/var/ossec/etc/ossec.conf'); print('XML_OK')"
  ```

#### B4. Habilitar `force_registration` en el manager NUEVO (172.44.30.12)
```bash
# Desde el host Arch
ssh tadeou7@172.44.30.12 'sudo grep -E "force_registration" /var/ossec/etc/ossec.conf'
```
Si está `<disabled>` o no aparece, editar:
```bash
ssh tadeou7@172.44.30.12 'sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%s)'
ssh -t tadeou7@172.44.30.12 'sudo nano /var/ossec/etc/ossec.conf'
# Buscar <auth> y agregar <force_registration>yes</force_registration> si falta
# Reiniciar:
ssh -t tadeou7@172.44.30.12 'sudo systemctl restart wazuh-manager'
```

#### B5. Enrolar agente local contra 172.44.30.12
```bash
sudo /var/ossec/bin/agent-auth -m 172.44.30.12 -p 1515 -A "$(hostname)"
sudo systemctl restart wazuh-agent
```

#### B6. Verificar
```bash
# En el manager nuevo
ssh tadeou7@172.44.30.12 'sudo /var/ossec/bin/manage_agents -l'
# Debe listar tu agente (host Arch) con ID nuevo

# Conexión TCP establecida al puerto de datos
ssh tadeou7@172.44.30.12 'ss -tnp | grep :1514'
# Debe haber una conexión ESTAB desde 172.44.30.9 (este host)

# Logs del agente
sudo journalctl -u wazuh-agent -n 20 --no-pager
# Sin "No valid server IP found" (error 4105)
```

### FASE C — Actualizar el `<integration>` block en el manager nuevo

> **Decisión de scope:** el bloque `<integration>` del manager (`<hook_url>`) apunta al **relay** (`172.44.30.9:8765`), no al manager mismo. Como el relay **NO se muda**, este bloque no necesita re-subirse a menos que también quieras regenerar el snippet por consistencia.

Si Tadeo quiere re-subir el bloque (recomendado para mantener todo sincronizado):

#### C1. Renderizar snippet
```bash
cd ~/Desktop/wazuh-waha
# Default: imprime con API key placeholder (commiteable)
python3 scripts/render_manager_snippet.py
# Con API key real del .env local:
python3 scripts/render_manager_snippet.py --with-key > /tmp/integration.xml
```

#### C2. Subir a la VM
```bash
scp /tmp/integration.xml tadeou7@172.44.30.12:/tmp/integration.xml
```

#### C3. Pegar en `ossec.conf` (usar `scripts/insert-integration-block.py`)
```bash
ssh tadeou7@172.44.30.12 'python3 -c "import shutil,time; shutil.copy2(\"/var/ossec/etc/ossec.conf\",\"/var/ossec/etc/ossec.conf.bak.\"+str(int(time.time())))"'
scp scripts/insert-integration-block.py tadeou7@172.44.30.12:/tmp/
ssh tadeou7@172.44.30.12 'sudo python3 /tmp/insert-integration-block.py /var/ossec/etc/ossec.conf /tmp/integration.xml'
ssh tadeou7@172.44.30.12 'sudo python3 -c "import xml.etree.ElementTree as ET; ET.parse(\"/var/ossec/etc/ossec.conf\"); print(\"XML_OK\")"'
ssh tadeou7@172.44.30.12 'sudo systemctl restart wazuh-manager'
```

### FASE D — End-to-end test (sandbox Hermes bloquea sudo, así que esto es para Tadeo en su TTY)

```bash
# En el host Arch, generar alerta real
sshpass -p wrongpass ssh root@localhost 2>&1 || true    # regla 5710

# Verificar cadena completa
ssh tadeou7@172.44.30.12 'sudo tail -20 /var/ossec/logs/integrations.log'
journalctl -u wazuh-waha -n 10 --no-pager
docker logs wazuh-waha --tail 10
```

## Files likely to change

### Commiteables (repo)
| Archivo | Tipo de cambio |
|---|---|
| `.env.example` | agregar `WAZUH_SERVER_IP`, marcar aliases deprecated |
| `scripts/render_manager_snippet.py` | NUEVO (~50 líneas) |
| `scripts/diagnose.sh` | defaults usan `WAZUH_SERVER_IP` |
| `manager/ossec.conf.snippet.md` | nota sobre el helper |
| `README.md` | referencia a `WAZUH_SERVER_IP` en topología |
| `ARCHITECTURE.md` | actualizar IP del manager en diagrama |
| `CHANGELOG.md` | nueva entrada v0.4.0 con la migración |

### NO commiteables (runtime en VM, fuera del repo)
| Archivo | Máquina | Cambio |
|---|---|---|
| `/var/ossec/etc/ossec.conf` | Host Arch | `<server><address>` 172.44.30.11 → **.12** |
| `/var/ossec/etc/ossec.conf` | VM 172.44.30.12 | `<force_registration>yes</force_registration>` (verificar) + re-pegar `<integration>` block |
| `/var/ossec/etc/client.keys` | VM 172.44.30.12 | nuevo agente enrolado |
| `/var/ossec/etc/wsl-relay.conf` | VM 172.44.30.12 | sin cambios (apunta al relay, no al manager) |

### NO se tocan (decisión explícita)
- `docs/PLAN-2026-06-16-*.md` — registros históricos.
- `CHANGELOG.md` líneas de versiones anteriores.
- Cambios sin commit actuales en HEAD (`config.py`, `formatter.py`, `templates.py`, `local_rules.xml`, `ossec.conf.snippet.xml` ya commiteado con `level 8`) — **se commitean por separado en este mismo plan**, en un commit aparte que NO toque los archivos del refactor.
- `wazuh-waha/wazuh_waha/*.py` — código del relay, no necesita la IP del manager.
- `docker-compose.yml` — WAHA no necesita la IP.

## Tests / validation

### Estáticos (sin red, sin sudo)
- `python3 -m py_compile scripts/render_manager_snippet.py && echo OK`
- `python3 -c "import ast; ast.parse(open('scripts/render_manager_snippet.py').read())"`
- `bash -n scripts/diagnose.sh && echo OK`
- `grep -nE '^(WAZUH_)' .env.example` → debe mostrar `WAZUH_SERVER_IP` y los dos deprecated.
- `grep -rE '172\.44\.30\.11' --include='*.md' --include='*.sh' --include='*.xml' --include='*.py' --include='*.yml' --include='*.example' --exclude-dir='docs' --exclude-dir='CHANGELOG.md' --exclude-dir='.venv' .` → debe dar 0 matches (excepto el deprecated comment en `.env.example`).

### Dinámicos (con red, sin sudo)
- `python3 scripts/render_manager_snippet.py | head -20` → debe imprimir el snippet con `WAZUH_SERVER_IP` sustituido.
- `bash scripts/diagnose.sh` → sección 10 (ping) y 10b (nc a 22) a `172.44.30.12` deben responder.

### End-to-end (con sudo — Tadeo en TTY)
- `sudo systemctl status wazuh-agent` → active (running), sin "No valid server IP found".
- `ssh tadeou7@172.44.30.12 'sudo /var/ossec/bin/manage_agents -l'` → agente enrolado.
- `ssh tadeou7@172.44.30.12 'ss -tnp | grep :1514'` → ESTAB desde 172.44.30.9.
- Dashboard `https://172.44.30.12` → el agente aparece Active.
- Trigger de prueba → WhatsApp llega (validación completa del pipeline, verificada en pasos previos).

## Risks, tradeoffs, and open questions

### Riesgos

1. **`force_registration` requerido en el manager nuevo.** Si Tadeo no lo activó, el `agent-auth` falla con timeout. Verificación B4 es obligatoria antes de B5.
2. **Firewall / routing entre 172.44.30.9 y 172.44.30.12.** Si la VM nueva está en una subred distinta o el firewall bloquea 1514/1515, el agente se conecta pero no transfiere datos. **Diagnóstico:** `nc -zvw3 172.44.30.12 1514` desde Arch. Si `Connection refused` o timeout → ajustar firewall o VirtualBox host-only network.
3. **Cambios sin commit actuales en HEAD** son mezclas de trabajo de Tadeo (templates + threshold). Si los commiteamos junto con el refactor del `.env`, el diff se vuelve ilegible. **Mitigación:** commits separados — uno para "wip: templates + threshold", otro para "feat: refactor .env con WAZUH_SERVER_IP".
4. **El alias deprecated `WAZUH_MANAGER_HOST` puede confundir.** Si Tadeo tiene `WAZUH_SERVER_IP` Y `WAZUH_MANAGER_HOST` en `.env`, el script helper prioriza `WAZUH_MANAGER_HOST` por compat. Si quiere limpiarlo, segundo commit los borra.
5. **El `docs/PLAN-2026-06-16-reconnect.md`** tiene instrucciones para `172.44.30.11` (el viejo). NO se toca, pero queda como referencia histórica. El nuevo flujo se documenta en este plan.

### Tradeoffs

| Decisión | Pro | Contra |
|---|---|---|
| Mantener `WAZUH_MANAGER_HOST` y `WAZUH_VM_SSH_HOST` como deprecated | No rompe scripts viejos | Más ruido en `.env.example` |
| Helper `render_manager_snippet.py` (Python) vs `sed` en bash | Python maneja bien multi-ocurrencia y warnings; menos escape hell | Dependencia implícita de Python en el repo (ya hay Python en el venv) |
| NO tocar `docs/PLAN-2026-06-16-reconnect.md` | Respeta histórico | Documentación dispersa (registro viejo vs nuevo plan) |
| Commit separado para el refactor | Diff limpio, rollback fácil | Más commits por PR |

### Open questions

1. **¿Tadeo quiere que también re-subamos el bloque `<integration>` al manager nuevo?** Si el `ossec.conf` del .12 ya lo tiene idéntico al .11 (porque la migración fue `cp -a` de la VM vieja), no hace falta. Si es una instalación fresca, sí. **Recomendación:** verificar primero con `ssh tadeou7@172.44.30.12 'sudo grep -A6 custom-whatsapp /var/ossec/etc/ossec.conf'`. Si está el bloque, skip Fase C.
2. **¿El relay `wazuh-waha` se queda en este host?** Asumimos que sí (no hay indicio de lo contrario en el código). Confirmar antes de ejecutar.
3. **¿El `wsl-relay.conf` en la VM nueva tiene los mismos valores (`WAZUH_RELAY_URL=http://172.44.30.9:8765/alerts` y la misma API key)?** Asumimos que sí porque las VMs se migraron con la config. Verificar con `ssh tadeou7@172.44.30.12 'sudo cat /var/ossec/etc/wsl-relay.conf'`.

## Out of scope (planes separados si Tadeo lo pide después)

- Renombrar `WAZUH_MANAGER_HOST` y `WAZUH_VM_SSH_HOST` (cleanup total del deprecado).
- Refactor de `docs/PLAN-2026-06-16-reconnect.md` para que use `WAZUH_SERVER_IP`.
- Mover el relay `wazuh-waha` a otra máquina.
- Cambiar Ollama de host.
- Actualizar `scripts/install-wazuh-waha.sh` si existe, para que use `WAZUH_SERVER_IP`.

## Commits sugeridos (en orden)

1. **`wip: templates más ricos + threshold para alertas sin template`** (los 6 archivos modificados actualmente sin commit).
2. **`feat: refactor .env con WAZUH_SERVER_IP centralizado + render helper`**.
3. **`docs: actualizar topología en README y ARCHITECTURE`** (opcional, puede ir en el mismo commit #2).
4. **`chore: bump a v0.4.0`** en `pyproject.toml` + entrada en `CHANGELOG.md`.

## Verificación final (post-deploy)

```bash
# 1. El repo está limpio
git status --short
# esperado: 0 cambios sin commit (o solo el .env real que está gitignored)

# 2. El agente está enrolado al manager nuevo
ssh tadeou7@172.44.30.12 'sudo /var/ossec/bin/manage_agents -l' | grep "$(hostname)"
# esperado: ID asignado, IP=172.44.30.9, Status=Active

# 3. El integration block sigue activo en el manager nuevo
ssh tadeou7@172.44.30.12 'sudo grep -A6 custom-whatsapp /var/ossec/etc/ossec.conf'
# esperado: bloque con hook_url apuntando al relay 172.44.30.9:8765

# 4. Trigger de prueba
sshpass -p wrongpass ssh root@localhost 2>&1 || true
sleep 5
journalctl -u wazuh-waha -n 5 --no-pager | grep POST
# esperado: 200 OK

# 5. WhatsApp llega
docker logs wazuh-waha --tail 5 | grep sendText
# esperado: 201 Created
```