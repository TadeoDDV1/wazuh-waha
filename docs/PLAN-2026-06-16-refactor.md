# Plan de mejora: wazuh-waha (renombre desde `wazuh-integration/`)

> **Para Tadeo:** reorganización + limpieza + documentación + multi-worker + renombre. Sin tests, sin git (lo hacés vos).
> **Para Hermes:** ejecutar task por task en orden. Cada task es una acción concreta con verificación.

---

## Cambios respecto al plan original

| Antes | Ahora | Razón |
|---|---|---|
| `wazuh-integration/` | `wazuh-waha/` | Renombre explícito. Más corto, dice qué hace. |
| `wazuh_relay` (paquete Python) | `wazuh_waha` | Consistencia con el nombre del proyecto. |
| `wazuh-relay` (systemd, paths) | `wazuh-waha` | Idem. |
| `wazuh-waha` (container Docker) | `wazuh-waha` (se mantiene) | Ya estaba bien. |
| 1 worker uvicorn | N workers | Pedido. Implica refactor del dedup. |
| Dedup in-process (dict) | Dedup con file lock atómico | Necesario para multi-worker (cada worker tiene su propia memoria). |

---

## Diagnóstico (relevante para el refactor)

### Multi-worker: el problema real

Hoy `dedup.py:13-58` tiene:

```python
class Deduper:
    def __init__(self, ttl: int, state_file: str | None = None):
        self.ttl = ttl
        self._state: dict[str, float] = {}   # ← en memoria RAM del proceso
        ...

deduper = Deduper(...)   # ← singleton
```

Con `--workers 4` de uvicorn, uvicorn fork-ea 4 procesos hijo. **Cada uno tiene su propio `deduper` con su propio `_state`**. Resultado:

- Worker 1 recibe alerta X, marca en su memoria, escribe a disco.
- Worker 2 recibe alerta X otra vez, lee de disco (puede ver la marca si hubo read), pero si está en cache local puede no verla.

**Fix:** usar `fcntl.flock(fd, LOCK_EX)` alrededor de las operaciones read-modify-write del JSON. Así solo un worker a la vez puede escribir, y todos leen la versión consistente.

### Multi-worker: qué SÍ escala bien

- `waha_client` (cliente async stateless) ✓
- `templates` (funciones puras) ✓
- `formatter` (orquesta las llamadas) ✓
- `config` (lee .env una vez al import) ✓ — aunque en multi-worker se lee N veces, es OK.
- `main.py` (FastAPI app) ✓
- `ollama_client` ✓

### Multi-worker: otros cambios necesarios

- `RotatingFileHandler` ya es thread-safe pero **NO** es multi-process-safe. Solución: usar `concurrent-log-handler` o un `FileLock` wrapper. Para mantener simple: agregar un `fcntl.flock` al handler custom, o usar `ConcurrentRotatingFileHandler` (paquete `concurrent-log-handler`).
- `logging.handlers.QueueListener` para el handler de journal + archivo. Pero eso es YAGNI por ahora: lo dejamos como está, se loguea 1 vez por worker (con `worker_id` en el formatter).

### Renombre: archivo de mapeo

| Viejo | Nuevo |
|---|---|
| `wazuh-integration/` (dir raíz) | `wazuh-waha/` |
| `relay/` (subdir) | `wazuh-waha/` (subdir) — ver nota |
| `relay/wazuh_relay/` (paquete Python) | `wazuh-waha/wazuh_waha/` |
| `relay/systemd/wazuh-relay.service` | `wazuh-waha/systemd/wazuh-waha.service` |
| `relay/pyproject.toml` (name=wazuh-relay) | `wazuh-waha/pyproject.toml` (name=wazuh-waha) |
| `/var/log/wazuh-relay/` | `/var/log/wazuh-waha/` |
| `/var/lib/wazuh-relay/` | `/var/lib/wazuh-waha/` |
| `wazuh-relay` (systemd unit name) | `wazuh-waha` |
| `wazuh-relay` (logger name) | `wazuh-waha` |
| `wazuh-relay` (version) | `wazuh-waha` v0.3.0 |
| Container `wazuh-waha` (WAHA Docker) | `wazuh-waha` (se mantiene, ya estaba bien) |
| `wazuh-relay` (volumen Docker) | `wazuh_waha_sessions` (se mantiene) |

**Nota sobre el subdir:** el viejo layout tenía `wazuh-integration/relay/`. Con el renombre, queda `wazuh-waha/wazuh-waha/` (paquete) o `wazuh-waha/src/wazuh_waha/`. Prefiero esto último (src layout) porque es lo que recomienda la doc de Python packaging moderna y evita imports confusos. **Decisión:** usar `wazuh-waha/wazuh_waha/` directo (mismo nivel, sin `src/`). Razón: este proyecto es chico, `src/` es overhead, y mantener el path corto es más legible. Documentado en ARCHITECTURE.md.

---

## Tareas (20, en 5 fases)

### Fase 1 — Renombre del árbol (mecánico)

#### Task 1: Renombrar carpeta raíz `wazuh-integration` → `wazuh-waha`

**Acción:**
```bash
cd ~/Desktop
mv wazuh-integration wazuh-waha
```

**Verificación:** `cd ~/Desktop/wazuh-waha && pwd && ls`

**No usar `rm -rf` ni batch.** El `mv` simple de una carpeta no genera alertas de sandbox.

⚠️ **Importante:** después de este task, el systemd unit del relay queda apuntando al path viejo (`/home/tadeo/Desktop/wazuh-integration/relay/...`) y va a crashear al restart. No reiniciar el servicio hasta haber aplicado Tasks 10-12 (override con paths nuevos). Si necesitás reiniciar antes, el unit ya está documentado con la fix pattern del pitfall #15 (override.conf).

#### Task 2: Renombrar subdir `relay/` → `wazuh-waha/`

**Acción:**
```bash
cd ~/Desktop/wazuh-waha
mv relay wazuh-waha
```

**Verificación:** `ls wazuh-waha/`

#### Task 3: Renombrar paquete Python `wazuh_relay/` → `wazuh_waha/`

**Acción:**
```bash
cd ~/Desktop/wazuh-waha/wazuh-waha
mv wazuh_relay wazuh_waha
```

**Verificación:** `ls wazuh_waha/`

---

### Fase 2 — `.env.example` y `.gitignore`

#### Task 4: Crear `.env.example` (raíz del proyecto)

**Path:** `~/Desktop/wazuh-waha/.env.example`

**Contenido completo:**

```ini
# =============================================================================
# wazuh-waha - Variables de entorno
# =============================================================================
# Copia este archivo a .env y completa los valores. .env NO se commitea.
#
# Para generar API keys seguras:
#   openssl rand -hex 24   # 48 chars
# =============================================================================

# --- Relay (servicio wazuh-waha) ---
RELAY_PORT=8765
RELAY_BIND=0.0.0.0
RELAY_API_KEY=***  # openssl rand -hex 24
RELAY_DEDUP_TTL=300
RELAY_LOG_DIR=/var/log/wazuh-waha
RELAY_LIB_DIR=/var/lib/wazuh-waha
RELAY_WORKERS=2   # cantidad de workers uvicorn (multi-proceso)
RELAY_LIFESPAN_TIMEOUT=10   # segundos esperando startup

# --- WhatsApp destino ---
ADMIN_PHONE=                  # formato: 5219991234567 (sin +)

# --- WAHA (WhatsApp HTTP API, en Docker) ---
WAHA_API_KEY=                 # 48 chars
WAHA_HOST=http://localhost:3000
WAHA_SESSION=default
WAHA_LOG_LEVEL=info
WAHA_HOOK_URL=

# --- Ollama (IA local) ---
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:0.5b
OLLAMA_TIMEOUT=10
OLLAMA_ENABLED=false   # false = no usa IA, solo templates (recomendado)

# --- Diagnóstico (opcional) ---
WAZUH_MANAGER_HOST=172.44.30.11
WAZUH_MANAGER_API_USER=wazuh
WAZUH_MANAGER_API_PASS=    # pass de la API REST del manager
WAZUH_VM_SSH_USER=tadeou7
WAZUH_VM_SSH_HOST=172.44.30.11
WAZUH_VM_SSH_PORT=22
# NOTA: la pass SSH se lee de WAZUH_VM_SSH_PASS en runtime, NO la pongas aca.
```

#### Task 5: Reescribir `.gitignore`

**Path:** `~/Desktop/wazuh-waha/.gitignore`

**Contenido completo:**

```gitignore
# Secrets — NUNCA subir
.env
.env.*
!.env.example
deploy/**/relay.env
deploy/**/*.env.local

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
.venv/
venv/
ENV/
env/
*.egg-info/
*.egg
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Logs
*.log
logs/

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# OS
Thumbs.db

# Cache local de Wazuh (no es parte del repo)
.sixth/
```

**Verificación:**
```bash
# esperado: paths ignorados
git check-ignore -v .env .venv wazuh-waha/wazuh_waha.egg-info/ 2>&1 || echo "no es repo git, OK"
```

---

### Fase 3 — Estructura de carpetas y archivos completos

#### Task 6: Crear `docs/`, `scripts/`, `deploy/`, `tests/` (vacíos con README)

**Acción:** crear las 4 carpetas + un `README.md` mínimo en cada una.

**`docs/README.md`:**
```markdown
# Docs

Contenido:

- `deployment.md` — cómo instalar en una VM nueva.
- `troubleshooting.md` — issues frecuentes y fixes.
- `rules-coverage.md` — qué rule_ids tienen template, qué level mínimo.
- `ollama.md` — estado actual de la integración con Ollama, cómo activarla.
- `multi-worker.md` — consideraciones al correr con `--workers N`.
- `migration-from-wazuh-integration.md` — checklist de qué renombrar si venís del proyecto viejo.
```

**`scripts/README.md`:**
```markdown
# Scripts

Ejecutables bash de primer nivel. No se commitean con sudo, ver nota en cada uno.

| Script | Para qué sirve | Necesita sudo | TTY |
|---|---|---|---|
| `diagnose.sh` | Check read-only de toda la stack | a veces | no |
| `diag-vbox.sh` | Diagnóstico de red VirtualBox | no | no |
| `fix-wazuh-waha.sh` | Reinicia el servicio si está zombie | sí | sí |
| `install-wazuh-waha.sh` | Instala unit + dirs + restart | sí | sí |
| `recover-waha.sh` | STOP+wait+START sesión WAHA pegada | no | no |
```

**`deploy/README.md`:**
```markdown
# Deploy

Configuración específica por host. Cada host donde se corre este proyecto tiene
su subcarpeta. El código de `wazuh-waha/` y `manager-side/` no se toca por deploys.

| Subdir | Para qué sirve |
|---|---|
| `arch-host/` | Ejemplo: el host Arch donde corre el relay. |
| `vm-manager-side/` | Ejemplo: la VM Wazuh 4.x que manda las alertas. |
```

**`tests/README.md`:**
```markdown
# Tests

(pendiente — alcance actual no incluye tests)

Tests planeados:
- `test_dedup.py` — Deduper con fcntl.flock (file lock atómico).
- `test_formatter.py` — orquesta dedup → template → default.
- `test_templates.py` — render() de cada rule_id.
- `test_waha_client.py` — mock httpx, cubre success / 4xx / 5xx / timeout.
- `test_main.py` — FastAPI TestClient, /health /alerts /debug/recent.
```

#### Task 7: Crear `docs/deployment.md` (contenido completo)

**Path:** `~/Desktop/wazuh-waha/docs/deployment.md`

**Contenido completo:**

```markdown
# Deployment

Instalar `wazuh-waha` desde cero en un host Arch (o Linux similar). Asume que
ya tenés WAHA corriendo en Docker y Wazuh manager en una VM aparte.

## 1. Instalar el relay

### 1.1 Clonar el repo

```bash
git clone https://github.com/<owner>/wazuh-waha.git
cd wazuh-waha
```

### 1.2 Crear `.env`

```bash
cp .env.example .env
$EDITOR .env
chmod 600 .env
```

Generar API key:
```bash
openssl rand -hex 24   # pegar en RELAY_API_KEY
```

### 1.3 Crear venv e instalar deps

```bash
cd wazuh-waha
python3.11 -m venv .venv
.venv/bin/pip install -e .
```

(Si el sistema tiene Python < 3.11, instalar `python3.11` desde AUR o usar
el `pyenv` del usuario.)

### 1.4 Instalar como servicio systemd

```bash
sudo cp systemd/wazuh-waha.service /etc/systemd/system/wazuh-waha.service
sudo mkdir -p /etc/wazuh-waha
sudo cp ../deploy/arch-host/relay.env /etc/wazuh-waha/relay.env
sudo chmod 600 /etc/wazuh-waha/relay.env
sudo cp ../deploy/arch-host/wazuh-waha.service.override.conf \
        /etc/systemd/system/wazuh-waha.service.d/override.conf

sudo systemctl daemon-reload
sudo systemctl enable wazuh-waha
sudo systemctl restart wazuh-waha
```

### 1.5 Verificar

```bash
systemctl status wazuh-waha --no-pager
curl -m 3 http://127.0.0.1:8765/health
# esperado: {"status":"ok","service":"wazuh-waha","version":"0.3.0"}
```

## 2. Instalar en la VM del manager

### 2.1 Subir archivos

Desde el host Arch:
```bash
scp manager-side/custom/whatsapp_alert.py tadeou7@<VM_IP>:/tmp/
scp manager-side/rules/local_rules.xml tadeou7@<VM_IP>:/tmp/
scp manager-side/ossec.conf.snippet.xml tadeou7@<VM_IP>:/tmp/
```

### 2.2 Instalar en la VM (ssh + sudo con TTY)

En la VM:
```bash
sudo mv /tmp/whatsapp_alert.py /var/ossec/integrations/custom/
sudo chmod 750 /var/ossec/integrations/custom/whatsapp_alert.py
sudo chown root:wazuh /var/ossec/integrations/custom/whatsapp_alert.py

sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
```

### 2.3 Editar `ossec.conf`

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%s)
sudo nano /var/ossec/etc/ossec.conf
```

Pegar el bloque `<integration>` de `ossec.conf.snippet.xml` justo antes del
`</ossec_config>` final. Reemplazar `<REEMPLAZAR_RELAY_HOST>` por la IP del
host donde corre el relay, y `<REEMPLAZAR_RELAY_API_KEY>` por el valor de
`RELAY_API_KEY` del `.env` del host.

Validar XML:
```bash
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("/var/ossec/etc/ossec.conf"); print("XML_OK")'
```

### 2.4 Reiniciar manager

```bash
sudo systemctl restart wazuh-manager
```

### 2.5 Verificar que el bloque está cargado

```bash
sudo /var/ossec/bin/wazuh-logtest -t   # testea lectura de ossec.conf
sudo tail -f /var/ossec/logs/ossec.log | grep -i integration
```

## 3. Test end-to-end

Desde el agente (tu host Arch):
```bash
# SSH fallido (regla 5710)
sshpass -p wrongpass ssh root@localhost 2>&1 || true

# O un FIM (regla 550)
touch /tmp/test_fim
```

Esperá 5-10 segundos. Debería llegarte un WhatsApp. Si no llega,
ver `docs/troubleshooting.md`.
```

#### Task 8: Crear `docs/troubleshooting.md`

**Path:** `~/Desktop/wazuh-waha/docs/troubleshooting.md`

**Contenido completo:**

```markdown
# Troubleshooting

## "El relay escucha en :8765 pero /health da timeout"

Síntoma:
- `systemctl status wazuh-waha` dice `active (running)`
- `ss -tln | grep :8765` muestra puerto abierto
- `curl -m 3 http://127.0.0.1:8765/health` → connection timeout

Causa típica: uvicorn colgó en startup (lock, Ollama unreachable, etc.) o un
worker está pegado en un handler. systemd NO lo reinicia (técnicamente corre).

Fix:
```bash
sudo systemctl restart wazuh-waha
sleep 2
curl -m 3 http://127.0.0.1:8765/health
```

Si persiste, ver `journalctl -u wazuh-waha -n 50`.

Script automatizado: `scripts/fix-wazuh-waha.sh`.

## "WAHA devuelve 201 pero el WhatsApp no llega"

Tres causas en orden de probabilidad:

1. **Número mal formateado** — para México el formato es `52 + 1 + número
   móvil` (12 dígitos). Si falta el `1` después de `52` (11 dígitos) WAHA
   acepta el POST pero el servidor de WhatsApp lo descarta silenciosamente.
   Verificar contra `me.id` de la sesión WAHA:
   ```bash
   curl -H "X-Api-Key: $WAHA_API_KEY" http://localhost:3000/api/sessions/default | jq .me.id
   ```

2. **`presence: "offline"`** en la sesión = el teléfono no está sincronizando
   con el servidor de WhatsApp. La API no falla, el mensaje queda encolado.
   No es bug del pipeline.

3. **Sesión desvinculada por uso anómalo** — WAHA sigue devolviendo 201, pero
   WhatsApp te desvinculó. Verificar `me.id != null`.

## "La sesión WAHA se quedó en STARTING"

Síntoma: `POST /api/sessions/default/start` la pasa a `STARTING` y queda ahí
indefinidamente.

Lo que NO funciona: varios `start` consecutivos, `restart` del container, `docker compose down -v` (esto último borra la sesión, hay que re-escanear QR).

Lo que SÍ funciona (secuencia STOP+wait+START):
```bash
source .env
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST http://localhost:3000/api/sessions/default/stop
sleep 5
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST http://localhost:3000/api/sessions/default/start
# Poll hasta WORKING (30-45s)
```

Script automatizado: `scripts/recover-waha.sh`.

## "401 Unauthorized en el relay"

La API key no coincide entre el manager y el relay. Verificar:
```bash
# En el host del relay
grep RELAY_API_KEY .env
systemctl show wazuh-waha -p EnvironmentFiles
# EnvironmentFile debe apuntar al archivo correcto
```

En el manager, la key vive en el `<api_key>` del bloque `<integration>` de
`ossec.conf`. Si la cambiaste, reiniciar el manager.

## "El manager manda el POST al relay pero el journal del relay está vacío"

Causa típica: el bloque `<integration>` está en `ossec.conf` pero
`whatsapp_alert.py` no está en `/var/ossec/integrations/custom/` o no tiene
los permisos correctos.

Verificar:
```bash
ssh tadeou7@<VM_IP> 'ls -la /var/ossec/integrations/custom/whatsapp_alert.py'
# esperado: -rwxr-x--- 1 root wazuh ... whatsapp_alert.py

ssh tadeou7@<VM_IP> 'sudo grep -A8 custom-whatsapp /var/ossec/etc/ossec.conf'
# esperado: bloque <integration> con tu hook_url
```

## "Multi-worker: el dedup no funciona"

Síntoma: la misma alerta llega 2-3 veces en lugar de 1.

Causa: con `--workers N`, cada worker tiene su propio `Deduper` en memoria.
Si llegan N requests en paralelo, cada worker chequea su propia cache y no
ve las marcas de los otros.

El `Deduper` actual usa `fcntl.flock` para serializar read-modify-write del
JSON. Si no funciona, verificar:

```bash
# ¿El archivo de estado es escribible por el usuario del servicio?
ls -la /var/lib/wazuh-waha/dedup_state.json
sudo -u <usuario> touch /var/lib/wazuh-waha/test
# esperado: 0, no "Permission denied"

# ¿Los workers están viendo el mismo archivo?
# Ver con: curl /debug/recent | jq '.alerts[].worker_id'
# Todos los workers deben escribir al mismo path
```

## "Quiero separar `wazuh-integration/` en su propio repo → renombrar a wazuh-waha"

Ver `docs/migration-from-wazuh-integration.md`.
```

#### Task 9: Crear `docs/rules-coverage.md`

**Path:** `~/Desktop/wazuh-waha/docs/rules-coverage.md`

**Contenido completo:**

```markdown
# Rules coverage

Mapeo rule_id → plantilla de mensaje → level mínimo en el `<integration>`.

| rule_id | Descripción | Plantilla | Level mín. | Grupo |
|---|---|---|---|---|
| 520 | Binario SUID | `templates.py:SUID` | 10 | syscheck |
| 550 | Archivo nuevo (FIM) | `templates.py:FIM_created` | 10 | syscheck |
| 553 | Archivo modificado (FIM) | `templates.py:FIM_modified` | 10 | syscheck |
| 554 | Archivo eliminado (FIM) | `templates.py:FIM_deleted` | 10 | syscheck |
| 2901 | Useradd fallido | `default` | 10 | adduser |
| 2902 | Descarga web | `templates.py:web_download` | 10 | web |
| 2903 | Descarga sospechosa | `templates.py:web_download_suspicious` | 10 | web |
| 5401 | Sudo fallido | `templates.py:sudo_failed` | 10 | sudo |
| 5710 | SSH fallido | `templates.py:ssh_failed` | 10 | sshd |
| 5712 | Múltiples SSH fallidos | `templates.py:ssh_bruteforce` | 10 | sshd |
| 5715 | `su` fallido | `templates.py:su_failed` | 10 | authentication |
| 57100 | SSH login exitoso (custom) | `templates.py:ssh_login_success` | 10 | authentication_success |
| 57101 | SSH login con pubkey (custom) | `templates.py:ssh_login_pubkey` | 10 | authentication_success |
| 57102 | SSH login como root (custom) | `templates.py:root_login` | 12 | authentication_success, root_login |
| 57103 | `su` exitoso (custom) | `templates.py:su_success` | 10 | authentication_success |
| 57104 | Sudo exitoso (custom) | `templates.py:sudo_success` | 8 | authentication_success |
| 57105 | Login local TTY (custom) | `templates.py:local_login` | 8 | authentication_success |
| 57106 | Logout (custom) | `templates.py:logout` | 3 | authentication_success |

## Cómo agregar un nuevo template

1. Editar `wazuh-waha/wazuh_waha/templates.py`.
2. Agregar el `rule_id` en el dict `TEMPLATES` con su función lambda.
3. Si la regla es custom (fuera de stock Wazuh), agregar el bloque en
   `manager-side/rules/local_rules.xml` y reiniciar el manager.
4. Actualizar esta tabla.

## Cómo desactivar un template

Borrar (o comentar) la entrada del dict `TEMPLATES` en `templates.py`.
Reiniciar el servicio. Las alertas que matcheen ese rule_id caerán a
`render_default()` (formato genérico).
```

#### Task 10: Crear `docs/ollama.md`

**Path:** `~/Desktop/wazuh-waha/docs/ollama.md`

**Contenido completo:**

```markdown
# Ollama integration

## Estado actual (junio 2026)

- `ollama_client.py` está **implementado** pero **desconectado** del formatter.
- Por default `OLLAMA_ENABLED=false` en `.env.example`.
- Si querés activarlo, hay un único cambio en `formatter.py` (ver abajo).

## Por qué off por default

Wazuh corre el script de integración con un timeout corto (~5s). Ollama
`qwen2.5:0.5b` en CPU tarda **~10s por resumen**. Eso excede el timeout, Wazuh
mata el script, y el `print(..., file=sys.stderr)` que documenta el error
tampoco se loguea (el proceso murió antes).

En resumen: con IA activada, **algunas alertas no se mandan y no sabemos por
qué**.

## Cuándo tiene sentido activarlo

- Tenés GPU disponible (`llama3.2:3b` con GPU corre en ~1s).
- Querés resumen para alertas que no tienen template (actualmente caen a
  `render_default()`, que es solo la metadata en texto plano).
- Podés tolerar que las alertas `level >= 12` tarden 2-3s más.

## Cómo activarlo

### 1. Setear env

```ini
# .env
OLLAMA_ENABLED=true
OLLAMA_MODEL=qwen2.5:0.5b   # o el que prefieras
OLLAMA_TIMEOUT=5            # segundos antes de fallback a default
```

### 2. Enchufar en `formatter.py`

Cambiar la rama "default" en `format_alert()`:

```python
# Antes:
meta["decision"] = "default"
return (templates.render_default(alert), meta)

# Después:
from . import ollama_client
from .config import settings
if settings.ollama_enabled:
    summary = await ollama_client.summarize(alert, timeout=settings.ollama_timeout)
    if summary:
        meta["decision"] = "ollama"
        return (summary, meta)
meta["decision"] = "default"
return (templates.render_default(alert), meta)
```

### 3. Subir el timeout del integration

En el bloque `<integration>` del manager:
```xml
<options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 30</options>
```

### 4. Reiniciar

```bash
sudo systemctl restart wazuh-waha
```

## Cuándo NO activarlo

- En hot path para TODAS las alertas (cuelga el manager).
- Sin GPU (CPU + qwen2.5:0.5b = ~10s, inaceptable).
- Si el operador no entiende por qué algunas alertas tardan más.
```

#### Task 11: Crear `docs/multi-worker.md`

**Path:** `~/Desktop/wazuh-waha/docs/multi-worker.md`

**Contenido completo:**

```markdown
# Multi-worker considerations

`wazuh-waha` corre con `uvicorn --workers N` por defecto (`N=2`, configurable
con `RELAY_WORKERS` en `.env`).

## Qué escala bien

- **`templates.py`**: funciones puras, sin estado.
- **`waha_client.py`**: cliente httpx async, sin estado.
- **`ollama_client.py`**: cliente httpx async, sin estado.
- **`config.py`**: se lee una vez al import del módulo; cada worker lee su
  propia copia, pero los valores son idénticos (del mismo `.env`).
- **`main.py`** (FastAPI): stateless entre requests, salvo el buffer
  `_recent` que es por-worker (cada uno tiene el suyo — esto es OK, no es
  estado crítico).
- **Logging**: el `StreamHandler` (journal) es independiente por worker, OK.

## Qué necesita coordinación entre workers

### Dedup

El `Deduper` actual persiste a `/var/lib/wazuh-waha/dedup_state.json`.
Con multi-worker, dos workers pueden intentar actualizar el JSON al mismo
tiempo, lo que resulta en un estado corrupto (read-modify-write race).

**Solución implementada:** `fcntl.flock(fd, LOCK_EX)` alrededor de read +
modify + write. Solo un worker a la vez puede actualizar; los demás esperan
con `LOCK_SH` para leer.

**Limitación:** bajo carga extrema (>100 alerts/s), el lock se vuelve
contended y la latencia sube. Para este caso de uso (alertas de seguridad,
picos de 5-10/s) es más que suficiente.

### Logging a archivo

`RotatingFileHandler` es thread-safe pero **NO** multi-process-safe.
Si dos workers escriben al mismo `/var/log/wazuh-waha/wazuh-waha.log` al
mismo tiempo, se pisan mensajes.

**Solución:** usamos `ConcurrentRotatingFileHandler` (paquete
`concurrent-log-handler`) en lugar de `RotatingFileHandler`. O el workaround
más simple: el `log_filename` incluye el `worker_id` (`wazuh-waha-1.log`,
`wazuh-waha-2.log`) y journald consolida.

**Decisión actual:** journal handler + log por worker. Los `journalctl -u
wazuh-waha` van a mostrar entries de todos los workers con su PID (que
uvicorn incluye en el log message).

### Estado en memoria (no crítico)

- **`_recent` (deque)**: buffer circular de últimas 50 alertas. Con 2
  workers, cada uno tiene su propio buffer de 50, así que en `/debug/recent`
  vas a ver hasta 100 alertas (50 de cada uno). No es bug, es feature.
- **`_fail_window` (en waha_client)**: counter de fallos de WAHA. Cada
  worker tiene el suyo. Si 4 alertas consecutivas fallan en worker 1 y
  worker 2 también falla 4, el umbral de CRITICAL (5 en 60s) no se dispara
  en ninguno de los dos.

  **Fix futuro (no implementado en este alcance):** mover `_fail_window` a
  un archivo `fail_state.json` con `fcntl.flock`, igual que dedup.

## Cómo saber cuántos workers están corriendo

```bash
systemctl status wazuh-waha --no-pager
# PIDs en la lista de procesos hijos de uvicorn

curl http://127.0.0.1:8765/debug/workers
# devuelve {"workers": [{"pid": 1234, "started_at": "..."}, ...]}
```

El endpoint `/debug/workers` se agrega como parte de este refactor.

## Tuning de `RELAY_WORKERS`

Regla de dedo: `workers = 2 * cpu_cores + 1`. Para una VM con 2 cores
típica, `workers=2` es suficiente. Más workers solo ayuda si las alertas
son CPU-bound (lo son: formateo + httpx + JSON parsing); I/O-bound no se
beneficia.
```

#### Task 12: Crear `docs/migration-from-wazuh-integration.md`

**Path:** `~/Desktop/wazuh-waha/docs/migration-from-wazuh-integration.md`

**Contenido completo:**

```markdown
# Migración desde `wazuh-integration/`

El proyecto se renombró de `wazuh-integration/` a `wazuh-waha/`. Esta guía es
para clones viejos o instalaciones previas del relay.

## Checklist de migración

### 1. Mover el código

```bash
# Si el proyecto está en ~/Desktop/wazuh-integration/
mv ~/Desktop/wazuh-integration ~/Desktop/wazuh-waha
```

### 2. Renombrar subdirs internos

```bash
cd ~/Desktop/wazuh-waha
mv relay wazuh-waha
mv wazuh-waha/wazuh_relay wazuh-waha/wazuh_waha
```

### 3. Actualizar el unit de systemd

El unit `/etc/systemd/system/wazuh-relay.service` (viejo nombre) tiene que
desaparecer y ser reemplazado por `wazuh-waha.service`:

```bash
sudo systemctl stop wazuh-relay
sudo systemctl disable wazuh-relay
sudo rm /etc/systemd/system/wazuh-relay.service
sudo rm -rf /etc/systemd/system/wazuh-relay.service.d   # si había override
```

Y reinstalar el nuevo (ver `docs/deployment.md` §1.4).

### 4. Mover logs y state

```bash
sudo mv /var/log/wazuh-relay /var/log/wazuh-waha
sudo mv /var/lib/wazuh-relay /var/lib/wazuh-waha
```

### 5. Actualizar `.env`

Editar `RELAY_LOG_DIR` y `RELAY_LIB_DIR`:

```ini
RELAY_LOG_DIR=/var/log/wazuh-waha
RELAY_LIB_DIR=/var/lib/wazuh-waha
```

Y `RELAY_API_KEY` se mantiene igual (no se regenera).

### 6. Si tenés el servicio corriendo en producción

```bash
sudo systemctl daemon-reload
sudo systemctl reset-failed
sudo systemctl start wazuh-waha
sudo systemctl status wazuh-waha --no-pager
```

### 7. Re-escanear el QR de WAHA (no, esto NO es necesario)

El volumen Docker de WAHA se mantiene igual (`wazuh_waha_sessions`). El
container `wazuh-waha` no cambia. La sesión de WhatsApp persiste.

## Búsqueda de paths viejos

Para encontrar cualquier referencia residual al nombre viejo:

```bash
cd ~/Desktop/wazuh-waha
grep -rE '(wazuh-integration|wazuh_relay|wazuh-relay)' \
  --include='*.py' --include='*.sh' --include='*.xml' \
  --include='*.md' --include='*.toml' --include='*.service' \
  --exclude-dir='.venv' --exclude-dir='*.egg-info' .
```

Si aparece algo que no debería, es un bug. Reemplazar siguiendo el mapping
de Task 1-3.
```

---

### Fase 4 — Scripts (contenido completo)

#### Task 13: `scripts/diagnose.sh` (rewrite completo, sin pass hardcoded)

**Path:** `~/Desktop/wazuh-waha/scripts/diagnose.sh`

**Contenido completo:**

```bash
#!/bin/bash
# Diagnostico read-only de la integracion Wazuh -> WAHA.
# NO modifica nada. Solo lee.
#
# Variables opcionales (de .env o exportadas):
#   WAZUH_VM_SSH_HOST     IP/host de la VM Wazuh (default 172.44.30.11)
#   WAZUH_VM_SSH_USER     Usuario SSH (default tadeou7)
#   WAZUH_VM_SSH_PORT     Puerto SSH (default 22)
#   WAZUH_VM_SSH_PASS     Pass SSH. Si no esta seteada, se skipea el ssh test.
#   WAHA_HOST             URL base de WAHA (default http://172.44.30.9:3000)
#   RELAY_HOST            URL base del relay (default http://172.44.30.9:8765)
#   OLLAMA_HOST           URL base de Ollama (default http://172.44.30.9:11434)
#   WAZUH_MANAGER_API_HOST (default 172.44.30.11)
#   WAZUH_MANAGER_API_USER (default wazuh)
#   WAZUH_MANAGER_API_PASS Si no esta seteada, se skipea el test de la API.

set +e

# Defaults
WAZUH_VM_SSH_HOST="${WAZUH_VM_SSH_HOST:-172.44.30.11}"
WAZUH_VM_SSH_USER="${WAZUH_VM_SSH_USER:-tadeou7}"
WAZUH_VM_SSH_PORT="${WAZUH_VM_SSH_PORT:-22}"
WAHA_HOST="${WAHA_HOST:-http://172.44.30.9:3000}"
RELAY_HOST="${RELAY_HOST:-http://172.44.30.9:8765}"
OLLAMA_HOST="${OLLAMA_HOST:-http://172.44.30.9:11434}"
WAZUH_MANAGER_API_HOST="${WAZUH_MANAGER_API_HOST:-172.44.30.11}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh}"

GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }
sep()  { echo -e "\n${YEL}========== $1 ==========${NC}"; }

# Cargar .env si existe en el cwd o ~/Desktop/wazuh-waha/.env
if [ -f .env ]; then
  set -a; source .env; set +a
elif [ -f ~/Desktop/wazuh-waha/.env ]; then
  set -a; source ~/Desktop/wazuh-waha/.env; set +a
fi

sep "1. WAHA (docker)"
docker ps --filter "name=wazuh-waha" --format "  {{.Names}}  {{.Status}}  {{.Ports}}" 2>&1
if docker ps --filter "name=wazuh-waha" --format "{{.Names}}" 2>/dev/null | grep -q waha; then
  ok "WAHA container running"
else
  fail "WAHA container NOT running"
fi

sep "2. WAHA session (pide API key desde .env)"
if [ -z "$WAHA_API_KEY" ]; then
  fail "no pude leer WAHA_API_KEY del .env"
else
  echo "  key len: ${#WAHA_API_KEY}"
  curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" "$WAHA_HOST/api/sessions/default" 2>&1 | head -c 600
  echo
fi

sep "3. Puerto 8765 (relay)"
if ss -tln 2>/dev/null | grep -q ":8765"; then
  ok "relay escucha en :8765"
else
  fail "nada escucha en :8765"
fi

sep "4. Relay health endpoint"
curl -sS -m 5 "$RELAY_HOST/health" 2>&1
echo

sep "5. Relay systemd unit"
systemctl is-active wazuh-waha 2>&1
systemctl is-enabled wazuh-waha 2>&1
systemctl status wazuh-waha --no-pager 2>&1 | head -15

sep "6. Ollama"
curl -sS -m 5 "$OLLAMA_HOST/api/tags" 2>&1 | head -c 400
echo

sep "7. Wazuh Manager API ($WAZUH_MANAGER_API_HOST:55000)"
if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
  warn "WAZUH_MANAGER_API_PASS no seteada, saltando"
else
  curl -sS -m 5 -k -u "$WAZUH_MANAGER_API_USER:$WAZUH_MANAGER_API_PASS" \
    "https://$WAZUH_MANAGER_API_HOST:55000/" 2>&1 | head -c 300
  echo
fi

sep "8. Wazuh Manager status"
if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
  warn "WAZUH_MANAGER_API_PASS no seteada, saltando"
else
  curl -sS -m 5 -k -u "$WAZUH_MANAGER_API_USER:$WAZUH_MANAGER_API_PASS" \
    "https://$WAZUH_MANAGER_API_HOST:55000/manager-side/status" 2>&1 | head -c 400
  echo
fi

sep "9. Agente Wazuh LOCAL"
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
  ok "wazuh-agent activo"
elif [ -x /var/ossec/bin/wazuh-control ]; then
  /var/ossec/bin/wazuh-control status 2>&1 | head -10
else
  warn "no encontre wazuh-agent local"
fi

sep "10. Ping a la VM manager"
ping -c 2 -W 2 "$WAZUH_VM_SSH_HOST" 2>&1 | tail -5

sep "10b. SSH port abierto?"
nc -zvw3 "$WAZUH_VM_SSH_HOST" "$WAZUH_VM_SSH_PORT" 2>&1 || echo "puerto $WAZUH_VM_SSH_PORT cerrado/timed out"

sep "11. SSH a la VM (solo check de pass, no hace nada)"
if [ -z "$WAZUH_VM_SSH_PASS" ]; then
  warn "WAZUH_VM_SSH_PASS no seteada, saltando ssh test"
elif ! command -v sshpass >/dev/null; then
  warn "sshpass no instalado, saltando ssh test"
else
  sshpass -p "$WAZUH_VM_SSH_PASS" ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -p "$WAZUH_VM_SSH_PORT" \
    "$WAZUH_VM_SSH_USER@$WAZUH_VM_SSH_HOST" \
    'echo SSH_OK; ls /var/ossec/etc/ossec.conf 2>&1; sudo -n true 2>&1 && echo SUDO_OK || echo SUDO_needs_tty' \
    2>&1 | head -10
fi

sep "12. Estructura del repo"
ls -la ~/Desktop/wazuh-waha/ 2>&1 | head -15
ls -la ~/Desktop/wazuh-waha/wazuh-waha/ 2>&1 | head -10

echo
echo -e "${GRN}========== FIN DIAGNOSTICO ==========${NC}"
echo "Pegame toda esta salida en el chat."
```

#### Task 14: `scripts/diag-vbox.sh` (rewrite)

**Path:** `~/Desktop/wazuh-waha/scripts/diag-vbox.sh`

**Contenido completo:**

```bash
#!/bin/bash
# Diagnostico del networking de VirtualBox desde el host Arch.
# NO modifica nada. Solo lee.

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }
sep()  { echo -e "\n${YEL}========== $1 ==========${NC}"; }

VM_NAME="${1:-wazuh-prueba1}"   # nombre de la VM Wazuh (default)

sep "1. VBoxManage existe?"
if command -v VBoxManage >/dev/null 2>&1; then
  ok "VBoxManage: $(which VBoxManage)"
  VBoxManage --version 2>&1
else
  fail "VBoxManage no esta en PATH"
  echo "Si VirtualBox esta instalado, proba:"
  echo "  /usr/lib/virtualbox/VBoxManage --version"
  echo "  /opt/VBoxManage --version"
  echo "  find / -name VBoxManage 2>/dev/null"
  exit 1
fi

sep "2. VMs registradas"
VBoxManage list vms 2>&1

sep "3. Estado de la VM $VM_NAME"
VBoxManage showvminfo "$VM_NAME" --details 2>&1 | head -40

sep "4. Adaptadores host-only de VirtualBox"
VBoxManage list hostonlyifs 2>&1

sep "5. DHCP servers de VirtualBox"
VBoxManage list dhcpservers 2>&1

sep "6. Tu Arch tiene la IP esperada en el host-only?"
ip -4 addr show 2>&1 | grep -E "inet 172.44" || warn "NO hay IP 172.44.30.x en ninguna interfaz"
echo
ip -4 addr show 2>&1 | grep -E "vbox|host-only|virbr" || echo "tampoco hay interface 'vboxnet' tipica"

sep "7. Si la VM esta corriendo, que dice su red (guest side)"
RUNNING=$(VBoxManage list runningvms 2>&1 | grep -c "$VM_NAME")
if [ "$RUNNING" -gt 0 ]; then
  ok "$VM_NAME esta corriendo"
  VBoxManage guestproperty get "$VM_NAME" "/VirtualBox/GuestInfo/Net/0/V4/IP" 2>&1
  VBoxManage guestproperty get "$VM_NAME" "/VirtualBox/GuestInfo/Net/0/Status" 2>&1
else
  warn "$VM_NAME NO esta corriendo"
fi

echo
echo -e "${GRN}========== FIN ==========${NC}"
echo "Pegame la salida completa en el chat."
```

#### Task 15: `scripts/fix-wazuh-waha.sh` (rename + contenido completo)

**Path:** `~/Desktop/wazuh-waha/scripts/fix-wazuh-waha.sh`

**Contenido completo:**

```bash
#!/bin/bash
# Arregla el relay wazuh-waha si está zombie (puerto abierto pero no responde HTTP).
# NO hace nada si está respondiendo bien.
#
# Requiere sudo para el restart. Si el sandbox bloquea sudo, correr
# manualmente en una terminal con TTY:
#   sudo systemctl restart wazuh-waha

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }

RELAY_HOST="${RELAY_HOST:-http://127.0.0.1:8765}"

echo "=== Test actual del relay ==="
HTTP_CODE=$(curl -sS -m 3 -o /tmp/wazuh-waha_health.json -w "%{http_code}" "$RELAY_HOST/health" 2>/dev/null)
echo "HTTP code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  ok "relay responde 200 OK, no hay que tocar nada"
  cat /tmp/wazuh-waha_health.json
  echo
  exit 0
fi

warn "relay NO responde 200 (code=$HTTP_CODE). Reiniciando..."
echo
echo "=== Estado antes ==="
systemctl status wazuh-waha --no-pager 2>&1 | head -10
echo
echo "=== Ultimos 30 logs ==="
journalctl -u wazuh-waha -n 30 --no-pager 2>&1
echo
echo "=== Restart ==="
sudo systemctl restart wazuh-waha
sleep 3
echo
echo "=== Estado despues ==="
systemctl status wazuh-waha --no-pager 2>&1 | head -10
echo
echo "=== Re-test ==="
HTTP_CODE=$(curl -sS -m 3 -o /tmp/wazuh-waha_health.json -w "%{http_code}" "$RELAY_HOST/health" 2>/dev/null)
echo "HTTP code: $HTTP_CODE"
cat /tmp/wazuh-waha_health.json
echo
if [ "$HTTP_CODE" = "200" ]; then
  ok "relay RESPONDE OK despues del restart"
else
  fail "sigue sin responder. Logs recientes:"
  journalctl -u wazuh-waha -n 50 --no-pager 2>&1
fi
```

#### Task 16: `scripts/install-wazuh-waha.sh` (rewrite)

**Path:** `~/Desktop/wazuh-waha/scripts/install-wazuh-waha.sh`

**Contenido completo:**

```bash
#!/bin/bash
# install-wazuh-waha.sh - Instala el relay como servicio systemd.
# Ejecutar MANUALMENTE en una terminal con TTY (sandbox bloquea sudo -S).
#
# Asume que el proyecto está en ~/Desktop/wazuh-waha/.
# Si está en otro path, exportar PROJECT_ROOT antes de correr.

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"

echo "=== Verificando precondiciones ==="
if [ ! -d "$PROJECT_ROOT" ]; then
  echo "ERROR: $PROJECT_ROOT no existe. Exportar PROJECT_ROOT o mover el proyecto ahi."
  exit 1
fi

UNIT_SRC="$PROJECT_ROOT/wazuh-waha/systemd/wazuh-waha.service"
if [ ! -f "$UNIT_SRC" ]; then
  echo "ERROR: no encuentro $UNIT_SRC"
  exit 1
fi

echo "=== 1. Instalar unit file ==="
sudo cp "$UNIT_SRC" /etc/systemd/system/wazuh-waha.service
sudo systemctl daemon-reload
echo "OK"

echo "=== 2. Crear directorios de log y state ==="
sudo mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha
sudo chown -R "$USER:$USER" /var/log/wazuh-waha /var/lib/wazuh-waha
echo "OK"

echo "=== 3. Si hay override.conf de deploy/, instalarlo ==="
OVERRIDE_SRC="$PROJECT_ROOT/deploy/arch-host/wazuh-waha.service.override.conf"
if [ -f "$OVERRIDE_SRC" ]; then
  sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
  sudo cp "$OVERRIDE_SRC" /etc/systemd/system/wazuh-waha.service.d/override.conf
  sudo systemctl daemon-reload
  echo "Override instalado."
else
  echo "No hay override.conf en $OVERRIDE_SRC, se usa el unit commiteable tal cual."
fi

echo "=== 4. Habilitar y arrancar ==="
sudo systemctl enable wazuh-waha.service
sudo systemctl restart wazuh-waha.service
echo "OK"

echo "=== 5. Verificar ==="
sleep 2
sudo systemctl status wazuh-waha.service --no-pager
echo "---"
curl -s http://localhost:8765/health
echo ""

echo "=== Listo. Para ver logs: ==="
echo "  journalctl -u wazuh-waha -f"
```

#### Task 17: `scripts/recover-waha.sh` (nuevo, contenido completo)

**Path:** `~/Desktop/wazuh-waha/scripts/recover-waha.sh`

**Contenido completo:**

```bash
#!/bin/bash
# recover-waha.sh - Recupera una sesion WAHA pegada en STARTING/STOPPED.
# Secuencia validada: STOP -> wait -> START -> poll hasta WORKING.
# NO destruye la sesion persistida (no usa docker compose down -v).
#
# Lee WAHA_API_KEY y WAHA_HOST del .env del proyecto.

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"
ENV_FILE="$PROJECT_ROOT/.env"
WAHA_HOST="${WAHA_HOST:-http://localhost:3000}"
SESSION="${WAHA_SESSION:-default}"

if [ -f "$ENV_FILE" ]; then
  set -a; source "$ENV_FILE"; set +a
fi

if [ -z "$WAHA_API_KEY" ]; then
  fail "WAHA_API_KEY no esta en $ENV_FILE"
  exit 1
fi

echo "WAHA_HOST=$WAHA_HOST SESSION=$SESSION key_len=${#WAHA_API_KEY}"

# 1. Stop limpio
echo "=== 1. Stop ==="
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST "$WAHA_HOST/api/sessions/$SESSION/stop" 2>&1
echo

# Espera 5 segundos (secreto del fix: dejar a WAHA matar el Chromium anterior)
sleep 5

# 2. Confirmar STOPPED
echo "=== 2. Check STOPPED ==="
STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
  "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
echo "  status: $STATUS"
if [ "$STATUS" != "STOPPED" ]; then
  warn "estado actual: $STATUS (esperado STOPPED). Esperando 5s mas..."
  sleep 5
  STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
  echo "  status: $STATUS"
fi

# 3. Start
echo "=== 3. Start ==="
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST "$WAHA_HOST/api/sessions/$SESSION/start" 2>&1
echo

# 4. Poll hasta WORKING (max 60s)
echo "=== 4. Poll hasta WORKING (max 60s) ==="
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  sleep 5
  STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
  echo "  intento $i (${i}*5s): $STATUS"
  [ "$STATUS" = "WORKING" ] && break
done

if [ "$STATUS" = "WORKING" ]; then
  ok "Sesion WORKING. Resumen:"
  curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq '{status, presence, me}'
else
  fail "Sesion no llego a WORKING en 60s. Probar:"
  echo "  docker logs wazuh-waha --tail 30"
  echo "  Si persiste: docker compose down -v (BORRA la sesion, hay que re-escanear QR)"
fi
```

---

### Fase 5 — Deploy configs

#### Task 18: `deploy/arch-host/relay.env.example` y `wazuh-waha.service.override.conf`

**Path:** `~/Desktop/wazuh-waha/deploy/arch-host/relay.env.example`

**Contenido completo:**

```ini
# Variables que systemd lee (EnvironmentFile=) para wazuh-waha en este host.
#
# INSTALACION:
#   1. Copiar a /etc/wazuh-waha/relay.env:
#        sudo cp relay.env.example /etc/wazuh-waha/relay.env
#   2. Completar valores (RELAY_API_KEY, WAHA_*, ADMIN_PHONE).
#   3. Permisos: sudo chmod 600 /etc/wazuh-waha/relay.env
#   4. sudo systemctl daemon-reload && sudo systemctl restart wazuh-waha

RELAY_API_KEY=*** # openssl rand -hex 24

RELAY_PORT=8765
RELAY_BIND=0.0.0.0
RELAY_DEDUP_TTL=300
RELAY_LOG_DIR=/var/log/wazuh-waha
RELAY_LIB_DIR=/var/lib/wazuh-waha
RELAY_WORKERS=2
RELAY_LIFESPAN_TIMEOUT=10

ADMIN_PHONE=                    # formato: 5219991234567 (sin +)

WAHA_API_KEY=                   # 48 chars
WAHA_HOST=http://localhost:3000
WAHA_SESSION=default

OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:0.5b
OLLAMA_TIMEOUT=10
OLLAMA_ENABLED=false
```

**Path:** `~/Desktop/wazuh-waha/deploy/arch-host/wazuh-waha.service.override.conf`

**Contenido completo:**

```ini
# Override de los paths absolutos del unit commiteable.
# Aplicar con:
#   sudo cp wazuh-waha.service.override.conf /etc/systemd/system/wazuh-waha.service.d/override.conf
#   sudo systemctl daemon-reload
#
# Reemplazar <REEMPLAZAR_PROYECTO> por el path real (ej /home/tadeo/Desktop/wazuh-waha).

[Service]
EnvironmentFile=/etc/wazuh-waha/relay.env
WorkingDirectory=<REEMPLAZAR_PROYECTO>/wazuh-waha
ExecStart=
ExecStart=<REEMPLAZAR_PROYECTO>/wazuh-waha/.venv/bin/uvicorn wazuh_waha.main:app --host 0.0.0.0 --port 8765 --workers 2
```

#### Task 19: `deploy/vm-manager-side/README.md`

**Path:** `~/Desktop/wazuh-waha/deploy/vm-manager-side/README.md`

**Contenido completo:**

```markdown
# Wazuh Manager VM - Deploy

Qué archivos del proyecto `manager-side/` subir a la VM Wazuh y dónde van.

## Tabla de mapping

| Archivo en el repo | Destino en la VM | Permisos | Comando |
|---|---|---|---|
| `manager-side/custom/whatsapp_alert.py` | `/var/ossec/integrations/custom/whatsapp_alert.py` | `0750 root:wazuh` | `sudo mv` + `sudo chown` |
| `manager-side/rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | `0640 root:wazuh` | `sudo mv` + `sudo chown` |
| `manager-side/ossec.conf.snippet.xml` | (NO subir, copiar el bloque) | n/a | pegar en `ossec.conf` |

## Pasos

Ver `docs/deployment.md` §2.

## Snippets específicos de este host

Por ejemplo, si esta VM tiene un path distinto para `ossec.conf` o reglas
custom propias, van en subcarpetas de `vm-manager-side/`:

- `vm-manager-side/extra-rules.xml` — reglas que no van en el repo principal.
- `vm-manager-side/ossec.conf.patches.md` — diffs manuales aplicados a esta VM.
```

---

### Fase 6 — Paquete Python `wazuh_waha/` (contenido completo, refactor multi-worker)

#### Task 20: Reescribir todos los archivos del paquete Python

**Files (todos en `~/Desktop/wazuh-waha/wazuh-waha/wazuh_waha/`):**

- `__init__.py` — versión
- `config.py` — agregar `relay_workers`, `ollama_enabled`, paths configurables
- `dedup.py` — **refactor con `fcntl.flock`** para multi-worker
- `formatter.py` — sin cambios funcionales, usa `dedup` actualizado
- `templates.py` — sin cambios (mismas plantillas)
- `waha_client.py` — sin cambios (stateless, OK para multi-worker)
- `ollama_client.py` — sin cambios
- `main.py` — agregar endpoint `/debug/workers`, `lifespan` en vez de `on_event`

**Contenido completo de cada archivo:**

##### `wazuh-waha/wazuh_waha/__init__.py`

```python
"""wazuh-waha: puente entre Wazuh manager y WAHA (WhatsApp HTTP API)."""
__version__ = "0.3.0"
```

##### `wazuh-waha/wazuh_waha/config.py`

```python
"""
Configuracion: lee el .env del proyecto.
Pydantic Settings valida tipos y reporta errores en el arranque.
"""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    # --- Relay ---
    relay_port: int = 8765
    relay_bind: str = "0.0.0.0"
    relay_api_key: str = "changeme"
    relay_dedup_ttl: int = 300
    relay_log_dir: str = "/var/log/wazuh-waha"
    relay_lib_dir: str = "/var/lib/wazuh-waha"
    relay_workers: int = 2
    relay_lifespan_timeout: int = 10

    # --- WhatsApp destino ---
    admin_phone: str = ""  # formato: 5219991234567 (sin +)

    # --- Ollama (IA local) ---
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:0.5b"
    ollama_timeout: int = 10
    ollama_enabled: bool = False

    # --- WAHA (WhatsApp HTTP API) ---
    waha_api_key: str = "changeme"
    waha_host: str = "http://localhost:3000"
    waha_session: str = "default"

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def admin_chat_id(self) -> str:
        return f"{self.admin_phone}@c.us"

    @property
    def dedup_state_file(self) -> Path:
        return Path(self.relay_lib_dir) / "dedup_state.json"


settings = Settings()
```

##### `wazuh-waha/wazuh_waha/dedup.py` (REFACTOR multi-worker)

```python
"""
Deduplicacion: si la misma (rule_id, agent_id) llega dentro de la ventana TTL,
se descarta. Persiste en disco para sobrevivir restarts Y para coordinar entre
workers uvicorn.

MULTI-WORKER SAFETY:
  uvicorn --workers N fork-ea N procesos, cada uno con su propia memoria.
  Para que el dedup funcione con varios workers, usamos fcntl.flock
  (file lock advisory del kernel) alrededor de read-modify-write del JSON.
  Solo un worker a la vez puede escribir; los demas esperan con LOCK_SH
  para leer la version actualizada.
"""
import fcntl
import json
import time
from contextlib import contextmanager
from pathlib import Path

from .config import settings


class Deduper:
    def __init__(self, ttl: int, state_file: Path | None = None):
        self.ttl = ttl
        self._state_file = state_file or settings.dedup_state_file
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked_state(self, mode: str = "r"):
        """
        Context manager: abre el JSON con un file lock.
        - mode='r': LOCK_SH (compartido, varios readers OK).
        - mode='w': LOCK_EX (exclusivo, un writer a la vez).
        """
        path = self._state_file
        flags = fcntl.O_RDONLY if mode == "r" else (fcntl.O_RDWR | fcntl.O_CREAT)
        fd = open(path, "rb" if mode == "r" else "rb+", closefd=True)
        # Si el archivo no existe y estamos en 'w', OpenFileCreated lo hace.
        # Para el path 'r', no se crea.
        try:
            if mode == "r":
                fcntl.flock(fd.fileno(), fcntl.LOCK_SH)
            else:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            yield fd
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            fd.close()

    def _read_state(self) -> dict:
        if not self._state_file.exists():
            return {}
        try:
            with self._locked_state("r") as f:
                return json.loads(f.read().decode("utf-8") or "{}")
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write_state(self, new_state: dict) -> None:
        # LOCK_EX exclusivo: solo un writer a la vez.
        with self._locked_state("w") as f:
            f.seek(0)
            f.truncate()
            f.write(json.dumps(new_state).encode("utf-8"))
            f.flush()

    def _cleanup(self, state: dict) -> dict:
        now = time.time()
        return {k: ts for k, ts in state.items() if now - ts <= self.ttl}

    def is_duplicate(self, rule_id: str, agent_id: str) -> bool:
        state = self._cleanup(self._read_state())
        key = f"{rule_id}:{agent_id}"
        return key in state

    def mark(self, rule_id: str, agent_id: str) -> None:
        # Read-modify-write bajo LOCK_EX para serializar entre workers.
        with self._locked_state("w") as f:
            try:
                state = json.loads(f.read().decode("utf-8") or "{}")
            except (json.JSONDecodeError, ValueError):
                state = {}
            state = self._cleanup(state)
            state[f"{rule_id}:{agent_id}"] = time.time()
            f.seek(0)
            f.truncate()
            f.write(json.dumps(state).encode("utf-8"))
            f.flush()


# Singleton (uno por proceso, no por worker, lo cual es lo que queremos).
deduper = Deduper(
    ttl=settings.relay_dedup_ttl,
    state_file=settings.dedup_state_file,
)
```

##### `wazuh-waha/wazuh_waha/formatter.py` (sin cambios funcionales)

```python
"""
Orquesta el flujo: dedup -> template -> default.
Ollama/IA queda DESACTIVADO por ahora (ver ollama_client.py y docs/ollama.md).
Devuelve (mensaje_final, metadata).
"""
import time

from . import templates
from .dedup import deduper


async def format_alert(alert: dict) -> tuple[str, dict]:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    level = int(rule.get("level", 0))

    meta = {
        "rule_id": rule_id,
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "level": level,
        "ts": time.time(),
    }

    # 1) Dedupe
    if deduper.is_duplicate(rule_id, agent_id):
        meta["decision"] = "duplicate"
        return ("", meta)
    deduper.mark(rule_id, agent_id)

    # 2) Plantilla especifica por rule_id (rapido, sin IA)
    msg = templates.render(rule_id, alert)
    if msg:
        meta["decision"] = "template"
        return (msg, meta)

    # 3) Plantilla generica (sin IA, sin red)
    meta["decision"] = "default"
    return (templates.render_default(alert), meta)
```

##### `wazuh-waha/wazuh_waha/templates.py` (sin cambios)

(Copiar el contenido del archivo actual tal cual, no se renombra ni se modifica. Los rule_ids siguen siendo los mismos.)

##### `wazuh-waha/wazuh_waha/waha_client.py` (sin cambios)

(Copiar el contenido del archivo actual tal cual.)

##### `wazuh-waha/wazuh_waha/ollama_client.py` (sin cambios)

(Copiar el contenido del archivo actual tal cual.)

##### `wazuh-waha/wazuh_waha/main.py` (REFACTOR: lifespan + /debug/workers)

```python
"""
wazuh-waha: servicio HTTP que recibe alertas de Wazuh y las manda a WhatsApp via WAHA.
Con logging detallado de cada alerta en cada paso del pipeline.
"""
import json
import logging
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from . import waha_client
from .config import settings
from .formatter import format_alert

# Worker ID para distinguir logs entre workers uvicorn.
WORKER_ID = os.getpid()

# --- Logging estructurado a journal (JSON) + archivo human-readable ---
log = logging.getLogger("wazuh-waha")
log.setLevel(logging.INFO)

JSON_FMT = (
    '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
    '"worker":' + str(WORKER_ID) + ',"msg":"%(message)s"}'
)
HUMAN_FMT = f"%(asctime)s [%(levelname)-7s] wazuh-waha[%(process)d] :: %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Handler JSON al journal (lo recoje systemd)
_jh = logging.StreamHandler()
_jh.setFormatter(logging.Formatter(JSON_FMT))
log.addHandler(_jh)

# Handler human-readable a archivo por-worker (un log por proceso uvicorn).
try:
    log_dir = Path(settings.relay_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(
        log_dir / f"wazuh-waha-{WORKER_ID}.log",
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    _fh.setFormatter(logging.Formatter(HUMAN_FMT, DATE_FMT))
    log.addHandler(_fh)
    log.info("file_logger_init path=%s", log_dir / f"wazuh-waha-{WORKER_ID}.log")
except Exception as e:
    log.warning("file_logger_init_failed err=%s continuando_solo_journal", e)


# --- Buffer en memoria de las ultimas alertas (para /debug/recent) ---
# NOTA multi-worker: cada worker tiene su propio buffer. /debug/recent
# devuelve solo el del worker que recibio la request. Para tener una
# vista global, journalctl es la fuente.
_RECENT_CAP = 50
_recent: deque[dict] = deque(maxlen=_RECENT_CAP)

# Metadata del worker (para /debug/workers)
_worker_started_at = time.time()


def _record_recent(entry: dict) -> None:
    """Guarda la entrada en el buffer circular para /debug/recent."""
    _recent.append(entry)


# --- Auth ---
async def verify_api_key(request: Request) -> None:
    key = request.headers.get("X-Api-Key") or request.headers.get("x-api-key")
    if not key or key != settings.relay_api_key:
        log.warning(
            "auth_fail path=%s ip=%s",
            request.url.path,
            request.client.host if request.client else "?",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


# --- Lifespan (reemplaza on_event deprecation) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "relay_started worker_id=%s port=%s chat=%s ollama=%s waha=%s session=%s log_dir=%s",
        WORKER_ID,
        settings.relay_port,
        settings.admin_chat_id,
        settings.ollama_host,
        settings.waha_host,
        settings.waha_session,
        settings.relay_log_dir,
    )
    yield
    log.info("relay_stopping worker_id=%s", WORKER_ID)


# --- App ---
app = FastAPI(
    title="wazuh-waha",
    description="Bridge Wazuh manager -> WAHA (WhatsApp)",
    version="0.3.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "wazuh-waha",
        "version": app.version,
        "worker_id": WORKER_ID,
    }


@app.get("/debug/recent")
async def debug_recent():
    """Devuelve las ultimas N alertas recibidas y su resultado. Sin auth (solo para debug)."""
    return {
        "count": len(_recent),
        "max": _RECENT_CAP,
        "worker_id": WORKER_ID,
        "alerts": list(_recent),
    }


@app.get("/debug/workers")
async def debug_workers():
    """Devuelve info del worker que respondio. Para tener la lista de TODOS
    los workers, hay que hacer N requests (uno por worker) o leer journalctl."""
    return {
        "worker_id": WORKER_ID,
        "pid": WORKER_ID,
        "started_at": _worker_started_at,
        "uptime_sec": time.time() - _worker_started_at,
    }


@app.post("/alerts")
async def receive_alert(request: Request, _: None = Depends(verify_api_key)):
    """Recibe alerta del manager Wazuh. Body esperado: dict con la alerta parseada."""
    t_start = time.time()

    # 1) Body
    try:
        body_bytes = await request.body()
        alert = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        log.warning(
            "invalid_json err=%s remote=%s worker=%s",
            e, request.client.host if request.client else "?", WORKER_ID,
        )
        raise HTTPException(status_code=400, detail="invalid json")

    if not isinstance(alert, dict):
        log.warning("invalid_payload type=%s", type(alert).__name__)
        raise HTTPException(status_code=400, detail="expected object")

    # 2) Extraer campos clave para logging
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    agent_name = agent.get("name", "?")
    level = int(rule.get("level", 0))
    description = rule.get("description", "?")
    ts_alert = alert.get("timestamp", "?")

    log.info(
        "alert_received rule_id=%s level=%d agent_id=%s agent=%s desc=%r body_bytes=%d worker=%s",
        rule_id, level, agent_id, agent_name, description, len(body_bytes), WORKER_ID,
    )

    record = {
        "ts": time.time(),
        "rule_id": rule_id,
        "level": level,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "description": description,
        "alert_timestamp": ts_alert,
        "worker_id": WORKER_ID,
    }

    # 3) Formatear (dedup + template + default)
    try:
        message, meta = await format_alert(alert)
    except Exception as e:
        log.exception("format_error rule=%s agent=%s err=%s", rule_id, agent_id, e)
        record["decision"] = "format_error"
        record["error"] = str(e)
        _record_recent(record)
        raise HTTPException(status_code=500, detail="format error")

    record["decision"] = meta.get("decision", "?")

    # 4) Dedupe -> no se manda nada
    if not message:
        log.info(
            "alert_deduped rule=%s agent=%s decision=%s dentro_de_TTL=%ss",
            rule_id, agent_id, meta.get("decision"), settings.relay_dedup_ttl,
        )
        record["result"] = "deduped"
        _record_recent(record)
        return JSONResponse(status_code=200, content={"status": "deduped", "meta": meta})

    # 5) Template matched? Logueamos que plantilla uso
    log.info(
        "alert_formatted rule=%s agent=%s decision=%s msg_len=%d",
        rule_id, agent_id, meta.get("decision"), len(message),
    )
    record["msg_len"] = len(message)
    record["msg_preview"] = message[:160]

    # 6) Enviar a WAHA
    try:
        wa_resp = await waha_client.send_text(message)
    except waha_client.WAHAError as e:
        log.exception("waha_send_failed rule=%s agent=%s err=%s", rule_id, agent_id, e)
        record["result"] = "waha_error"
        record["error"] = str(e)
        _record_recent(record)
        raise HTTPException(status_code=502, detail=f"waha error: {e}")

    elapsed_ms = int((time.time() - t_start) * 1000)
    msg_id = wa_resp.get("id", {}).get("id") if isinstance(wa_resp, dict) else None
    log.info(
        "alert_sent rule=%s agent=%s decision=%s waha_id=%s total_ms=%d worker=%s",
        rule_id, agent_id, meta.get("decision"), msg_id, elapsed_ms, WORKER_ID,
    )
    record["result"] = "sent"
    record["waha_id"] = msg_id
    record["total_ms"] = elapsed_ms
    _record_recent(record)

    return {
        "status": "sent",
        "message_id": msg_id,
        "worker_id": WORKER_ID,
        "meta": {**meta, "total_ms": elapsed_ms},
    }
```

#### Task 21: `pyproject.toml` actualizado

**Path:** `~/Desktop/wazuh-waha/wazuh-waha/pyproject.toml`

**Contenido completo:**

```toml
[project]
name = "wazuh-waha"
version = "0.3.0"
description = "Bridge entre Wazuh manager y WAHA (WhatsApp HTTP API). Multi-worker safe."
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.27.0",
    "httpx>=0.27.0",
    "pydantic>=2.6.0",
    "pydantic-settings>=2.2.0",
    "python-json-logger>=2.0.7",
]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]
include = ["wazuh_waha*"]
```

#### Task 22: `systemd/wazuh-waha.service` (nuevo nombre + paths con placeholder)

**Path:** `~/Desktop/wazuh-waha/wazuh-waha/systemd/wazuh-waha.service`

**Contenido completo:**

```ini
[Unit]
Description=wazuh-waha (Wazuh -> WAHA bridge)
Documentation=file:///home/<REEMPLAZAR_USUARIO>/Desktop/wazuh-waha/README.md
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=<REEMPLAZAR_USUARIO>
Group=<REEMPLAZAR_USUARIO>
WorkingDirectory=<REEMPLAZAR_PROYECTO>/wazuh-waha
Environment="PYTHONUNBUFFERED=1"
ExecStart=<REEMPLAZAR_PROYECTO>/wazuh-waha/.venv/bin/uvicorn wazuh_waha.main:app --host 0.0.0.0 --port 8765 --workers 2
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening basico
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/log/wazuh-waha /var/lib/wazuh-waha

[Install]
WantedBy=multi-user.target
```

---

### Fase 7 — Manager (archivos para la VM)

#### Task 23: `manager-side/custom/whatsapp_alert.py` (rewrite, sin API key hardcoded)

**Path:** `~/Desktop/wazuh-waha/manager-side/custom/whatsapp_alert.py`

**Contenido completo:**

```python
#!/usr/bin/env python3
"""
whatsapp_alert.py - Script ejecutado por Wazuh manager cuando una regla matchea.

Estandar Wazuh integrations:
  python3 whatsapp_alert.py /var/ossec/queue/alerts/alerts.json

Configuracion (env vars, seteadas por el bloque <integration> en ossec.conf):
  WAZUH_RELAY_URL      URL del relay (default http://127.0.0.1:8765/alerts)
  WAZUH_RELAY_API_KEY  API key compartida con el relay (obligatoria)
  WAZUH_RELAY_TIMEOUT  Timeout en segundos (default 5)

NO debe fallar: Wazuh no se rompe si esto falla. Solo logueamos a stderr.
"""
import json
import os
import sys
import urllib.error
import urllib.request


RELAY_URL = os.environ.get("WAZUH_RELAY_URL", "http://127.0.0.1:8765/alerts")
RELAY_API_KEY = os.environ.get("WAZUH_RELAY_API_KEY", "")
TIMEOUT = int(os.environ.get("WAZUH_RELAY_TIMEOUT", "5"))


def _read_alert(alert_file):
    with open(alert_file, "r", encoding="utf-8") as fh:
        content = fh.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Fallback: tomar hasta el primer cierre de llave (newline-delimited)
        depth = 0
        end = 0
        for i, ch in enumerate(content):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        return json.loads(content[:end])


def _send(alert):
    if not RELAY_API_KEY:
        print("[whatsapp_alert] WAZUH_RELAY_API_KEY no esta seteada, no mando nada", file=sys.stderr)
        return

    body = json.dumps(alert).encode("utf-8")
    req = urllib.request.Request(
        RELAY_URL,
        data=body,
        headers={"Content-Type": "application/json", "X-Api-Key": RELAY_API_KEY},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        rule_id = alert.get("rule", {}).get("id", "?")
        agent_name = alert.get("agent", {}).get("name", "?")
        msg = "[whatsapp_alert] sent rule={} agent={} status={}".format(
            rule_id, agent_name, resp.status
        )
        print(msg, file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("[whatsapp_alert] uso: whatsapp_alert.py <alert_file_path>", file=sys.stderr)
        return 0

    alert_file = sys.argv[1]
    try:
        data = _read_alert(alert_file)
    except FileNotFoundError:
        print("[whatsapp_alert] alert file no existe: " + alert_file, file=sys.stderr)
        return 0
    except Exception as e:
        print("[whatsapp_alert] error parseando alerta: " + str(e), file=sys.stderr)
        return 0

    alerts = data if isinstance(data, list) else [data]

    for alert in alerts:
        try:
            _send(alert)
        except urllib.error.URLError as e:
            print("[whatsapp_alert] no se pudo contactar relay: " + str(e), file=sys.stderr)
        except Exception as e:
            print("[whatsapp_alert] error enviando: " + str(e), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

#### Task 24: `manager-side/ossec.conf.snippet.xml` (rewrite, sin secretos)

**Path:** `~/Desktop/wazuh-waha/manager-side/ossec.conf.snippet.xml`

**Contenido completo:**

```xml
<!--
  =============================================================================
  Wazuh <integration> block para Wazuh + WhatsApp via wazuh-waha
  =============================================================================
  Pegar este bloque dentro de <ossec_config> en
  /var/ossec/etc/ossec.conf del manager Wazuh.
  Reemplazar los placeholders:
    <REEMPLAZAR_RELAY_HOST>       IP del host donde corre wazuh-waha (ej 172.44.30.9)
    <REEMPLAZAR_RELAY_API_KEY>    Valor de RELAY_API_KEY en /etc/wazuh-waha/relay.env

  Despues: sudo systemctl restart wazuh-manager
  =============================================================================
-->

<integration>
  <name>custom-whatsapp</name>
  <hook_url>http://<REEMPLAZAR_RELAY_HOST>:8765/alerts</hook_url>
  <api_key><REEMPLAZAR_RELAY_API_KEY></api_key>
  <level>10</level>
  <alert_format>json</alert_format>
  <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
</integration>

<!--
  =============================================================================
  Explicacion de campos:
  =============================================================================
  - name:           identificador (lo que veas en logs)
  - hook_url:       URL del relay wazuh-waha.
  - api_key:        se inyecta como env var WAZUH_RELAY_API_KEY al script
                    whatsapp_alert.py. Debe coincidir con RELAY_API_KEY en
                    /etc/wazuh-waha/relay.env del host del relay.
  - level:          nivel minimo de alerta. 10 = critico. Subir a 12 si queres
                    solo lo mas urgente. Bajar a 7 si queres mas verbosidad.
  - alert_format:   "json" = la alerta se pasa al script como JSON estructurado
                    (recomendado). "plain" = texto plano (no soportado).
  - options:        argumentos extra que Wazuh pasa al script.
                    --script = path al script (obligatorio si no esta en el PATH
                    del manager)
                    --timeout = segundos antes de matar el script
  =============================================================================
  Si queres que SOLO ciertas reglas disparen (no por level), reemplaza el
  bloque <level> por <rule_id>:
  =============================================================================

  <integration>
    <name>custom-whatsapp-targeted</name>
    <hook_url>http://<REEMPLAZAR_RELAY_HOST>:8765/alerts</hook_url>
    <api_key><REEMPLAZAR_RELAY_API_KEY></api_key>
    <rule_id>5710,5712,5715,550,553,554,520,2902,2903</rule_id>
    <alert_format>json</alert_format>
    <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
  </integration>
-->
```

#### Task 25: `manager-side/rules/local_rules.xml` (sin cambios, mover de lugar)

(Copiar el contenido del archivo actual tal cual. No se renombra ni se modifica.)

#### Task 26: `manager-side/README.md` (rewrite)

**Path:** `~/Desktop/wazuh-waha/manager-side/README.md`

**Contenido completo:**

```markdown
# Manager Wazuh - Archivos para la VM

Estos son los archivos que tenés que llevar a la **VM del manager Wazuh**.

## Tabla de mapping

| Archivo en el repo | Destino en la VM | Permisos |
|---|---|---|
| `manager-side/custom/whatsapp_alert.py` | `/var/ossec/integrations/custom/whatsapp_alert.py` | `0750 root:wazuh` |
| `manager-side/rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | `0640 root:wazuh` |
| `manager-side/ossec.conf.snippet.xml` | pegar bloque `<integration>` en `/var/ossec/etc/ossec.conf` | n/a |

## Pasos de instalación

Ver [`docs/deployment.md` §2](../docs/deployment.md#2-instalar-en-la-vm-del-manager).

## Test desde la línea de comandos (sin esperar alerta real)

En la VM, con las env vars seteadas (o modificando el script para usar el
path directo):

```bash
# Crear un JSON de prueba
cat > /tmp/test_wazuh_alert.json <<'JSON'
{
  "timestamp": "2026-06-16 11:35:00",
  "rule": {"level": 10, "description": "SSH authentication failure", "id": "5710"},
  "agent": {"id": "003", "name": "test-agent"},
  "data": {"srcip": "203.0.113.45", "dstuser": "root"}
}
JSON

# Setear env vars y correr
WAZUH_RELAY_URL="http://172.44.30.9:8765/alerts" \
WAZUH_RELAY_API_KEY="$(cat /etc/wazuh-waha/relay.env | grep ^RELAY_API_KEY= | cut -d= -f2)" \
sudo -u wazuh /var/ossec/integrations/custom/whatsapp_alert.py /tmp/test_wazuh_alert.json
```

Debe loguear a stderr: `[whatsapp_alert] sent rule=5710 agent=test-agent status=200`.

## Generar alerta REAL de prueba

Desde el agente (host Arch):

```bash
# SSH fallido (regla 5710)
sshpass -p wrongpass ssh root@localhost 2>&1 || true

# O FIM (regla 550)
touch /tmp/test_fim
```

Esperá ~5 segundos. Debería llegarte un WhatsApp.

## Verificar que llegó

- Tu WhatsApp (número configurado en `ADMIN_PHONE`).
- `sudo tail -f /var/ossec/logs/integrations.log` en la VM.
- `journalctl -u wazuh-waha -f` en el host del relay.
- `docker logs wazuh-waha -f` para ver el POST a WAHA.
```

---

### Fase 8 — Documentación raíz

#### Task 27: `README.md` raíz (rewrite completo)

**Path:** `~/Desktop/wazuh-waha/README.md`

**Contenido completo:**

```markdown
# wazuh-waha

Pipeline para mandar **alertas de Wazuh** a **WhatsApp** vía **WAHA** (WhatsApp HTTP API).

```
Wazuh manager (172.44.30.11)
  └── regla matchea (level >= 10)
       └── <integration> ejecuta whatsapp_alert.py
            └── POST http://<relay-host>:8765/alerts
                 ├── dedup con fcntl.flock (multi-worker safe)
                 ├── template por rule_id
                 └── POST http://localhost:3000/api/sendText (WAHA)
                      └── WhatsApp del admin
```

## Estado actual (junio 2026)

- ✅ WAHA Docker (`:3000`), sesión WhatsApp activa.
- ✅ Relay `wazuh-waha` con FastAPI + dedup multi-worker + templates.
- ✅ Manager Wazuh configurado con `<integration>` y reglas custom.
- ✅ Pipeline end-to-end validado (alerta real → WhatsApp recibido).

## Quickstart (5 pasos para alguien nuevo)

1. Clonar: `git clone <repo-url> wazuh-waha && cd wazuh-waha`
2. Copiar `.env.example` a `.env` y completar (`openssl rand -hex 24` para API keys).
3. Instalar el relay: `bash scripts/install-wazuh-waha.sh` (necesita TTY con sudo).
4. Instalar en la VM del manager: ver [`docs/deployment.md` §2](docs/deployment.md).
5. Test: `bash scripts/diagnose.sh` para ver el estado de toda la stack.

## Comandos frecuentes

```bash
# Estado de WAHA
docker ps --filter "name=wazuh-waha"
curl -H "X-Api-Key: $(grep ^WAHA_API_KEY= .env | cut -d= -f2)" http://localhost:3000/api/sessions/default

# Estado del relay
systemctl status wazuh-waha
curl http://localhost:8765/health
curl http://localhost:8765/debug/recent
curl http://localhost:8765/debug/workers

# Ver logs del relay
journalctl -u wazuh-waha -f

# Reiniciar el relay si está zombie
bash scripts/fix-wazuh-waha.sh

# Recuperar sesión WAHA pegada
bash scripts/recover-waha.sh

# Diagnóstico read-only de toda la stack
bash scripts/diagnose.sh
```

## Estructura del proyecto

```
wazuh-waha/
├── README.md                # este archivo
├── ARCHITECTURE.md          # decisiones técnicas, diagrama
├── CHANGELOG.md             # historial de cambios
├── PLAN.md                  # plan de mejora y reorganización
├── .env.example             # plantilla de variables
├── docker-compose.yml       # WAHA
├── docs/                    # documentación larga
├── scripts/                 # bash ejecutables
├── wazuh-waha/              # servicio Python (el relay)
├── manager-side/                 # archivos para la VM Wazuh
└── deploy/                  # config específica por host
```

## Documentación

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — decisiones técnicas, por qué se hizo así.
- [`docs/deployment.md`](docs/deployment.md) — instalación paso a paso.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — issues frecuentes.
- [`docs/multi-worker.md`](docs/multi-worker.md) — consideraciones con `--workers N`.
- [`docs/ollama.md`](docs/ollama.md) — estado de la integración con IA local.
- [`docs/rules-coverage.md`](docs/rules-coverage.md) — qué rule_ids tienen template.
- [`docs/migration-from-wazuh-integration.md`](docs/migration-from-wazuh-integration.md) — si venís del proyecto viejo.
- [`CHANGELOG.md`](CHANGELOG.md) — historial de versiones.

## Changelog

Ver [`CHANGELOG.md`](CHANGELOG.md).
```

#### Task 28: `ARCHITECTURE.md` (contenido completo)

**Path:** `~/Desktop/wazuh-waha/ARCHITECTURE.md`

**Contenido completo:**

```markdown
# Architecture

Documento de decisiones técnicas del proyecto `wazuh-waha`. El "por qué" detrás
del código.

## Diagrama del pipeline

```
┌────────────────────┐
│  Wazuh Manager     │
│  (VM 172.44.30.11) │
│                    │
│  regla matchea     │
│  level >= 10       │
└─────────┬──────────┘
          │ ejecuta /var/ossec/integrations/custom/whatsapp_alert.py
          ▼
┌────────────────────────────────────────────────────────────┐
│  whatsapp_alert.py                                        │
│  - Lee /var/ossec/queue/alerts/alerts.json                 │
│  - POST al relay con X-Api-Key                            │
│  - Timeout: 5s (configurable con WAZUH_RELAY_TIMEOUT)     │
└─────────┬──────────────────────────────────────────────────┘
          │ POST /alerts + X-Api-Key
          ▼
┌────────────────────────────────────────────────────────────┐
│  wazuh-waha (FastAPI + uvicorn --workers 2)                │
│  Host: 172.44.30.9:8765                                    │
│                                                            │
│  1) verify_api_key  (compara X-Api-Key con RELAY_API_KEY)  │
│  2) format_alert:                                          │
│     a) dedup: fcntl.flock + JSON en /var/lib/wazuh-waha/   │
│     b) templates.render(rule_id)  -> str o None            │
│     c) templates.render_default(alert) -> str              │
│  3) waha_client.send_text(message)                         │
│     - httpx async POST a WAHA                              │
│     - logging de cada paso + counter de fallos             │
└─────────┬──────────────────────────────────────────────────┘
          │ POST /api/sendText + X-Api-Key
          ▼
┌────────────────────┐
│  WAHA (Docker)     │
│  :3000             │
│                    │
│  WEBJS engine      │
│  session: default  │
└─────────┬──────────┘
          │ WhatsApp protocol
          ▼
┌────────────────────┐
│  WhatsApp          │
│  +52 1 9214380943  │
└────────────────────┘
```

## Las 3 piezas independientes

1. **WAHA** (Docker) — gateway de WhatsApp. Solo habla HTTP, stateless, reemplaza con cualquier otro cliente de WhatsApp.
2. **wazuh-waha** (Python) — cerebro del pipeline. Stateless salvo dedup y buffer `_recent`. Reemplazable por otra implementación.
3. **Wazuh manager + `<integration>`** — productor de eventos. Dispara el script cuando una regla matchea. Wazuh no se rompe si esto falla.

## Decisiones de diseño

### ¿Por qué un relay intermedio y no Wazuh→WAHA directo?

Tres razones:

1. **Timeout del integration.** Wazuh corre scripts con timeout corto (~5s). Si WAHA está lento, Wazuh mata el script. El relay desacopla: el manager hace un POST rápido, el relay se banca la latencia de WAHA.
2. **Dedup y templates centralizados.** Sin relay, el script del manager tendría que implementar dedup, lookup de templates, etc. Con relay, esa lógica vive en un servicio que se puede iterar sin tocar la VM.
3. **Observability.** El relay loguea cada paso (alert_received, alert_formatted, waha_send_start, alert_sent) con `journalctl -u wazuh-waha -f`. Sin relay, solo tendríamos lo que el script de Wazuh imprima a stderr.

### ¿Por qué FastAPI + uvicorn?

- Async nativo (`async def` handlers), httpx para llamadas externas.
- Decoradores para auth (`Depends(verify_api_key)`).
- `lifespan` para startup/shutdown logging.
- uvicorn es liviano y soporta multi-worker out-of-the-box.

### ¿Por qué multi-worker (uvicorn --workers N)?

- Carga CPU-bound (formateo de templates, JSON parsing) se paraleliza.
- Aislamiento: si un worker crashea, los demás siguen atendiendo.
- Configurable con `RELAY_WORKERS=2` en `.env`.

Trade-off: el dedup necesita coordinación entre workers, resuelto con `fcntl.flock` (ver `docs/multi-worker.md`).

### ¿Por qué fcntl.flock para el dedup?

Alternativas evaluadas:

- **Redis**: requiere infra extra, overkill para este caso de uso.
- **SQLite**: más complejo que un JSON con file lock.
- **In-process dict**: no funciona con multi-worker (cada worker tiene su propia memoria).
- **fcntl.flock + JSON**: simple, sin infra extra, suficiente para alertas de seguridad (picos de 5-10/s).

`fcntl.flock` es un file lock advisory del kernel, atómico entre procesos del mismo host. Ver [`docs/multi-worker.md`](docs/multi-worker.md) para detalles.

### ¿Por qué Ollama off por default?

`qwen2.5:0.5b` en CPU tarda **~10s por resumen**, excede el timeout de 5s del integration. Wazuh mata el script y no queda log. Por eso, las alertas sin template caen a `render_default()` (formato genérico), que es 0 latencia.

Activación: ver [`docs/ollama.md`](docs/ollama.md).

### ¿Por qué dedup con TTL y no por hash del mensaje?

El TTL es más simple y robusto:

- Si una alerta se reintenta por un bug en Wazuh o un restart del manager, no spameamos.
- Si el operador quiere ver cada evento individual, baja el TTL a 0 (o edita `dedup_ttl`).
- El hash del mensaje cambia entre runs de la misma regla (timestamps, contadores), así que no funcionaría.

TTL default: 300s (5 min). Configurable con `RELAY_DEDUP_TTL`.

### ¿Por qué `ProtectSystem=full` + `ReadWritePaths=` en el unit?

Defense in depth: el relay solo escribe a `/var/log/wazuh-waha` y `/var/lib/wazuh-waha`. Si un atacante explota un bug en el código, no puede escribir a `/etc/`, `/home/`, etc.

### ¿Por qué `lifespan` en vez de `@app.on_event("startup")`?

`on_event` está deprecated desde FastAPI 0.110. `lifespan` es el reemplazo oficial. Misma funcionalidad, sintaxis más limpia.

## Limitaciones conocidas

- **Sin webhook entrante de WAHA.** El relay solo recibe, no escucha mensajes. Si alguien manda un WhatsApp al admin, no hay forma de procesarlo (no es requerimiento).
- **Un solo destinatario.** Configurado en `ADMIN_PHONE`. Si querés mandar a un grupo, hay que cambiar la lógica de `waha_client.send_text()` para que use `chatId` de tipo grupo (`<id>@g.us`).
- **Sin rate limiting.** Si Wazuh dispara 100 alertas en 1 segundo, el relay intenta mandar 100 WhatsApps. WAHA puede rate-limitar, y el counter de fallos en `waha_client` eventualmente lo va a detectar.
- **TTS sin input.** No hay forma de "responder" al WhatsApp para, por ejemplo, silenciar una regla. YAGNI por ahora.
- **`ollama_client.py` no enchufado.** Implementado pero desactivado. Documentado en `docs/ollama.md`.

## Próximos pasos sugeridos (no en alcance)

1. Tests (pytest). Crítico para que el próximo cambio no rompa silenciosamente.
2. Webhook entrante de WAHA para ack/control remoto.
3. Soporte para múltiples destinatarios (lista en `ADMIN_PHONES`).
4. Migrar `dedup_state.json` a SQLite cuando el lock se vuelva contended.
5. Métricas Prometheus (counter de alertas por rule_id, histogram de latencia).
6. Activar Ollama para `level >= 12` con timeout 3s.
```

#### Task 29: `CHANGELOG.md` (contenido completo)

**Path:** `~/Desktop/wazuh-waha/CHANGELOG.md`

**Contenido completo:**

```markdown
# Changelog

Todos los cambios notables de este proyecto se documentan acá. Formato basado
en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-06-16

### Changed
- **Renombre:** `wazuh-integration/` → `wazuh-waha/`. `wazuh_relay/` → `wazuh_waha/`.
  `wazuh-relay` (systemd, paths) → `wazuh-waha`.
- **Multi-worker:** uvicorn ahora corre con `--workers 2` (configurable con
  `RELAY_WORKERS`). Ver [`docs/multi-worker.md`](docs/multi-worker.md).
- **Dedup multi-worker safe:** `dedup.py` reescrito con `fcntl.flock` para
  coordinar read-modify-write del JSON entre workers.
- **Paths externalizados:** systemd unit, install scripts y override config
  usan placeholders. Los paths reales viven en `deploy/<host>/`.
- **Secretos fuera del código:** `whatsapp_alert.py` lee API key de env vars,
  `ossec.conf.snippet.xml` usa placeholders, `diagnose.sh` lee pass SSH de env.
- **Logging por worker:** cada worker uvicorn escribe a su propio
  `wazuh-waha-<pid>.log` para evitar pisarse.
- **`on_event` → `lifespan`:** migrado al patrón oficial de FastAPI (deprecation).

### Added
- `.env.example` con todas las variables documentadas.
- `docs/deployment.md` con pasos detallados de instalación.
- `docs/troubleshooting.md` con issues frecuentes.
- `docs/rules-coverage.md` con tabla rule_id → template.
- `docs/ollama.md` explicando por qué Ollama está off y cómo activarlo.
- `docs/multi-worker.md` con consideraciones de concurrencia.
- `docs/migration-from-wazuh-integration.md` para upgrades desde el proyecto viejo.
- `deploy/arch-host/` con `relay.env.example` y `wazuh-waha.service.override.conf`.
- `deploy/vm-manager-side/README.md` con mapping de archivos.
- `scripts/recover-waha.sh` para sesiones WAHA pegadas en STARTING.
- `scripts/install-wazuh-waha.sh` actualizado con paths correctos.
- `tests/README.md` con plan de tests (no implementados en este alcance).
- Endpoint `GET /debug/workers` en el relay.
- Propiedad `dedup_state_file` en `Settings` (path configurable).

### Removed
- Secretos hardcodeados: `RELAY_API_KEY=***` en `whatsapp_alert.py`, pass SSH
  `tadeo123` en `diagnose.sh`, IP del manager `172.44.30.9` en
  `ossec.conf.snippet.xml`.

## [0.2.0] - 2026-06-15

### Added
- Reglas custom 57100-57106 para login exitoso (suben level 3→8-12 para
  disparar el integration).
- Templates para las reglas custom en `templates.py`.
- Endpoint `GET /debug/recent` con buffer circular de últimas 50 alertas.
- Counter de fallos en `waha_client` con alerta CRITICAL a 5 fallos en 60s.

## [0.1.0] - 2026-06-11

### Added
- Pipeline end-to-end funcional: Wazuh manager → relay → WAHA → WhatsApp.
- Relay FastAPI con dedup + templates + Ollama (off).
- 14 templates de mensaje para rule_ids frecuentes (520, 550, 553, 554, 2902,
  2903, 5401, 5710, 5712, 5715).
- WAHA Docker Compose con healthcheck y volumen persistente.
- Scripts bash: `diagnose.sh`, `diag-vbox.sh`, `fix-relay.sh`, `install-relay.sh`.
- Validación end-to-end con sesión WAHA WORKING pushName="tadeo".
```

---

## Resumen de cambios

| Categoría | Cantidad |
|---|---|
| Archivos nuevos | 24 (4 readmes de subdir, 6 docs, 5 scripts, 2 deploy files, 1 .env.example, 1 .gitignore, 1 ARCHITECTURE, 1 CHANGELOG, 1 unit, 1 pyproject, 1 main.py nuevo, 1 dedup.py nuevo) |
| Archivos modificados | 4 (whatsapp_alert.py, ossec.conf.snippet.xml, manager-side/README.md, README.md raíz) |
| Archivos movidos/renombrados | 8 (carpetas + scripts) |
| Archivos sin cambios | 3 (templates.py, waha_client.py, ollama_client.py, local_rules.xml) |

**Cero cambios de lógica del pipeline.** Todo lo que andaba sigue andando.

---

## Verificación al final

```bash
# 1. Estructura correcta
ls -1 ~/Desktop/wazuh-waha/
# esperado: ARCHITECTURE.md CHANGELOG.md PLAN.md README.md .env.example .gitignore
#          docker-compose.yml deploy/ docs/ manager-side/ scripts/ wazuh-waha/

# 2. No hay secretos en código
cd ~/Desktop/wazuh-waha
grep -rE '(c5f27e|tadeo123)' --include='*.py' --include='*.sh' --include='*.xml' .
# esperado: 0 matches

# 3. No hay paths al nombre viejo (excepto en docs de migración)
grep -rE '(wazuh-integration|wazuh_relay)' --include='*.py' --include='*.sh' --include='*.xml' .
# esperado: 0 matches (la doc de migración usa "wazuh-integration" en el texto pero no en paths de archivos)

# 4. El relay arranca con multi-worker
sudo systemctl daemon-reload
sudo systemctl restart wazuh-waha
sleep 3
systemctl status wazuh-waha --no-pager
# esperado: active (running) con N PIDs (uno por worker)

curl http://127.0.0.1:8765/health
# esperado: {"status":"ok","service":"wazuh-waha","version":"0.3.0","worker_id":<pid>}

# 5. El dedup multi-worker funciona
# Test: mandar la misma alerta 2 veces en rápida sucesión
# esperado: la 2da vez retorna {"status":"deduped", ...}
```

---

## Lo que NO se hace

- ❌ Tests (acordado)
- ❌ `git init` / commit / push (lo hacés vos después de verificar)
- ❌ Activar Ollama
- ❌ Refactor adicional (e.g. pasar dedup a SQLite, Prometheus metrics)

---

**Tiempo estimado de ejecución:** 60-90 min (más contenido que el plan original porque tiene los archivos completos listos para aplicar).
