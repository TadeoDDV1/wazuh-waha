# Changelog

Todos los cambios notables de este proyecto se documentan acá. Formato basado
en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Rediseño Forense de Reportes PDF (v2.0)**:
  - Generador ReportLab con paleta visual SOC slate (`#0f172a`, `#0284c7`, `#10b981`, `#cbd5e1`) y foliado dinámico institucional (`NumberedCanvas`, paginación "Página X de Y" y encabezado superior automático).
  - **Tarjeta de Resumen Ejecutivo & Postura Global:** Mini-dashboard al inicio del reporte con 4 KPIs (Estado de enlace, Cumplimiento CIS SCA %, Alertas críticas/altas y Sockets/FIM).
  - **Explicación Contextual de los 10 Apartados Forenses:** Cada sección incluye un recuadro explicativo (Callout) con:
    - 🎯 *Objetivo de Auditoría*
    - 🛡️ *Relevancia para la Seguridad*
    - 💡 *Criterio de Análisis*
  - **Dashboard Web (`ReportsCard.tsx`):** Guía interactiva desplegable que detalla los 10 apartados forenses con iconografía y descripciones antes de iniciar la descarga.
  - **Bot de Telegram (`telegram_bot.py`):** Notificación de `/reporte` enriquecida con métricas de postura, conteo de alertas y sockets.

### Changed / Cleaned
- **Depuración Integral del Repositorio:**
  - Limpieza de 17 copias sueltas de `.env.bak.*` en la raíz; copia de seguridad limpia consolidada en `backups/env-latest.bak`.
  - Archivado de planes obsoletos y guía de migración histórica en `docs/archive/` (`PLAN-2026-06-16-refactor.md`, `PLAN-2026-06-16-reconnect.md`, `migration-from-wazuh-integration.md`).
  - Eliminación de directorios vacíos remanentes de actualizaciones previas (`manager-side/test/`).
  - Reemplazo de la plantilla genérica de Vite en `dashboard/README.md` con documentación oficial del panel web.
  - Homologación de rutas relativas y referencias en `README.md`, `docs/README.md`, `docs/deployment.md`, `docs/rules-coverage.md`, `docs/ollama.md`, `docs/troubleshooting.md`, `deploy/README.md`, `deploy/vm-manager/README.md`, `scripts/README.md` y `tests/README.md`.

### Security
- **Hardening completo de la telemetría en vivo y del relay** (auditoría
  completa de `/api/v1/telemetry/*`, `/debug/*`, nginx y frontend):
  - **BFF de sesión: la API key ya no vive en el bundle JS.** Antes
    `VITE_RELAY_API_KEY` se inyectaba en `dist/assets/*.js` (legible con
    `curl` desde cualquier visitante) y habilitaba lectura *y* escritura de
    todo. Ahora el usuario ingresa la key una sola vez en un login
    (`POST /api/v1/auth/login`) y el relay emite una cookie **HttpOnly,
    SameSite=Strict, firmada HMAC-SHA256** (`ww_session`) con TTL de 8h
    (`SESSION_TTL_HOURS`). Firma derivada de `RELAY_API_KEY` → estado sin
    servidor, válida en todos los workers y sobrevive restarts. Opcional:
    `RELAY_READONLY_API_KEY` para sesiones de solo-lectura (scope `read`).
  - **`/debug/*` ya no es anónimo.** `/debug/recent`, `/debug/workers` y
    `/debug/backups` exigen auth (antes filtraban últimas 50 alertas con
    IPs, usuarios y logs crudos a cualquiera). `/health` sigue público pero
    ya no expone `worker_id` (recon).
  - **`?api_key=` eliminado de la autenticación** (se filtraba en access
    logs, historial del browser y proxies). SSE ahora usa la cookie (mismo
    origen). `X-Api-Key` se mantiene para servicios (integración Wazuh,
    `admin.sh`, `conectar.sh`).
  - **RBAC mínimo + auditoría:** las mutaciones (config, agents, módulos,
    simulate…) exigen scope `full` (403 con sesión read-only) y quedan en
    `<relay_lib_dir>/audit.jsonl` (flock, rotación 5 MiB): ts, ip, sid,
    scope, método, path y status. Login fallido también se audita.
  - **Validación de entrada:** `POST /traffic/simulate` con modelo Pydantic
    (level 0–15, description ≤300, rule_id numérico, src_ip ≤45) → 422 en
    vez de 500/eventos inyectables gigantes al journal compartido.
    `?limit=` de `/traffic/tail` acotado a 1–400 y `?lines=` de
    `/dashboard/logs` a 1–500 (`journalctl -n` ya no acepta absurdos).
  - **Límite de tamaño de body** (`MAX_BODY_BYTES`, default 512 KiB) como
    middleware ASGI puro: rechaza también bodies chunked sin
    Content-Length con 413.
  - **SSE acotado también en `/traffic/stream`** (cap 10, antes sin límite
    → DoS trivial con heartbeats de 2s) y race del cap de
    `/telemetry/stream` corregido (check+incremento atómico en el event
    loop).
  - **Frontend: 1 sola conexión SSE por pestaña.** Nuevo `telemetryBus`
    compartido entre Navbar, TelemetryGlobalCard y WazuhModulesControlCard
    (antes eran 3 EventSource por pestaña; ~7 tabs agotaban el cap y
    entraban en bucle de reintento con 503).
  - **Comparación de key constante en tiempo** (`hmac.compare_digest` sobre
    bytes; los valores no-ASCII ya no producen 500).
  - **Rate limit por IP real:** lee `X-Forwarded-For` solo si el peer está
    en `TRUSTED_PROXIES` (si no, se ignora → no se puede falsear la IP);
    buckets por `sid` de sesión verificado (usuarios detrás del proxy de
    nginx ya no comparten bucket); sweep periódico que depura buckets
    huérfanos (memory leak por IPs rotando); bucket dedicado de 5/min para
    `POST /api/v1/auth/login` (fuerza bruta).
  - **`/docs` y `/openapi.json` desactivados por defecto** (`ENABLE_DOCS`);
    el mapa completo de la API ya no es público.
  - **nginx:** headers de seguridad (CSP con `frame-ancestors 'none'`,
    `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`,
    `Permissions-Policy`), `client_max_body_size 512k`, `server_tokens off`
    y access log **sin query strings** (`$request_method $uri` en vez de
    `$request`).
  - **SSH del traffic source:** `StrictHostKeyChecking` configurable
    (`WAZUH_VM_SSH_STRICT_HOST_KEY`); el default sigue `accept-new` pero se
    recomienda `yes` con known_hosts pre-provisionado (evita MITM de
    primera conexión inyectando telemetría falsa). Valor invalidado →
    fallback controlado, sin inyección de opciones.
  - **Minimización de datos en telemetría:** `full_log` recortado a 2 KiB y
    `raw_json` acotado a 8 KiB (antes cada frame SSE y el journal
    transportaban alertas crudas completas de FIM/syscollector).
  - **`scripts/sync_relay_env.sh`:** sincroniza a prod las claves que se
    omitían (`TRAFFIC_*`, `ALLOWED_ORIGINS`, `WAZUH_VM_SSH_*`, y las
    nuevas de seguridad) — antes un hardening en `.env` nunca llegaba a
    `/etc/wazuh-waha/relay.env`.
  - **Nuevo `dashboard/vite.config.ts` con proxy dev** (`/api`, `/debug`,
    `/health` → relay): el browser habla siempre mismo origen en dev y prod
    (requisito de las cookies BFF; sin CORS en dev).
  - **Tests de seguridad:** `tests/test_auth_security.py` (25) +
    `tests/test_telemetry_security.py` (25) — auth en `/debug/*`, flujo
    login/cookie/forja/expiración, `?api_key=` rechazado, RBAC 403, rate
    limit con XFF, caps SSE, body limit (con y sin Content-Length),
    validación de simulate, audit trail y truncado de datos.
  - **Docs:** `ARCHITECTURE.md` (decía "Sin rate limiting"), README,
    `docs/troubleshooting.md` y `docs/multi-worker.md` actualizados con
    auth en `/debug/*`.

### Fixed
- **Relay caído y notificaciones muertas:** `relay/.venv` quedó incompleto
  (instalación parcial con archivos root-owned a las 15:24; `uvicorn`,
  `pydantic` y `pydantic_settings` desaparecidos) → `wazuh-waha.service`
  en crash-loop (153 reinicios, `203/EXEC`) y `boot-notify` fallando con
  `ModuleNotFoundError`. Venv recreado desde `uv.lock` (`sudo rm -rf .venv`
  + `uv sync`); servicio activo y `/health` 200.
- **Test de correo del dashboard:** eliminado el fallback `settings.smtp_to`
  (el campo no existe en `Settings` → `AttributeError` si `ADMIN_EMAIL`
  estuviera vacío). El destino único y canónico es `ADMIN_EMAIL`.
- `scripts/sync_relay_env.sh`: el preview y el conteo de keys usaban el path
  hardcodeado `/tmp/relay.env.new` (mostraba "Total keys: 0" en `apply`);
  ahora usan `$TMP_NEW`.
- **Build del dashboard:** nuevo `dashboard/.dockerignore` (excluye
  `node_modules`, `dist`, `.env` y logs del contexto de build), Dockerfile con
  `npm ci` y build arg `VITE_RELAY_API_KEY`. Antes el bundle de prod se
  construía sin la key → 401 en todos los endpoints del relay.
- `docker-compose.yml` inyecta `VITE_RELAY_API_KEY` desde `RELAY_API_KEY`
  (fuente única de la key).
- `dashboard/.env` local: `VITE_RELAY_API_KEY` desactualizada (daba 401 contra
  el relay en `npm run dev`).
- `dashboard/package-lock.json` ahora se trackea (el `.gitignore` raíz solo
  ignora el lock de la raíz).
- README: troubleshooting del build del dashboard (disco lleno, caché de
  BuildKit corrupta, warning de Bake sin buildx).
- `admin.sh` restaurado como archivo regular: era un symlink a
  `administrador-wazuh-waha.sh`, que se eliminó en la limpieza anterior
  (symlink colgado).
- `admin.sh`: detección automática de contexto Docker (inyecta
  `--context default` si los contenedores viven ahí). Antes los contenedores
  se veían "detenidos" con el contexto activo equivocado.
- `admin.sh`: `instalar_herramientas` y "limpiar paquetes obsoletos"
  multi-distro (pacman / apt-get / dnf). Antes solo existía apt-get (no-op en
  hosts Arch).

### Removed
- **`.env` limpio —6 claves muertas:** `SMTP_TO` y `HYVOR_TO` (el destino de
  todos los correos es siempre `ADMIN_EMAIL`), `WAHA_DASHBOARD_USERNAME/
  PASSWORD` y `WHATSAPP_SWAGGER_USERNAME/PASSWORD` (cero referencias en el
  código: ni compose, ni nginx, ni relay, ni dashboard). Referencias
  eliminadas también en `scripts/sync_relay_env.sh`, 
  `deploy/arch-host/relay.env.example`, `docs/waha-recovery.md` y el visor
  de credenciales de `admin.sh` (50 →44 claves).
- `.hermes/` (planes de trabajo viejos) y `_archive/` (código legacy).
- `administrador-wazuh-waha.sh` (duplicado byte a byte de `admin.sh`).
- `monitor.sh` y `logs.sh` (redundantes con las opciones de `admin.sh`).
- Artefactos locales: `dashboard/dist/`, `dashboard/dashboard.log`,
  `.pytest_cache/`, `__pycache__/` de `manager-side/custom/`.

### Added
- `relay/uv.lock` trackeado (builds del relay reproducibles con `uv sync`).
- `ADMIN_EMAIL` ahora se sincroniza a `/etc/wazuh-waha/relay.env`
  (`sync_relay_env.sh`): antes no estaba en el EnvironmentFile del servicio
  y dependía solo de la lectura directa del `.env` del repo.
- **`admin.sh` ampliado** (nuevo reemplazo del script borrado):
  - Reinicio individual de Wazuh Manager / Indexer / Dashboard (opciones 3-5
    del menú 11): local si la unidad existe, si no en la VM del Manager por
    SSH (clave → `sshpass` con `WAZUH_VM_SSH_PASS` → interactivo con TTY).
  - Opción 6 del menú 11: vista de estado Wazuh local/VM con uptime y disco
    de la VM (una sola conexión SSH por consulta).
  - Reinicio individual de los contenedores WAHA y Dashboard Web
    (opciones 7-8 del menú 11); el menú pasó de 11 a 16 opciones.
  - Estado de servicios con etiquetas `[ACTIVO]` local / `(VM)` /
    `[VM SIN ACCESO]` en lugar de "no encontrado" engañoso.
  - Opción 17 del menú principal: visualización de credenciales de acceso
    a Wazuh (API del Manager y SSH de la VM) con confirmación. Por diseño
    **no** muestra API keys ni secrets del `.env` (relay, SMTP, Hyvor).
  - Respaldo de la sesión WAHA (volumen `wazuh_waha_sessions`) como tipo de
    respaldo en `backups/`.
  - Reinicio maestro actualizado para incluir los servicios Wazuh de la VM
    (modo batch, sin prompts).

## [0.4.0] - 2026-09-22

### Added
- **Terminal de telemetría en vivo (pestaña en el navbar):** consola SSE con
  tail inicial, pausa con cola de eventos, filtros por nivel/búsqueda,
  auto-scroll, Test Event y vista JSON expandible.
- **Fuente de tráfico multi-agente:** el host suele ser *agente*; el manager
  está en la VM. `traffic_source=auto|local|ssh|api|off`:
  - `local` — tail de `alerts.json` si el path existe y es legible;
  - `api` — poll de la API del manager (`:55000`);
  - `ssh` — poll de `alerts.json` en la VM (BatchMode, sin password en repo);
  - journal JSONL compartido `traffic.jsonl` (`fcntl.flock`) para que
    `/telemetry/traffic/tail` y SSE sean consistentes con `--workers 2`.
- Endpoint `GET /api/v1/telemetry/traffic/source` (fuente activa + journal).
- Rate limiting simple por IP en el relay (429): `/alerts` 120/min,
  telemetría 600/min, resto 300/min.
- `ALLOWED_ORIGINS` configurable (dev Vite + nginx `:8001`).

### Fixed
- **API key hardcodeada** eliminada de `nginx.conf` y de los fallbacks del
  frontend (`api.ts`, `telemetryService.ts`). En prod el browser manda
  `?api_key=` (SSE) o `X-Api-Key` (REST) desde `VITE_RELAY_API_KEY`.
- **`_fail_window` multi-worker:** contador de fallos WAHA persistido en
  `fail_state.json` con `flock` (fix documentado en `docs/multi-worker.md`).
- **Password SSH por defecto** eliminada de `tests/test_traffic_detection.py`.
- **CORS** ya no solo `localhost:5173`; ahora incluye `:8001` y es configurable.
- **Watchdog unit:** paths con placeholders `<REEMPLAZAR_PROYECTO>` (no
  hardcodeados a `/home/tadeo/...`).
- **Puerto dashboard** unificado en scripts/docs a **8001** (compose ya usaba
  8001 tras el cambio previo).
- **nginx SSE:** `proxy_buffering off`, HTTP/1.1, `Connection ""` para
  Server-Sent Events sin cortes detrás del reverse proxy.
- **Versión unificada** en `0.4.0` (`__version__`, `pyproject.toml`, CHANGELOG).

### Changed
- `LiveTrafficTerminal` acepta `asPanel` (pestaña principal) y reconecta SSE
  con backoff exponencial + jitter.
- `record_manual_event(..., source=...)` etiqueta el origen (`relay`,
  `simulate`, `local`, `ssh`, `api`) en cada evento de la terminal.

## [0.3.1] - 2026-06-16

### Fixed
- `dedup.py`: `_locked_state` ahora crea el archivo de estado si no existe
  (`path.touch()` antes de `open()`), fixea `FileNotFoundError` en el primer
  arranque o en TTLs nuevos.
- `manager-side/ossec.conf.snippet.xml`: dividido en `.xml` (solo bloque ejecutable)
  + `.md` (variantes documentadas). El segundo `<integration>` adentro del
  comentario HTML rompía el parser XML.
- `manager-side/custom/whatsapp_alert.py`: ahora lee `WAZUH_RELAY_API_KEY` de
  `/var/ossec/etc/wsl-relay.conf` además de env vars. Wazuh 4.x NO inyecta el
  `<api_key>` del bloque `<integration>` como env var automáticamente.
- `manager-side/ossec.conf` (deploy): fusionados dos bloques `<ossec_config>`
  duplicados que tenia el manager, despues se inserto el bloque
  `<integration>` antes del último `</ossec_config>`.

### Verified
- Test 1 (relay + dedup): 2 POSTs identicos → 1 sent, 1 deduped. OK.
- Test 5 (stress 20 alertas distintas): 20 sent, distribucion 10/10 entre
  workers. OK.
- Test 6 (dedup multi-worker con fcntl.flock): 10 POSTs identicos en
  paralelo → 1 sent, 9 deduped. fcntl.flock serializa correctamente. OK.
- Pipeline end-to-end: Wazuh manager → relay wazuh-waha → WAHA → WhatsApp.
  Alerta real `level=10` (rule_id=5710) → WhatsApp recibido.

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
- Secretos hardcodeados: `RELAY_API_KEY=*** en `whatsapp_alert.py`, pass SSH
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
