# Changelog

Todos los cambios notables de este proyecto se documentan acá. Formato basado
en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
