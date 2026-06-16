# Changelog

Todos los cambios notables de este proyecto se documentan acá. Formato basado
en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.1] - 2026-06-16

### Fixed
- `dedup.py`: `_locked_state` ahora crea el archivo de estado si no existe
  (`path.touch()` antes de `open()`), fixea `FileNotFoundError` en el primer
  arranque o en TTLs nuevos.
- `manager/ossec.conf.snippet.xml`: dividido en `.xml` (solo bloque ejecutable)
  + `.md` (variantes documentadas). El segundo `<integration>` adentro del
  comentario HTML rompía el parser XML.
- `manager/custom/whatsapp_alert.py`: ahora lee `WAZUH_RELAY_API_KEY` de
  `/var/ossec/etc/wsl-relay.conf` además de env vars. Wazuh 4.x NO inyecta el
  `<api_key>` del bloque `<integration>` como env var automáticamente.
- `manager/ossec.conf` (deploy): fusionados dos bloques `<ossec_config>`
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
- `deploy/vm-manager/README.md` con mapping de archivos.
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
