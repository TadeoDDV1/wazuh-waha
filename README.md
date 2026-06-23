# wazuh-waha

Pipeline para mandar **alertas de Wazuh** a **WhatsApp** vía **WAHA** (WhatsApp HTTP API).

```
Wazuh manager (ver WAZUH_SERVER_IP en .env)
  └── regla matchea (level >= 8)
       └── <integration> ejecuta whatsapp_alert.py
            └── POST http://<relay-host>:8765/alerts
                 ├── dedup con fcntl.flock (multi-worker safe)
                 ├── template por rule_id
                 └── POST http://localhost:3000/api/sendText (WAHA)
                      └── WhatsApp del admin
```

> **Nota:** La IP del manager Wazuh vive en **una sola variable** del `.env`:
> `WAZUH_SERVER_IP`. Cambiarla ahí y todos los scripts + el helper
> `scripts/render_manager_snippet.py` la reflejan automáticamente.

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
curl -H "X-Api-Key: $(grep ^WAHA_API_KEY=*** | cut -d= -f2)" http://localhost:3000/api/sessions/default

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
├── manager/                 # archivos para la VM Wazuh
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
