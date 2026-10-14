# Architecture

Documento de decisiones técnicas del proyecto `wazuh-waha`. El "por qué" detrás
del código.

## Diagrama del pipeline

```
┌────────────────────┐
│  Wazuh Manager     │
│  (ver WAZUH_SERVER │
│   _IP en .env)     │
│                    │
│  regla matchea     │
│  level >= 8        │
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
│  Host: 172.44.30.8:8765                                    │
│                                                            │
│  1) verify_api_key  (cookie de sesión BFF del dashboard o       │
│                      X-Api-Key de servicios, comparación        │
│                      constante en tiempo con RELAY_API_KEY)     │
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

### ¿Por qué ReportLab en memoria y NumberedCanvas para los reportes PDF?

El endpoint `/api/v1/reports/agent/{agent_id}` y el bot de Telegram generan el PDF de forma dinámica en memoria (`io.BytesIO`) consumiendo el perfil forense completo del agente:
1. **Sin persistencia temporal en disco:** Evita fugas de I/O y acumulación de PDFs temporales en el servidor; el stream se sirve directamente en la respuesta HTTP o en la llamada multipart de Telegram.
2. **Canvas de dos pasos (`NumberedCanvas`):** Permite resolver el total de páginas (`Página X de Y`) y dibujar el encabezado y pie de página institucional sin interferir con el cálculo de flujo de las tablas.
3. **Consistencia multicanal:** El mismo generador alimenta las descargas desde el Dashboard Web y los envíos instantáneos a los chats de Telegram de los analistas de seguridad.

## Hitos de Arquitectura Completados

1. **Suite de Pruebas Automatizadas (pytest):** 9 módulos cubriendo reportes, autenticación BFF, journal de tráfico, backup rotativo, reglas Wazuh y bot de Telegram.
2. **Control Interactivo Vía Telegram:** Soporte para silenciar/reactivar reglas, consultar estado de servicios, disparar escaneos y recibir reportes PDF forenses directamente en chat.
3. **Dashboard Web SOC (React 18 + Vite):** Panel analítico en tiempo real con streaming SSE, visor de eventos y editor de configuración.
4. **Motor de Reportes Forenses PDF:** Informes de auditoría con 10 apartados técnicos explicados y métricas ejecutivas.

