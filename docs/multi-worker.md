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
con `LOCK_SH` para leer la versión actualizada.

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
- **`_fail_window` (en waha_client)**: counter de fallos de WAHA.
  **Implementado (0.4.0):** se persiste en `fail_state.json` con
  `fcntl.flock`, igual que dedup. El umbral CRITICAL (5 en 60s) es
  consistente entre workers.

### Tráfico en vivo / terminal

- Journal compartido `traffic.jsonl` (`fcntl.flock`) bajo `RELAY_LIB_DIR`.
- `/api/v1/telemetry/traffic/tail` lee el journal (consistente entre workers).
- Solo un worker (leader via lock) corre las fuentes externas (local/ssh/api)
  para no duplicar polls; todos los workers hacen broadcast SSE del journal.

## Cómo saber cuántos workers están corriendo

```bash
systemctl status wazuh-waha --no-pager
# PIDs en la lista de procesos hijos de uvicorn

curl -H "X-Api-Key: $RELAY_API_KEY" http://127.0.0.1:8765/debug/workers
# devuelve {"worker_id": 1234, "pid": 1234, "started_at": "...", "uptime_sec": ...}
# (requiere auth: header X-Api-Key de servicios o cookie de sesión del dashboard)

# Para ver la lista de TODOS los workers, hay que hacer N requests
# (uno por worker) o leer journalctl.
```

El endpoint `/debug/workers` se agrega como parte de este refactor.

## Tuning de `RELAY_WORKERS`

Regla de dedo: `workers = 2 * cpu_cores + 1`. Para una VM con 2 cores
típica, `workers=2` es suficiente. Más workers solo ayuda si las alertas
son CPU-bound (lo son: formateo + httpx + JSON parsing); I/O-bound no se
beneficia.
