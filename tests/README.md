# Tests

## Cómo correrlos

```bash
relay/.venv/bin/python -m pytest tests/ -q
# (si falta pytest: uv pip install --python relay/.venv/bin/python pytest)
```

Nota: `test_traffic_detection.py` es un script de detección end-to-end que
requiere `WAZUH_SERVER_IP`/`WAZUH_SSH_USER` (no corre en CI).

## Existentes

- `test_traffic_journal.py` — journal JSONL con flock + normalización de
  eventos Wazuh.
- `test_backup.py` / `test_alerts_backup.py` — backups JSONL de alertas.
- `test_traffic_detection.py` — generación de tráfico real + alertas (manual).
- `test_auth_security.py` — **BFF de sesión**: auth en `/debug/*`, flujo
  login→cookie→logout, cookie forjada/tampered/expirada, `?api_key=`
  rechazado, header de servicios OK, RBAC read-only (403), rate limit de
  login (429), X-Forwarded-For con proxies de confianza, sweep de buckets,
  `/docs` apagado.
- `test_telemetry_security.py` — **telemetría en vivo**: validación de
  `/traffic/simulate` (422), clamp de `?limit=`, caps SSE (503), body limit
  413 (Content-Length y chunked), audit trail JSONL, truncado de
  `full_log`/`raw_json`, `StrictHostKeyChecking` del source SSH.

## Planeados

- `test_dedup.py` — Deduper con fcntl.flock (file lock atómico).
- `test_formatter.py` — orquesta dedup → template → default.
- `test_templates.py` — render() de cada rule_id.
- `test_waha_client.py` — mock httpx, cubre success / 4xx / 5xx / timeout.
