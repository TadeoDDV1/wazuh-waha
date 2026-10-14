# Suite de Pruebas Automatizadas — Wazuh-WAHA

Pruebas unitarias, de seguridad, integración y generación de reportes del sistema.

---

## 🚀 Ejecución de Tests

```bash
# Correr toda la suite de pruebas
relay/.venv/bin/python -m pytest tests/ -q

# Correr una prueba específica (ej. reportes)
relay/.venv/bin/python -m pytest tests/test_reports.py -v
```

> **Nota:** `test_traffic_detection.py` es una prueba de integración end-to-end opcional que requiere conectividad activa hacia `WAZUH_SERVER_IP` y no se ejecuta en CI.

---

## 📋 Catálogo de Pruebas Existentes

- `test_reports.py` — Generador de reportes forenses PDF por agente, validación de cabeceras HTTP, `NumberedCanvas`, estructura A4 y autenticación por API key.
- `test_auth_security.py` — Seguridad de sesión BFF, flujo login → cookie → logout, prevención de tampering de cookies, control RBAC y rate limiting.
- `test_telemetry_security.py` — Validación de endpoints de telemetría, límites de payload (413 Body Limit), stream SSE (503 caps) y journal de auditoría.
- `test_traffic_journal.py` — Journal JSONL con bloqueo concurrente (`fcntl.flock`) y normalización de eventos Wazuh.
- `test_backup.py` / `test_alerts_backup.py` — Rotación de archivos de backup y persistencia de alertas en formato JSONL.
- `test_telegram.py` — Comandos administrativos del bot de Telegram, worker en background y entrega de reportes en chat.
- `test_network_sites.py` — Inspección, agrupación y categorización de sockets remotos y destinos web activos.
- `test_wazuh_rules.py` — Verificación de sintaxis XML y mapeo de reglas personalizadas de seguridad (`57100` a `57140`).
- `test_notification_channels.py` — Notificaciones multicanal hacia WAHA (WhatsApp), Telegram y correo SMTP.
