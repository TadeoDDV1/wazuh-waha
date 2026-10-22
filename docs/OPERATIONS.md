# Operación y mantenimiento

## Servicios

```bash
systemctl status wazuh-waha
systemctl restart wazuh-waha
journalctl -u wazuh-waha -f

systemctl status wazuh-waha-watchdog.timer
systemctl status caddy
docker compose -f /opt/wazuh-waha/deploy/production/docker-compose.prod.yml ps
```

## Logs

- Relay: `journalctl -u wazuh-waha` y `/var/log/wazuh-waha/`.
- Dashboard/WAHA: `docker logs wazuh-waha-dashboard` y `docker logs wazuh-waha`.
- Caddy: `/var/log/caddy/`.
- Auditoría de mutaciones: `/var/lib/wazuh-waha/audit.jsonl`.
- Alertas procesadas: `/var/backups/wazuh-waha/` y `backups/alerts-*.jsonl`.

## Backups

```bash
sudo bash /opt/wazuh-waha/scripts/backup.sh
ls -la /var/backups/wazuh-waha/
```

Cron sugerido (diario 03:00):
```cron
0 3 * * * root /opt/wazuh-waha/scripts/backup.sh >> /var/log/wazuh-waha/backup.log 2>&1
```

Incluye `.env`, `/etc/wazuh-waha`, `agent.conf`, `ossec.conf`, estado,
auditoría, últimos JSONL y el volumen Docker de sesión WAHA.

## Restore

```bash
sudo bash scripts/restore.sh /var/backups/wazuh-waha/<timestamp>
# incluir Wazuh y volumen WAHA:
sudo bash scripts/restore.sh /var/backups/wazuh-waha/<timestamp> --with-wazuh --with-waha-volume
```

## Actualización

```bash
cd /opt/wazuh-waha
sudo git pull --ff-only
sudo bash scripts/deploy-production.sh
```

El deploy hace backup previo, sincroniza env, reconstruye el dashboard,
levanta contenedores, reinicia el relay y valida healthchecks.

## Rollback

```bash
sudo bash scripts/rollback.sh
# o indicar un backup concreto:
sudo bash scripts/rollback.sh /var/backups/wazuh-waha/<timestamp>
```

## Rotación de claves

1. Generar nuevas claves:
   ```bash
   openssl rand -hex 24
   ```
2. Actualizar `.env` (`RELAY_API_KEY`, `WAHA_API_KEY`, etc.).
3. `sudo bash scripts/deploy-production.sh`.
4. Reinstalar integración en el manager si cambió `RELAY_API_KEY`.
5. Cerrar sesiones del dashboard (la cookie se invalida al rotar la key).

## Consola web

- Ver sesiones activas: `journalctl -u wazuh-waha | grep console_session`.
- Auditoría: `/var/lib/wazuh-waha/audit.jsonl`.
- Transcripciones (si `CONSOLE_RECORD_TRANSCRIPT=true`): `/var/log/wazuh-waha/console-*.log`.
- Deshabilitar: `CONSOLE_ENABLED=false` y desplegar.

## Capacidad y rendimiento

- SSE: 20 clientes telemetría, 10 tráfico, 20 red por worker.
- `RELAY_WORKERS=2` por defecto.
- El journal de tráfico rota a 10 MiB; la auditoría a 5 MiB.
- Revisar espacio en `/var`, `/var/log`, `/var/lib/docker` y `/var/backups`.
