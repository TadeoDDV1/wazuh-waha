# Boot heartbeat (`wazuh-waha-boot-notify`)

Heartbeat de boot del host Arch. Manda **un email + un WhatsApp** con el estado
de todo el stack al iniciar el host, así sabés en el momento si algo arrancó
mal (o si la red cambió mientras estabas fuera).

## Qué hace

1. Espera 90s después del boot (para que Docker, WAHA, el relay y el agente
   estén settled).
2. Sondea cada pieza del stack vía `scripts/boot_stack_status.sh`:
   - 4 servicios systemd (`wazuh-waha`, `wazuh-waha-watchdog`,
     `watch_manager_ip`, `wazuh-agent`)
   - Container `wazuh-waha` (Docker)
   - Sesión WhatsApp (WAHA REST API)
   - Manager Wazuh (TCP 1514 + TCP 55000), incluyendo IPs fallback
   - Ollama local (TCP 11434)
3. **SIEMPRE manda email** (canal primario, no depende de WAHA).
4. **DESPUÉS manda WhatsApp** (canal secundario, solo si WAHA responde).
5. Cachea el `boot_id` en `/var/lib/wazuh-waha/boot_notified` para no
   duplicar si systemd reintenta el unit.

## Orden de notificación (Tadeo lo pidió así el 2026-07-01)

```
email PRIMERO   →   WhatsApp DESPUÉS (si WAHA responde)
   ↓                        ↓
  llega siempre       puede no llegar si WAHA está caído
```

Razón: si WAHA se reinició junto con el host, el email igual sale y confirma
que el sistema "sabe" que algo del stack aún no está OK.

## Instalación

```bash
# Copiar los units a systemd
sudo cp deploy/arch-host/wazuh-waha-boot-notify.{service,timer} \
        /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-waha-boot-notify.timer

# Verificar
systemctl list-timers wazuh-waha-boot-notify.timer
```

## Testing

### Dry run (no envía nada, solo imprime los mensajes)

```bash
sudo DRY_RUN=1 /home/tadeo/Desktop/wazuh-waha/relay/.venv/bin/python \
  /home/tadeo/Desktop/wazuh-waha/scripts/boot-notify.py
```

Vas a ver el subject + body del email y el mensaje de WhatsApp.

### Forzar envío real (sin esperar al próximo boot)

```bash
# CUIDADO: esto manda un WhatsApp y email reales. Usar solo para test.
sudo systemctl start wazuh-waha-boot-notify.service
sudo journalctl -u wazuh-waha-boot-notify -n 50
```

### Test de fallback (WAHA apagado)

```bash
docker stop wazuh-waha
sudo systemctl start wazuh-waha-boot-notify.service
# Email llega, WhatsApp NO llega (log: "boot_notify_whatsapp_skipped")
docker start wazuh-waha
```

### Limpiar cache (para testear de nuevo en el mismo boot)

```bash
sudo rm /var/lib/wazuh-waha/boot_notified
sudo systemctl start wazuh-waha-boot-notify.service
```

## Ejemplo de mensajes

### Email (texto plano)

```
WAHA-WAHA STACK ONLINE
========================================

Host:        greenalgorithm
Local IP:    192.168.0.71
Boot ID:     34808523
Timestamp:   2026-07-01T18:21:19Z
Uptime:      3430s

SERVICES:
  [active      ] wazuh-waha.service
  [active      ] wazuh-waha-watchdog.timer
  [active      ] watch_manager_ip.timer
  [active      ] wazuh-agent.service

DOCKER + WHATSAPP:
  [running     ] container wazuh-waha
  [WORKING     ] WAHA session default

WAZUH MANAGER:
  Expected IP:  192.168.1.82
  TCP 1514:     closed  (agent->manager)
  TCP 55000:    closed  (REST API)
  Fallbacks:
    [closed      ] 172.44.30.14

LOCAL:
  [open        ] Ollama 127.0.0.1:11434

!! NOTA: El manager no responde en la IP esperada.
   Si la red cambio, actualiza WAZUH_SERVER_IP en:
     - /home/tadeo/Desktop/wazuh-waha/.env
     - /etc/wazuh-waha/relay.env (via sync_relay_env.sh apply)
   o espera al watch_manager_ip.timer que lo detecte.
```

### WhatsApp (markdown)

```
✅ *Stack wazuh-waha online*
Host:    greenalgorithm (192.168.0.71)
Boot:    34808523 | Uptime: 57m

*Servicios:*
  relay=active  agent=active  watchdog=active
  watch_ip=active  docker=running  waha=WORKING

*Manager* ❌  192.168.1.82  tcp1514=closed  api=closed
```

## Cómo se integra con el resto

```
network-online.target ─┐
docker.service ────────┼─→ wazuh-waha-boot-notify.timer
wazuh-waha.service ────┘         │
                                  │ 90s despues del boot
                                  ↓
              wazuh-waha-boot-notify.service
                                  │
                                  ↓
                        boot-notify.py
                                  │
                ┌─────────────────┼─────────────────┐
                ↓                                   ↓
        Email (SIEMPRE)                   WhatsApp (si WAHA ok)
                ↓                                   ↓
      notifier.notify_email()           waha_client.send_text()
```

**No toca** los watchdogs periódicos (`wazuh-waha-watchdog.timer` y
`watch_manager_ip.timer`). Es puramente aditivo: solo agrega el heartbeat
al boot.

## Deshabilitar

```bash
sudo systemctl disable --now wazuh-waha-boot-notify.timer
```

Para desinstalar:

```bash
sudo systemctl disable --now wazuh-waha-boot-notify.{service,timer}
sudo rm /etc/systemd/system/wazuh-waha-boot-notify.{service,timer}
sudo systemctl daemon-reload
sudo rm /var/lib/wazuh-waha/boot_notified
```

## Archivos

| Path | Rol |
|---|---|
| `scripts/boot_stack_status.sh` | Sondea cada servicio. Sin side effects. |
| `scripts/boot-notify.py` | Wrapper Python: formatea, envía email+WA. |
| `deploy/arch-host/wazuh-waha-boot-notify.service` | Unit oneshot. |
| `deploy/arch-host/wazuh-waha-boot-notify.timer` | Trigger `OnBootSec=90s`. |
| `/var/lib/wazuh-waha/boot_notified` | Cache de boot_id (idempotencia). |
| `/var/log/journal` | Logs vía `journalctl -u wazuh-waha-boot-notify`. |
