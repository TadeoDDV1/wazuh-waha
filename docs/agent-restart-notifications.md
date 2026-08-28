# Notificaciones de reinicio y errores del agente / relay

Este documento describe las **3 piezas complementarias** que notifican eventos
de meta-infraestructura del agente Wazuh y del relay `wazuh-waha`.

> **Regla de oro (Tadeo, 2026-07-01):** email SIEMPRE primero, WhatsApp DESPUÉS.
> Los meta-eventos (reconexión, fallo de unit) **NO** se postean al Wazuh Manager
> API — son ruido en el SIEM.

## Las 3 piezas

| Pieza | Cuándo dispara | Qué hace | Nivel |
|---|---|---|---|
| `wazuh-agent-failure-notify.service` | systemd `OnFailure=` de `wazuh-agent` | Email + WhatsApp: "wazuh-agent falló" | 12 (High) |
| `wazuh-waha-failure-notify.service` | systemd `OnFailure=` de `wazuh-waha` | Email + WhatsApp: "relay falló" | 15 (Critical) |
| `wazuh-agent-health.{service,timer}` | cada 5 min | Email + WhatsApp si no hay `ESTAB :1514` al manager | 12 (High) |

Estas se complementan con las que ya estaban:

| Pieza (existente) | Cuándo dispara | Qué hace |
|---|---|---|
| `wazuh-waha-boot-notify.{service,timer}` | `OnBootSec=90s` | Email + WhatsApp al iniciar el host (estado de TODO el stack) |
| `wazuh-waha-watchdog.{service,timer}` | cada 5 min | Recupera sesión WAHA si está caída |
| `watch_manager_ip.{service,timer}` | cada 5 min | Detecta drift de IP del manager y avisa |

## Instalación

Después de copiar el código nuevo al repo, correr **una vez**:

```bash
bash scripts/install-wazuh-waha.sh
```

Esto:
1. Instala los drop-ins de `OnFailure=` para `wazuh-agent` y `wazuh-waha`.
2. Instala los services oneshot de notify (`wazuh-agent-failure-notify.service`,
   `wazuh-waha-failure-notify.service`).
3. Habilita el timer `wazuh-agent-health.timer` (cada 5 min).

El script es **idempotente**: corre las veces que quieras.

## Verificación post-instalación

```bash
# Drop-ins aplicados
ls /etc/systemd/system/wazuh-agent.service.d/
ls /etc/systemd/system/wazuh-waha.service.d/

# Services oneshot listos (NO requieren enable)
systemctl list-unit-files wazuh-agent-failure-notify.service wazuh-waha-failure-notify.service

# Timer habilitado
systemctl list-timers wazuh-agent-health.timer

# Smoke test: simular una falla del agente (arranca, falla, OnFailure dispara)
sudo systemctl reset-failed wazuh-agent.service
sudo systemctl restart wazuh-agent.service  # si esta OK, no deberia disparar
# Para forzar OnFailure:
#   sudo systemctl stop wazuh-agent
#   sudo systemctl edit wazuh-agent  # agregar: [Service] ExecStart=/bin/false
#   sudo systemctl reset-failed wazuh-agent
#   sudo systemctl start wazuh-agent  # falla, OnFailure dispara
#   journalctl -u wazuh-agent-failure-notify -f
#   sudo systemctl revert wazuh-agent
```

## Cómo funciona cada una

### 1. `wazuh-agent-failure-notify.service`

systemd corre este service cuando `wazuh-agent` entra en `failed` (después de
agotar `StartLimitBurst` reintentos automáticos). El script:

1. Lee `$SERVICE_UNIT`, `$SERVICE_RESULT`, `$EXIT_CODE` (variables automáticas
   que systemd popula en el unit disparado por `OnFailure=`).
2. Construye un mensaje legible según el tipo de resultado
   (`exit-code`, `signal`, `timeout`, etc.).
3. Llama a `waha-notify.py --action agent_failed --no-manager-api`.

### 2. `wazuh-waha-failure-notify.service`

Idéntico al anterior pero para el relay. Nivel 15 porque **sin relay el pipeline
completo está caído** (Wazuh puede seguir mandando alertas al manager pero no
llegan a WhatsApp).

### 3. `wazuh-agent-health.{service,timer}`

Health-check recurrente que detecta el caso **"el agente corre pero no está
conectado al manager"** — ej. cambió la IP del manager y el `ossec.conf` no se
actualizó. El timer dispara cada 5 min y:

1. Lee `WAZUH_SERVER_IP` del `.env` (o fallback del archivo).
2. `ss -tnp | grep ESTAB | grep ":1514" | grep "$MANAGER_IP"` para verificar.
3. Si NO hay conexión:
   - Respeta un cooldown de 30 min (env `AGENT_ALERT_COOLDOWN_SEC`,
     cache en `/var/lib/wazuh-waha/agent_disconnected_notified`).
   - Llama a `waha-notify.py --action agent_disconnected --no-manager-api`.
4. Si HAY conexión y antes había cache de "disconnected", notifica recovery
   (nivel 6, informativo).

## Variables de entorno relevantes

| Variable | Default | Qué hace |
|---|---|---|
| `AGENT_ALERT_COOLDOWN_SEC` | `1800` (30 min) | Cooldown entre alertas de agente desconectado |
| `WAZUH_SERVER_IP` | (lee de `.env`) | IP del manager para el chequeo `ESTAB` |

Las dos se setean vía `/etc/wazuh-waha/relay.env`, que `sync_relay_env.sh`
regenera desde el `.env` del repo.

## Caveats

1. **`OnFailure=` solo dispara cuando el unit entra en `failed`**, no en cada
   reinicio automático (systemd hace restart transparente sin notificar). Si
   querés notificar **cada** restart, agregá un `ExecStartPost=` que dispare
   `waha-notify.py --action agent_restart --level 6`. No lo hacemos por
   defecto para no spamear durante un crash loop.

2. **`Restart=always` en `wazuh-agent.service` + `StartLimitBurst`**: si el
   agente crashea 5 veces en 60s, systemd desiste y dispara `OnFailure=`.
   Mientras está en el loop NO se notifica (es transparente). Eso es
   intencional — el `wazuh-agent-health.timer` cubre ese caso con su propia
   notificación cada 5 min.

3. **El `waha-notify.py --no-email` parchea `settings.smtp_host = ""` antes
   de la llamada y restaura en `finally`.** Esto evita que un cambio de
   config "de meta-evento" ensucie el `.env` o `relay.env`.

4. **Los drop-ins en `deploy/arch-host/*-service.d-notify.conf`** NO se llaman
   `notify.conf` en el repo para que `install-wazuh-waha.sh` los pueda renombrar
   al instalar y dejar claro que es un archivo separado del `override.conf`
   del operador (no se pisa si el operador customiza algo).

## Tests manuales sugeridos

```bash
# Test 1: forzar que wazuh-agent-failure-notify corra sin crashear el agente
sudo systemctl start wazuh-agent-failure-notify.service
sudo journalctl -u wazuh-agent-failure-notify -f

# Test 2: forzar wazuh-waha-failure-notify
sudo systemctl start wazuh-waha-failure-notify.service
sudo journalctl -u wazuh-waha-failure-notify -f

# Test 3: forzar health-check ahora (sin esperar 5 min)
sudo systemctl start wazuh-agent-health.service
sudo journalctl -u wazuh-agent-health -f

# Test 4: matar el agente y ver que OnFailure= dispara (cuidado, esto
# SI deja al agente caido)
sudo systemctl stop wazuh-agent
sudo systemctl start wazuh-agent  # deberia levantar normal
# Para forzar falla real: ver seccion "Smoke test" arriba.
```