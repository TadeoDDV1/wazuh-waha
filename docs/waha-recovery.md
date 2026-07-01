# WAHA session recovery

Como el proyecto detecta, recupera y notifica cuando la sesion WAHA
se cae (status = STOPPED, FAILED, etc.).

## Tres capas de defensa

```
                    ┌──────────────────────────────────────────┐
                    │  1. Auto-recovery en el relay (en vivo)  │
                    │     waha_client.py detecta 422 STOPPED  │
                    │     y dispara _auto_recover_session()   │
                    │     fire-and-forget, con cooldown 5min  │
                    └──────────────────┬───────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  2. Watchdog externo (systemd timer)     │
                    │     wazuh-waha-watchdog.timer            │
                    │     corre cada 5 min, chequea sesion,    │
                    │     si cayo llama scripts/recover-waha.sh│
                    │     independiente del relay              │
                    └──────────────────┬───────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  3. Notificacion (Wazuh API + email)     │
                    │     Cuando se detecta la caida o el      │
                    │     recovery, se postea una alerta       │
                    │     rule_id 999001 level 10/15 al       │
                    │     manager Wazuh. Vuelve por el         │
                    │     pipeline -> WhatsApp.                │
                    │     Si WAHA sigue caido, queda encolada │
                    │     en el manager y sale apenas vuelva.  │
                    └──────────────────────────────────────────┘
```

## Que pasa cuando WAHA se cae

1. El primer POST del relay recibe `422 STOPPED` de WAHA.
2. `waha_client.py:215` detecta el 422 y dispara `asyncio.create_task(_auto_recover_session())`.
3. `_auto_recover_session()` (en `waha_client.py:104-185`):
   - Llama a `notify_health("WAHA session default STOPPED - auto-recovery triggered", level=15)`
     -> eso manda un POST al manager Wazuh (si esta configurado) y un email (si esta configurado).
   - STOP -> wait 5s -> START
   - Poll cada 5s hasta `WORKING` (max `WAHA_RECOVERY_MAX_WAIT_SEC`)
   - Cuando llega a WORKING: `notify_health("WAHA session default recovered successfully", level=10)`
   - Si no llega: `notify_health("WAHA session default recovery FAILED", level=15)`
4. El POST original que causo el 422 devuelve 502 al manager Wazuh (esa alerta
   Wazuh normal queda registrada como fallida, pero el evento de recovery llega
   por el otro canal).

## Anti-loop

El auto-recovery tiene dos protecciones contra loops infinitos:

1. `_recovery_in_progress` (asyncio lock en proceso): si ya hay un recovery
   corriendo, los nuevos requests no disparan otro.
2. `_recovery_last_attempt` + `WAHA_RECOVERY_COOLDOWN_SEC`: aunque no haya
   recovery en curso, no se intenta de nuevo hasta que pase el cooldown
   (default 5 min). Configurable via `.env`.

El watchdog externo NO tiene estos limites (es independiente) pero solo
corre cada 5 min via systemd timer, asi que tampoco hay tormenta.

## Como lo notifico al manager Wazuh

El notifier (`wazuh_waha/notifier.py`) hace un POST a
`https://${WAZUH_MANAGER_HOST}:55000/alerts` con:

```json
{
  "rule": {"id": "999001", "level": 15, "description": "WAHA session default STOPPED - auto-recovery triggered"},
  "agent": {"id": "000", "name": "wazuh-waha-relay"},
  "data": {"action": "auto_recovery_start", "session": "default"},
  "timestamp": "2026-06-24T10:00:00+0000",
  "groups": ["waha_health", "auto_recovery"]
}
```

El manager lo procesa, matchea la regla custom 999001 (`local_rules.xml`),
y como level=15 >= 8 (umbral del `<integration>`), dispara el WhatsApp.

Si WAHA sigue caido en ese momento, el POST a WAHA devuelve 502, pero la
alerta **queda registrada en el manager**. Apenas WAHA vuelva, el manager
la reencola y sale por WhatsApp.

## Como lo notifico por email

Si `SMTP_HOST` esta configurado en el `.env`, se manda un email en paralelo.
Variables necesarias:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu-cuenta@gmail.com
SMTP_PASS=app-password
SMTP_FROM=wazuh-waha@tu-dominio.com
SMTP_TO=admin@tu-dominio.com,backup@tu-dominio.com
SMTP_TLS=true
```

Si SMTP no esta configurado, el canal email se desactiva silenciosamente
(solo log debug).

## Comandos utiles

### Verificar estado actual

```bash
curl -sS -H "X-Api-Key: $(grep ^WAHA_API_KEY /etc/wazuh-waha/relay.env | cut -d= -f2)" \
  http://localhost:3000/api/sessions/default | jq '{status, presence, me}'
```

### Recovery manual (igual que antes)

```bash
cd ~/Desktop/wazuh-waha
bash scripts/recover-waha.sh
```

### Logs del auto-recovery (en el relay)

```bash
journalctl -u wazuh-waha -f | grep -E "waha_recover|waha_session_stopped|waha_request_failed"
```

### Logs del watchdog

```bash
journalctl -u wazuh-waha-watchdog -n 30 --no-pager
systemctl list-timers wazuh-waha*
```

### Forzar un test del auto-recovery (con sesion WORKING)

```bash
# 1. Parar la sesion
curl -sS -H "X-Api-Key: $(grep ^WAHA_API_KEY /etc/wazuh-waha/relay.env | cut -d= -f2)" \
  -X POST http://localhost:3000/api/sessions/default/stop

# 2. Mandar un POST al relay (deberia disparar auto-recovery)
curl -sS -X POST http://localhost:8765/alerts \
  -H "X-Api-Key: $(grep ^RELAY_API_KEY /etc/wazuh-waha/relay.env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{"rule":{"id":"5710","level":10,"description":"force recovery test"},
       "agent":{"id":"001","name":"vm-test"},
       "data":{"srcip":"1.2.3.4","dstuser":"admin"}}'

# 3. Esperar ~10-15s y ver logs
journalctl -u wazuh-waha -n 30 | grep -E "waha_recover|waha_session_stopped"

# 4. Verificar que volvio a WORKING
curl -sS -H "X-Api-Key: $(grep ^WAHA_API_KEY /etc/wazuh-waha/relay.env | cut -d= -f2)" \
  http://localhost:3000/api/sessions/default | jq .status
```

### Forzar un test del watchdog

```bash
sudo systemctl start wazuh-waha-watchdog.service
journalctl -u wazuh-waha-watchdog -n 20 --no-pager
```

## Variables de entorno relevantes

| Variable | Default | Proposito |
|---|---|---|
| `WAHA_RECOVERY_COOLDOWN_SEC` | 300 | Segundos entre intentos de auto-recovery |
| `WAHA_RECOVERY_MAX_WAIT_SEC` | 60 | Cuanto espera el recovery antes de darse por vencido |
| `WAHA_WATCHDOG_INTERVAL_SEC` | 300 | (referencia, el timer esta hardcodeado a 5 min) |
| `WAZUH_MANAGER_HOST` | (vacio) | IP del manager para notificaciones API |
| `WAZUH_MANAGER_API_PORT` | 55000 | Puerto de la API REST |
| `WAZUH_MANAGER_API_USER` | wazuh | Usuario de la API |
| `WAZUH_MANAGER_API_PASS` | (vacio) | Password de la API |
| `WAZUH_MANAGER_API_VERIFY_TLS` | false | Verificar cert TLS (false = self-signed OK) |
| `SMTP_HOST` | (vacio) | Host SMTP. Vacio = email desactivado |
| `SMTP_PORT` | 587 | Puerto SMTP |
| `SMTP_USER` / `SMTP_PASS` | (vacio) | Credenciales SMTP |
| `SMTP_FROM` | wazuh-waha@localhost | From |
| `SMTP_TO` | (vacio) | Lista separada por coma |
| `SMTP_TLS` | true | STARTTLS |

Todas viven en `/etc/wazuh-waha/relay.env` (producción) o en `.env` (dev local).

## Limitaciones conocidas

- Si WAHA esta caido Y el manager Wazuh no acepta el POST (puerto 55000
  cerrado, pass incorrecta), la notificacion Wazuh tambien falla. En ese
  caso queda el log CRITICAL en el journal del relay + email (si esta
  configurado).
- El email usa `smtplib` sincronico (corriendo en thread executor via
  `asyncio.to_thread`). Si el server SMTP esta caido, espera 10s antes de
  timeout. No bloquea el relay.
- El recovery solo funciona si el container Docker sigue vivo. Si WAHA
  mismo crashea y el restart automatico de Docker falla, el watchdog lo
  detecta pero no puede levantar el container (eso lo hace
  `restart: unless-stopped` de docker-compose.yml).