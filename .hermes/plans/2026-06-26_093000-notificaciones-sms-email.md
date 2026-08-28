# Plan: notificaciones multi-canal (SMS + Email) en wazuh-waha

## Contexto

Hoy el relay notifica por **dos canales** (ver `wazuh-waha/wazuh_waha/notifier.py`):

1. **Wazuh Manager API** → regla 999001 en el SIEM (principal, vuelve a salir por pipeline).
2. **SMTP email** → ya implementado pero opcional, configurable con `SMTP_*` en `.env`.

Falta el tercer canal: **SMS** para eventos críticos (sesión WAHA caída, recovery fallido, agente offline >N min). El email ya existe pero hay que **endurecerlo** (rate limiting, retry, separar plantillas críticas vs info).

**Por qué no antes:** el feature depende de que el pipeline Wazuh→Relay→WAHA esté verde end-to-end. Validamos primero; después agregamos canales.

---

## Decisiones de diseño

### D1. SMS provider — Twilio vs. Alternativos

| Criterio | Twilio | Vonage (ex-Nexmo) | Plivo | AWS SNS |
|---|---|---|---|---|
| Confiabilidad | ★★★★★ | ★★★★ | ★★★ | ★★★★★ |
| Costo (México ≈ $0.05/SMS) | ~$0.05/SMS | ~$0.04 | ~$0.03 | ~$0.02 |
| Setup | Cuenta + número + API key | Igual | Igual | IAM + SDK |
| SDK Python | `twilio` oficial | `vonage` oficial | `plivo` | `boto3` |
| Free tier | $15 crédito | €2 crédito | $5 | Gratis vía SNS |

**Recomendación:** **Twilio**. Es el más documentado, tiene SDK Python oficial mantenido, y el free tier de $15 cubre ~300 SMS — suficiente para alertas raras. Si Tadeo prefiere algo local mexicano (como `Mensatek` o `Netelip`) lo cambiamos, pero Twilio es el default sensato.

**Alternativa zero-config inicial:** usar la **Wazuh Manager API como remitente** (el manager ya tiene módulo `integrations/sms` opcional, o vía `ossec.conf` con `<integration>` a un script Python local en la VM). Esto evita crear cuenta Twilio ahora. **Trade-off:** requiere SSH a la VM para instalar/configurar, y el SMS sale del server Wazuh (no del relay).

### D2. Arquitectura — ¿dónde corre el cliente SMS?

**Opción A: en el relay (Arch, este host)**
- Pros: un solo servicio que orquesta, tests en local, no SSH a VM.
- Cons: el relay necesita IP pública saliente o ruta hacia el provider SMS.

**Opción B: en el manager Wazuh (VM .14)**
- Pros: Wazuh ya tiene `integrations.d/` para scripts custom.
- Cons: requiere mantener script en la VM, doble código si relay también quiere notificar.

**Recomendación:** **A** (en el relay). Ya tenemos `notifier.py` con la estructura `async def notify_*`. Solo agregar `notify_sms()`.

### D3. Cuándo SMS vs. Email vs. WhatsApp

| Severidad | Canal | Razón |
|---|---|---|
| **Crítica** (WAHA down >5min, agente offline) | SMS + Email + WhatsApp | Triple redundancia. Si WhatsApp cae (porque WAHA cayó), SMS llega. |
| **Alta** (recovery en curso, alert level ≥12) | Email + WhatsApp | Suficiente, no gastamos SMS. |
| **Media/Baja** (level <12, info) | WhatsApp | Default actual. |

**Rate limiting SMS:** máx **1 SMS / 5 min / número** para evitar loop. Mismo cooldown que el `WAHA_RECOVERY_COOLDOWN_SEC` actual.

### D4. Email — endurecer lo existente

El SMTP actual (en `notifier.py:81-144`) hace fire-and-forget sin retry. Mejoras:

- **Retry con backoff** (3 intentos: 1s, 5s, 30s).
- **Cola persistente** si SMTP cae (escribir a `RELAY_LIB_DIR/email_queue/` como JSON, replay en background).
- **Plantillas separadas**: crítica (`SESION_WAHA_CAIDA`), recovery, info.
- **TLS verification** ya está (`SMTP_TLS=true`), bien.

### D5. Configuración `.env` — qué agregar

```bash
# --- SMS (Twilio default) ---
SMS_ENABLED=false
SMS_PROVIDER=twilio          # twilio | vonage | plivo | aws_sns
SMS_ACCOUNT_SID=ACxxxx       # Twilio Account SID
SMS_AUTH_TOKEN=***           # Twilio Auth Token
SMS_FROM=+15551234567        # número Twilio (formato E.164)
SMS_TO=+5219991234567        # tu número (uno o varios separados por coma)
SMS_COOLDOWN_SEC=300         # anti-loop, mismo patrón que WAHA_RECOVERY_COOLDOWN_SEC

# --- Email (ya existe, agregar retry + cola) ---
EMAIL_RETRY_MAX=3
EMAIL_RETRY_BACKOFF=1,5,30   # segundos, comma-separated
EMAIL_QUEUE_DIR=/var/lib/wazuh-waha/email_queue
```

---

## Plan de implementación (orden)

### FASE 0 — Decisiones (este chat)

- ✅ Confirmar provider SMS (Twilio default).
- ✅ Confirmar arquitectura (cliente en relay).
- ✅ Confirmar matriz de severidad.

### FASE 1 — SMS mínimo viable (Twilio)

**Archivos a tocar:**

1. `wazuh-waha/wazuh_waha/config.py` — agregar `Settings` para `SMS_*` (12 líneas).
2. `wazuh-waha/wazuh_waha/notifier.py` — agregar `notify_sms()` (≈40 líneas).
3. `wazuh-waha/pyproject.toml` — agregar `twilio>=9.0` a dependencies.
4. `.env.example` — bloque nuevo `# --- SMS ---` con todas las vars.
5. `tests/test_notifier.py` — nuevo archivo, 6-8 tests unitarios (mockear Twilio).
6. `docs/notifications.md` — doc corta de cómo configurar Twilio + troubleshooting.

**Pasos:**

1. Tadeo crea cuenta Twilio (free tier), obtiene SID + token + número.
2. Tadeo agrega `SMS_*` al `.env` real.
3. Implementar `notify_sms()` async (httpx al API de Twilio, o SDK si pesa más).
4. Implementar cooldown via archivo en `RELAY_LIB_DIR/sms_cooldown.json` (mismo patrón que watchdog).
5. Tests: mockear Twilio, validar payload, validar cooldown.
6. Verificar end-to-end con un SMS de prueba.

### FASE 2 — Email endurecido

1. Refactor `notify_email()` actual → retry con backoff.
2. Cola persistente en `EMAIL_QUEUE_DIR` (JSON por mensaje).
3. Worker background (`asyncio.create_task` en lifespan) que drena la cola cada 60s.
4. Plantillas separadas (`templates/email_critical.j2`, `email_recovery.j2`, `email_info.j2`).
5. Tests de retry + cola (mockear SMTP, simular fallo, verificar replay).

### FASE 3 — Integración con el pipeline

1. En `wazuh-waha/wazuh_waha/handlers.py` (o donde se llama `notifier`), pasar nivel de alerta.
2. Decidir canal según matriz D3 (SMS para ≥15, email para ≥10, WhatsApp para todo).
3. Si SMS falla → fallback a email (log warn, no rompe el flujo).
4. Métricas Prometheus opcionales (contador `notifications_sent_total{channel,status}`).

### FASE 4 — Documentación + tests E2E

1. `docs/notifications.md` con:
   - Setup Twilio paso a paso.
   - Setup SMTP (Gmail con App Password, SendGrid, Mailgun).
   - Matriz de severidad.
   - Troubleshooting (SMS no llega, email en spam, rate limits).
2. Test E2E: trigger alerta crítica → verificar 3 canales.

---

## Estructura de archivos (al terminar)

```
wazuh-waha/
  wazuh_waha/
    config.py          # + Settings.sms_*
    notifier.py        # + notify_sms(), refactor notify_email()
    sms/
      __init__.py
      twilio.py        # cliente Twilio
      cooldown.py      # rate limit por archivo
  tests/
    test_notifier_sms.py
    test_notifier_email.py
  docs/
    notifications.md
  templates/           # opcional, Jinja2 para emails
    email_critical.j2
    email_recovery.j2
    email_info.j2
```

---

## Riesgos + mitigaciones

| Riesgo | Mitigación |
|---|---|
| Twilio caída | Fallback email + WhatsApp (matriz D3). |
| Costos SMS (loop) | Cooldown 5min, máx 1 SMS/incidente. Alertas en `metrics` si rate sube. |
| Credenciales Twilio en `.env` | `.env` ya está gitignored. Mismo patrón que `WAHA_API_KEY`. |
| Email en spam | SPF/DKIM del dominio remitente (out of scope, Tadeo configura en su DNS). |
| Queue persistente crece sin bound | Límite duro de 100 mensajes en cola, descartar oldest si llega. |
| Tests flaky (Twilio API) | Mockear con `httpx.MockTransport`, no llamar API real en CI. |

---

## Out of scope (explícito)

- **Push notifications** (mobile app) — no pedidas.
- **Slack/Discord webhooks** — no pedidas, fácil de agregar después si querés (mismo patrón que SMS).
- **SMS bidireccional** (recibir replies) — no útil para alertas.
- **Voice calls** (Twilio tiene) — overkill.
- **Wazuh Manager native SMS module** — alternativa a Twilio, requiere instalar en VM, no vamos por ahí.

---

## Estimación

| Fase | Tiempo | Bloqueante |
|---|---|---|
| 0 — decisiones | este chat | — |
| 1 — SMS mínimo | 2-3h implementación + 1h tests | credenciales Twilio |
| 2 — Email endurecido | 1-2h | nada |
| 3 — Integración | 1h | Fase 1+2 listas |
| 4 — Docs + E2E | 1h | nada |

Total: **~1 día de trabajo** si Tadeo tiene cuenta Twilio lista. Si no, 2-3 días (incluye setup cuenta + verificación número).
