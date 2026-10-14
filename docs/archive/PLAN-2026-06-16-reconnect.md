# Plan: reconectar agente + levantar relay nuevo + WAHA WORKING

> **Para Tadeo:** 3 problemas, 1 orden estricto, comandos copy-paste. No hay git todavía — esto es operacional, no es cambio de código.
> **Diagnóstico confirmado (junio 16, ~09:17):** agente en loop "Duplicate agent name: greenalgorithm", relay viejo en crash loop 203/EXEC por paths rotos, sesión WAHA STOPPED.

---

## ⚠️ Lo que SÍ es urgente vs. lo que puede esperar

| Problema | Urgencia | Por qué |
|---|---|---|
| **Agente duplicado** | 🔴 **CRÍTICO** | Sin agente activo, el integration no se puede probar end-to-end. El manager rechaza el handshake. |
| **Relay viejo en crash loop** | 🔴 **CRÍTICO** | Consume CPU y logs. Va a quedar zombie hasta que se limpie. Una vez resuelto, el relay nuevo se puede levantar. |
| **WAHA STOPPED** | 🟠 **MEDIA** | Sin WAHA WORKING, el relay no puede mandar mensajes. Pero el agente se puede reconectar sin WAHA. |
| **El rename viejo en systemd** | 🟡 **BAJA** | No rompe nada, pero ensucia. Hay que limpiar después. |

**Orden de ejecución:** agente → relay viejo (cleanup) → relay nuevo → WAHA → test end-to-end.

---

## 📋 Plan de ejecución (5 fases)

### Fase 1 — Limpiar el relay viejo (CRÍTICO, antes que nada)

El unit `wazuh-relay.service` apunta a `/home/tadeo/Desktop/wazuh-integration/relay/.venv/bin/uvicorn` que ya no existe. Está en crash loop infinito con `203/EXEC` (pitfall #15 del skill). **No se puede ni parar** porque systemd lo reintenta cada 5s.

**Comandos (TTY con sudo):**

```bash
sudo systemctl stop wazuh-relay
sudo systemctl disable wazuh-relay
sudo rm /etc/systemd/system/wazuh-relay.service
sudo rm -rf /etc/systemd/system/wazuh-relay.service.d
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

**Verificación:**
```bash
systemctl status wazuh-relay
# esperado: "Unit wazuh-relay.service could not be found."
systemctl list-units --state=failed wazuh-*
# esperado: lista vacía
ps -eo pid,user,comm | grep uvicorn | grep -v grep
# esperado: 0 líneas (el crash loop se fue)
```

### Fase 2 — Reconectar el agente (CRÍTICO)

**El problema:** el manager tiene 2 agentes registrados con nombre `greenalgorithm` (uno viejo, uno nuevo). El nuevo (el de tu Arch) intenta registrarse y el manager lo rechaza. El fix: borrar el agente duplicado viejo desde el manager, y forzar re-registro desde el Arch.

**Paso 1: listar agentes en el manager (vía SSH)**

Comando (TTY):
```bash
ssh tadeou7@172.44.30.11 'sudo /var/ossec/bin/manage_agents -l'
# esperado: lista de agentes con sus IDs, IPs, nombres
# Buscar todas las entradas con nombre "greenalgorithm"
```

**Paso 2: identificar cuál es cuál**

Vas a ver algo como:
```
Available agents:
   ID: 001, Name: greenalgorithm, IP: 172.44.30.9
   ID: 002, Name: greenalgorithm, IP: 172.44.30.9
   ID: 003, Name: otro-host, IP: 192.168.1.50
```

**No borrar nada todavía.** Necesitamos:
- Cuál es el agente "viejo" (probablemente el ID más bajo, ej. 001).
- Cuál es el que tu Arch está intentando registrar.
- El agent_id de tu Arch (`sudo /var/ossec/bin/wazuh-control info` lo tiene que decir, o lo sacás de `/var/ossec/etc/client.keys`).

**Pegame el output de los siguientes 3 comandos:**

```bash
# A) Manager: lista de agentes
ssh tadeou7@172.44.30.11 'sudo /var/ossec/bin/manage_agents -l'

# B) Arch: client.keys (qué agente cree ser este)
sudo cat /var/ossec/etc/client.keys

# C) Arch: agent_id desde el control
sudo /var/ossec/bin/wazuh-control info | head -5
```

**Con esa info te digo qué borrar exactamente.** Hay 3 escenarios posibles:

| Escenario | Fix |
|---|---|
| Tu Arch tiene client.keys viejo apuntando a un agent_id distinto al que está registrado | Borrar el `client.keys` en Arch y re-enrolar |
| El manager tiene 2 agentes con mismo nombre, uno nunca se conectó | Borrar el huérfano desde el manager con `manage_agents -r <id>` |
| El Arch tiene nombre distinto al que está registrado | Cambiar el `<agent_name>` en `ossec.conf` del Arch y re-enrolar |

**Mientras tanto, la fix más probable (con el escenario más común, "duplicado en manager"):**

```bash
# 1) En el Arch: parar el agente, borrar client.keys
sudo systemctl stop wazuh-agent
sudo rm /var/ossec/etc/client.keys

# 2) En el manager: borrar TODOS los agentes con nombre greenalgorithm
#    (correr este loop SSH; ajustar los IDs según lo que veas en manage_agents -l)
ssh tadeou7@172.44.30.11
sudo /var/ossec/bin/manage_agents -l
# Para cada ID con nombre greenalgorithm:
#   sudo /var/ossec/bin/manage_agents -r <ID>
#   Confirmar con 'Y'
exit

# 3) En el Arch: re-enrolar
sudo /var/ossec/bin/agent-auth \
  -m 172.44.30.11 \
  -p 1515 \
  -A "$(hostname)" \
  -D /var/ossec
# Esperado: "Agent key created. Agent ID: <N>"
# Anotar el ID que devuelve.

# 4) Verificar que arrancó
sudo systemctl start wazuh-agent
sleep 5
sudo tail -30 /var/ossec/logs/ossec.log
# Esperado: "Connected to the server" o similar, NO "Duplicate agent name"
```

**Paso 3: verificar que el manager lo ve**

```bash
ssh tadeou7@172.44.30.11 'sudo /var/ossec/bin/manage_agents -l'
# Esperado: tu agente aparece UNA sola vez con el ID nuevo
ss -tnp | grep :1514 | grep ESTAB
# Esperado: una conexión ESTAB desde 172.44.30.9 (tu Arch)
```

**Dashboard:** `https://172.44.30.11` → ☰ → **Server management** → **Endpoints summary** → tu agente debe aparecer **Active**.

---

### Fase 3 — Levantar el relay `wazuh-waha` nuevo (CRÍTICO)

El relay nuevo no está instalado en systemd. Hay que instalarlo ahora. Los comandos asumen que ya corriste las tareas de la sesión anterior (regenerar venv, etc.) — si no, no va a funcionar.

**Precondición:** `.venv` regenerado con el nombre `wazuh-waha` (no `wazuh_relay`). Verificar:
```bash
ls /home/tadeo/Desktop/wazuh-waha/wazuh-waha/.venv/lib/python*/site-packages/wazuh_waha/ 2>&1
# esperado: archivos del paquete nuevo
```

**Comandos (TTY con sudo):**

```bash
# 1) Copiar el unit nuevo
sudo cp /home/tadeo/Desktop/wazuh-waha/wazuh-waha/systemd/wazuh-waha.service \
        /etc/systemd/system/wazuh-waha.service

# 2) Reemplazar placeholders del unit (en una sola pasada con sed)
sudo sed -i 's|<REEMPLAZAR_USUARIO>|tadeo|g; s|<REEMPLAZAR_PROYECTO>|/home/tadeo/Desktop/wazuh-waha|g' \
    /etc/systemd/system/wazuh-waha.service

# 3) Verificar que el unit quedó bien
cat /etc/systemd/system/wazuh-waha.service | grep -E "User|WorkingDirectory|ExecStart"
# Esperado:
#   User=tadeo
#   Group=tadeo
#   WorkingDirectory=/home/tadeo/Desktop/wazuh-waha/wazuh-waha
#   ExecStart=/home/tadeo/Desktop/wazuh-waha/wazuh-waha/.venv/bin/uvicorn wazuh_waha.main:app --host 0.0.0.0 --port 8765 --workers 2

# 4) Crear dirs de log y state
sudo mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha
sudo chown -R tadeo:tadeo /var/log/wazuh-waha /var/lib/wazuh-waha

# 5) Instalar el override con env vars
sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
sudo cp /home/tadeo/Desktop/wazuh-waha/deploy/arch-host/relay.env.example \
        /etc/wazuh-waha/relay.env
sudo chmod 600 /etc/wazuh-waha/relay.env
# Editar el relay.env con tus valores reales
sudo nano /etc/wazuh-waha/relay.env
# Completar: RELAY_API_KEY, ADMIN_PHONE, WAHA_API_KEY
# El RELAY_API_KEY debe coincidir con el que pusiste en el <api_key> del ossec.conf del manager
# El WAHA_API_KEY debe coincidir con el de tu .env actual

sudo cp /home/tadeo/Desktop/wazuh-waha/deploy/arch-host/wazuh-waha.service.override.conf \
        /etc/systemd/system/wazuh-waha.service.d/override.conf
# Reemplazar el placeholder en el override
sudo sed -i 's|<REEMPLAZAR_PROYECTO>|/home/tadeo/Desktop/wazuh-waha|g' \
    /etc/systemd/system/wazuh-waha.service.d/override.conf

# 6) Recargar y arrancar
sudo systemctl daemon-reload
sudo systemctl enable wazuh-waha
sudo systemctl restart wazuh-waha
sleep 3
```

**Verificación:**

```bash
systemctl status wazuh-waha --no-pager
# Esperado: Active: active (running) con 2-3 líneas de "Main PID"

curl -m 3 http://127.0.0.1:8765/health
# Esperado: {"status":"ok","service":"wazuh-waha","version":"0.3.0","worker_id":<pid>}

ss -tln | grep :8765
# Esperado: 0.0.0.0:8765 o [::]:8765

journalctl -u wazuh-waha -n 20 --no-pager
# Esperado: "relay_started worker_id=..." (uno por worker)
```

**Si falla:**
- `journalctl -u wazuh-waha -n 50` → ver el error.
- Verificar que `/etc/wazuh-waha/relay.env` tiene los valores reales (no placeholders).
- Verificar que `.venv` tiene el paquete `wazuh_waha` instalado: `.venv/bin/python -c "import wazuh_waha; print(wazuh_waha.__version__)"`.

---

### Fase 4 — Levantar la sesión WAHA (MEDIA)

El contenedor está UP pero la sesión está en `STOPPED`. El script `recover-waha.sh` ya está en el repo.

**Comandos (TTY):**

```bash
bash /home/tadeo/Desktop/wazuh-waha/scripts/recover-waha.sh
```

**Lo que va a hacer:**
1. POST a `/api/sessions/default/stop` (por si quedó algo medio abierto).
2. Espera 5s.
3. POST a `/api/sessions/default/start`.
4. Poll cada 5s hasta que `status` sea `WORKING` (típico 30-45s).

**Si después de 60s no llega a WORKING:**
```bash
# Ver logs del contenedor
docker logs wazuh-waha --tail 50 | tail -30
# Buscar errores de Chromium o memoria
```

**Si ves `bad interpreter` o shebang roto** (pitfall #16): el `.venv` quedó con paths viejos. Regenerar con `rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -e .`.

**Verificación final:**
```bash
source ~/Desktop/wazuh-waha/.env
curl -sS -H "X-Api-Key: $WAHA_API_KEY" http://localhost:3000/api/sessions/default | jq '{status, presence, me}'
# Esperado: status="WORKING", presence="online" o "unavailable", me.id poblado
```

---

### Fase 5 — Test end-to-end (CRÍTICO, es el momento de la verdad)

Una vez que el agente está conectado, el relay nuevo responde, y WAHA está WORKING, podemos probar el pipeline completo.

**Test 1: relay solo (sin alertas reales)**

```bash
# Disparar 1 alerta idéntica 2 veces — la 2da debe ser dedupeada
curl -X POST -H "X-Api-Key: $(grep ^RELAY_API_KEY=*** | cut -d= -f2)" \
     -H "Content-Type: application/json" \
     -d '{"rule":{"level":10,"id":"5710","description":"test SSH fail"},"agent":{"id":"999","name":"test-end-to-end"},"data":{"srcip":"1.2.3.4","dstuser":"root"}}' \
     http://127.0.0.1:8765/alerts
# Esperado: {"status":"sent","message_id":"...","worker_id":<pid>,"meta":{...}}

# Repetir inmediatamente (dentro de los 300s de TTL)
curl -X POST -H "X-Api-Key: $(grep ^RELAY_API_KEY=*** | cut -d= -f2)" \
     -H "Content-Type: application/json" \
     -d '{"rule":{"level":10,"id":"5710","description":"test SSH fail"},"agent":{"id":"999","name":"test-end-to-end"},"data":{"srcip":"1.2.3.4","dstuser":"root"}}' \
     http://127.0.0.1:8765/alerts
# Esperado: {"status":"deduped",...}

# Ver el buffer
curl http://127.0.0.1:8765/debug/recent | jq .
# Esperado: 2 entries, una con result="sent" y otra con result="deduped"
```

**Test 2: alerta real del agente (SSH fail)**

```bash
# Dispara regla 5710 (SSH authentication failure)
sshpass -p wrongpass ssh root@localhost 2>&1 || true

# Esperar 5-10 segundos
sleep 10

# Verificar logs en 3 lugares
echo "=== Relay ===" && journalctl -u wazuh-waha -n 10 --no-pager | grep -E "alert_(received|sent|deduped)"

echo "=== WAHA ===" && docker logs wazuh-waha --tail 20 | grep sendText

echo "=== Manager ===" && ssh tadeou7@172.44.30.11 'sudo tail -30 /var/ossec/logs/integrations.log' 2>&1 | tail -20

echo "=== Tu WhatsApp ===" && echo "Debería haber llegado un mensaje SSH fallido."
```

**Test 3: regla custom 57100 (SSH login exitoso, tu propio login)**

```bash
# Tu próximo login por SSH va a disparar la regla 57100
# (siempre que las reglas custom estén instaladas en el manager)

# Verificar después de loguearte:
ssh tadeou7@172.44.30.11 'ls /var/ossec/etc/rules/local_rules.xml 2>&1'
# Si no está, scp:
#   scp ~/Desktop/wazuh-waha/manager-side/rules/local_rules.xml tadeou7@172.44.30.11:/tmp/
#   ssh tadeou7@172.44.30.11 'sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/ && sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml && sudo systemctl restart wazuh-manager'

# Dispara el login
ssh tadeou7@172.44.30.11 'echo ssh login test OK; exit'

# Esperar 5-10 segundos
sleep 10
journalctl -u wazuh-waha -n 5 --no-pager | grep -E "alert_(sent|deduped)"
# Esperado: alert_sent con rule_id=57100 (si el manager tiene la regla custom)
```

**Test 4: regla 550 (FIM) — la más rápida de probar**

```bash
# Crear archivo en /tmp
touch /tmp/wazuh-fim-test-$$

# Esperar 5-10 segundos
sleep 10
journalctl -u wazuh-waha -n 5 --no-pager | grep -E "alert_(sent|deduped) rule=550"
# Esperado: alert_sent con rule_id=550, decision=template

# Limpiar
rm /tmp/wazuh-fim-test-*
```

**Test 5: bombardear el relay con alertas (stress test multi-worker)**

```bash
# Disparar 20 alertas distintas en paralelo (distintos rule_id/agent_id)
for i in $(seq 1 20); do
  curl -sS -X POST -H "X-Api-Key: $(grep ^RELAY_API_KEY=*** | cut -d= -f2)" \
       -H "Content-Type: application/json" \
       -d "{\"rule\":{\"level\":10,\"id\":\"$i\",\"description\":\"stress $i\"},\"agent\":{\"id\":\"$i\",\"name\":\"stress-$i\"}}" \
       http://127.0.0.1:8765/alerts &
done
wait

# Ver distribución por worker
curl http://127.0.0.1:8765/debug/recent | jq '[.alerts[].worker_id] | group_by(.) | map({worker: .[0], count: length})'
# Esperado: 2 workers con ~10 alertas cada uno
```

**Test 6: dedup multi-worker (el test que valida fcntl.flock)**

```bash
# Disparar 10 alertas IDÉNTICAS en paralelo (mismo rule_id+agent_id)
ALERT='{"rule":{"level":10,"id":"9999","description":"dedup stress"},"agent":{"id":"888","name":"dedup-stress"}}'
for i in $(seq 1 10); do
  curl -sS -X POST -H "X-Api-Key: $(grep ^RELAY_API_KEY=*** | cut -d= -f2)" \
       -H "Content-Type: application/json" \
       -d "$ALERT" \
       http://127.0.0.1:8765/alerts &
done
wait

# Verificar que SOLO se mando 1 WhatsApp
curl http://127.0.0.1:8765/debug/recent | jq '.alerts | map(select(.rule_id == "9999")) | length'
# Esperado: 1 (las otras 9 fueron deduped)

# Ver en WAHA
docker logs wazuh-waha --tail 50 | grep "sendText" | grep -c "9999"
# Esperado: 1
```

---

## 🔄 Resumen de comandos en orden

Voy a darte el bloque completo para copiar y pegar de a poco. **Cada bloque es independiente** (no se rompen si los pegás por separado):

### Bloque A: limpiar relay viejo (terminal con sudo)

```bash
sudo systemctl stop wazuh-relay
sudo systemctl disable wazuh-relay
sudo rm /etc/systemd/system/wazuh-relay.service
sudo rm -rf /etc/systemd/system/wazuh-relay.service.d
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

### Bloque B: diagnosticar agente (SSH al manager)

```bash
ssh tadeou7@172.44.30.11 'sudo /var/ossec/bin/manage_agents -l'
```

Pegame el output y te digo qué borrar exactamente.

### Bloque C: arreglar agente (después de que confirmes)

```bash
# En Arch
sudo systemctl stop wazuh-agent
sudo rm /var/ossec/etc/client.keys

# En manager (ajustar IDs según lo que viste en Bloque B)
ssh tadeou7@172.44.30.11
sudo /var/ossec/bin/manage_agents -r 001
# responder Y
sudo /var/ossec/bin/manage_agents -r 002
# responder Y
sudo systemctl restart wazuh-manager
exit

# Volver a Arch
sudo /var/ossec/bin/agent-auth -m 172.44.30.11 -p 1515 -A "$(hostname)" -D /var/ossec
sudo systemctl start wazuh-agent
sleep 5
sudo tail -20 /var/ossec/logs/ossec.log
```

### Bloque D: instalar relay nuevo (después de regenerar .venv)

```bash
sudo cp /home/tadeo/Desktop/wazuh-waha/wazuh-waha/systemd/wazuh-waha.service /etc/systemd/system/wazuh-waha.service
sudo sed -i 's|<REEMPLAZAR_USUARIO>|tadeo|g; s|<REEMPLAZAR_PROYECTO>|/home/tadeo/Desktop/wazuh-waha|g' /etc/systemd/system/wazuh-waha.service

sudo mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha
sudo chown -R tadeo:tadeo /var/log/wazuh-waha /var/lib/wazuh-waha

sudo mkdir -p /etc/wazuh-waha
sudo cp /home/tadeo/Desktop/wazuh-waha/deploy/arch-host/relay.env.example /etc/wazuh-waha/relay.env
sudo chmod 600 /etc/wazuh-waha/relay.env
sudo nano /etc/wazuh-waha/relay.env   # ← completar: RELAY_API_KEY, ADMIN_PHONE, WAHA_API_KEY

sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
sudo cp /home/tadeo/Desktop/wazuh-waha/deploy/arch-host/wazuh-waha.service.override.conf /etc/systemd/system/wazuh-waha.service.d/override.conf
sudo sed -i 's|<REEMPLAZAR_PROYECTO>|/home/tadeo/Desktop/wazuh-waha|g' /etc/systemd/system/wazuh-waha.service.d/override.conf

sudo systemctl daemon-reload
sudo systemctl enable wazuh-waha
sudo systemctl restart wazuh-waha
sleep 3
curl -m 3 http://127.0.0.1:8765/health
```

### Bloque E: levantar WAHA

```bash
bash /home/tadeo/Desktop/wazuh-waha/scripts/recover-waha.sh
```

### Bloque F: tests end-to-end (6 tests)

```bash
# Test 1: relay + dedup
API_KEY=$(grep ^RELAY_API_KEY=*** | cut -d= -f2)
ALERT='{"rule":{"level":10,"id":"5710","description":"test SSH fail"},"agent":{"id":"999","name":"test-end-to-end"},"data":{"srcip":"1.2.3.4","dstuser":"root"}}'
curl -X POST -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" -d "$ALERT" http://127.0.0.1:8765/alerts
curl -X POST -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" -d "$ALERT" http://127.0.0.1:8765/alerts
curl http://127.0.0.1:8765/debug/recent | jq .

# Test 2: alerta real
sshpass -p wrongpass ssh root@localhost 2>&1 || true
sleep 10
journalctl -u wazuh-waha -n 10 --no-pager | grep -E "alert_(sent|deduped)"

# Test 4: FIM
touch /tmp/wazuh-fim-test
sleep 10
journalctl -u wazuh-waha -n 5 --no-pager | grep "rule=550"
rm /tmp/wazuh-fim-test

# Test 5: stress multi-worker
for i in $(seq 1 20); do
  curl -sS -X POST -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" \
       -d "{\"rule\":{\"level\":10,\"id\":\"$i\",\"description\":\"stress\"},\"agent\":{\"id\":\"$i\",\"name\":\"stress-$i\"}}" \
       http://127.0.0.1:8765/alerts &
done
wait
curl http://127.0.0.1:8765/debug/recent | jq '[.alerts[].worker_id] | group_by(.) | map({worker: .[0], count: length})'

# Test 6: dedup multi-worker
ALERT='{"rule":{"level":10,"id":"9999","description":"dedup stress"},"agent":{"id":"888","name":"dedup-stress"}}'
for i in $(seq 1 10); do
  curl -sS -X POST -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" -d "$ALERT" http://127.0.0.1:8765/alerts &
done
wait
curl http://127.0.0.1:8765/debug/recent | jq '.alerts | map(select(.rule_id == "9999")) | length'
docker logs wazuh-waha --tail 100 | grep -c "rule=9999\|dedup-stress"
```

---

## ⏱️ Tiempo estimado

- **Fase 1 (limpiar relay viejo):** 2 min
- **Fase 2 (reconectar agente):** 5-10 min (depende de cuántos agentes duplicados haya)
- **Fase 3 (instalar relay nuevo):** 5 min
- **Fase 4 (levantar WAHA):** 1-2 min
- **Fase 5 (tests):** 5 min

**Total: ~20 min**, asumiendo que no hay sorpresas.

---

## 🚨 Cosas a chequear antes de empezar

- [ ] Confirmaste que `~/Desktop/wazuh-waha/wazuh-waha/.venv` está regenerado con el nombre `wazuh-waha` (no `wazuh_relay`). Si no, hay que regenerarlo.
- [ ] Tu `.env` en `~/Desktop/wazuh-waha/.env` tiene los valores reales (no placeholders).
- [ ] El manager tiene `ossec.conf` con el bloque `<integration>` apuntando a tu relay (el del paso 6 del plan original).
- [ ] El manager tiene `whatsapp_alert.py` instalado en `/var/ossec/integrations/custom/` con permisos correctos.

**Si alguna de esas no está, avisame y lo chequeamos antes de seguir.**
