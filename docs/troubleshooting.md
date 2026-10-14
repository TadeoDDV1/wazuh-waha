# Troubleshooting

## "El relay escucha en :8765 pero /health da timeout"

Síntoma:
- `systemctl status wazuh-waha` dice `active (running)`
- `ss -tln | grep :8765` muestra puerto abierto
- `curl -m 3 http://127.0.0.1:8765/health` → connection timeout

Causa típica: uvicorn colgó en startup (lock, Ollama unreachable, etc.) o un
worker está pegado en un handler. systemd NO lo reinicia (técnicamente corre).

Fix:
```bash
sudo systemctl restart wazuh-waha
sleep 2
curl -m 3 http://127.0.0.1:8765/health
```

Si persiste, ver `journalctl -u wazuh-waha -n 50`.

Script automatizado: `scripts/fix-wazuh-waha.sh`.

## "WAHA devuelve 201 pero el WhatsApp no llega"

Tres causas en orden de probabilidad:

1. **Número mal formateado** — para México el formato es `52 + 1 + número
   móvil` (12 dígitos). Si falta el `1` después de `52` (11 dígitos) WAHA
   acepta el POST pero el servidor de WhatsApp lo descarta silenciosamente.
   Verificar contra `me.id` de la sesión WAHA:
   ```bash
   curl -H "X-Api-Key: $WAHA_API_KEY" http://localhost:3000/api/sessions/default | jq .me.id
   ```

2. **`presence: "offline"`** en la sesión = el teléfono no está sincronizando
   con el servidor de WhatsApp. La API no falla, el mensaje queda encolado.
   No es bug del pipeline.

3. **Sesión desvinculada por uso anómalo** — WAHA sigue devolviendo 201, pero
   WhatsApp te desvinculó. Verificar `me.id != null`.

## "La sesión WAHA se quedó en STARTING"

Síntoma: `POST /api/sessions/default/start` la pasa a `STARTING` y queda ahí
indefinidamente.

Lo que NO funciona: varios `start` consecutivos, `restart` del container, `docker compose down -v` (esto último borra la sesión, hay que re-escanear QR).

Lo que SÍ funciona (secuencia STOP+wait+START):
```bash
source .env
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST http://localhost:3000/api/sessions/default/stop
sleep 5
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST http://localhost:3000/api/sessions/default/start
# Poll hasta WORKING (30-45s)
```

Script automatizado: `scripts/recover-waha.sh`.

## "401 Unauthorized en el relay"

La API key no coincide entre el manager y el relay. Verificar:
```bash
# En el host del relay
grep RELAY_API_KEY .env
systemctl show wazuh-waha -p EnvironmentFiles
# EnvironmentFile debe apuntar al archivo correcto
```

En el manager, la key vive en el `<api_key>` del bloque `<integration>` de
`ossec.conf`. Si la cambiaste, reiniciar el manager.

## "El manager manda el POST al relay pero el journal del relay está vacío"

Causa típica: el bloque `<integration>` está en `ossec.conf` pero
`whatsapp_alert.py` no está en `/var/ossec/integrations/custom/` o no tiene
los permisos correctos.

Verificar:
```bash
ssh tadeou7@<VM_IP> 'ls -la /var/ossec/integrations/custom/whatsapp_alert.py'
# esperado: -rwxr-x--- 1 root wazuh ... whatsapp_alert.py

ssh tadeou7@<VM_IP> 'sudo grep -A8 custom-whatsapp /var/ossec/etc/ossec.conf'
# esperado: bloque <integration> con tu hook_url
```

## "Multi-worker: el dedup no funciona"

Síntoma: la misma alerta llega 2-3 veces en lugar de 1.

Causa: con `--workers N`, cada worker tiene su propio `Deduper` en memoria.
Si llegan N requests en paralelo, cada worker chequea su propia cache y no
ve las marcas de los otros.

El `Deduper` actual usa `fcntl.flock` para serializar read-modify-write del
JSON. Si no funciona, verificar:

```bash
# ¿El archivo de estado es escribible por el usuario del servicio?
ls -la /var/lib/wazuh-waha/dedup_state.json
sudo -u <usuario> touch /var/lib/wazuh-waha/test
# esperado: 0, no "Permission denied"

# ¿Los workers están viendo el mismo archivo?
# Ver con: curl -H "X-Api-Key: $RELAY_API_KEY" http://127.0.0.1:8765/debug/recent | jq '.alerts[].worker_id'
# Todos los workers deben escribir al mismo path
```

## "Historial: Migración desde el proyecto anterior `wazuh-integration/`"

Ver [`docs/archive/migration-from-wazuh-integration.md`](archive/migration-from-wazuh-integration.md).
