# Manager Wazuh - Archivos para la VM

Estos son los archivos que tenés que llevar a la **VM del manager Wazuh**.

## Tabla de mapping

| Archivo en el repo | Destino en la VM | Permisos |
|---|---|---|
| `manager-side/rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | `0640 root:wazuh` |
| `manager-side/wsl-relay.conf.example` | `/var/ossec/etc/wsl-relay.conf` (con valores reales) | `0640 root:wazuh` |
| `manager-side/ossec.conf.snippet.xml` | pegar bloque `<integration>` en `/var/ossec/etc/ossec.conf` | n/a |

> **Nota:** el script `whatsapp_alert.py` de esta carpeta es el integration
> actual (solo hace de puente hacia el relay). La versión monolítica previa al
> relay fue eliminada del repo; está en el historial de git.

## Pasos de instalación

Ver [`docs/deployment.md` §2](../docs/deployment.md#2-instalar-en-la-vm-del-manager).

## Test desde la línea de comandos (sin esperar alerta real)

En la VM, con las env vars seteadas:

```bash
# Crear un JSON de prueba
cat > /tmp/test_wazuh_alert.json <<'JSON'
{
  "timestamp": "2026-06-16 11:35:00",
  "rule": {"level": 10, "description": "SSH authentication failure", "id": "5710"},
  "agent": {"id": "003", "name": "test-agent"},
  "data": {"srcip": "203.0.113.45", "dstuser": "root"}
}
JSON

# Setear env vars y correr
WAZUH_RELAY_URL="http://172.44.30.8:8765/alerts" \
WAZUH_RELAY_API_KEY="$(grep ^RELAY_API_KEY= /etc/wazuh-waha/relay.env | cut -d= -f2)" \
sudo -u wazuh /var/ossec/integrations/custom/whatsapp_alert.py /tmp/test_wazuh_alert.json
```

Debe loguear a stderr: `[whatsapp_alert] sent rule=5710 agent=test-agent status=200`.

## Generar alerta REAL de prueba

Desde el agente (host Arch):

```bash
# SSH fallido (regla 5710)
sshpass -p wrongpass ssh root@localhost 2>&1 || true

# O FIM (regla 550)
touch /tmp/test_fim
```

Esperá ~5 segundos. Debería llegarte un WhatsApp.

## Verificar que llegó

- Tu WhatsApp (número configurado en `ADMIN_PHONE`).
- `sudo tail -f /var/ossec/logs/integrations.log` en la VM.
- `journalctl -u wazuh-waha -f` en el host del relay.
- `docker logs wazuh-waha -f` para ver el POST a WAHA.
