# Migración desde `wazuh-integration/`

El proyecto se renombró de `wazuh-integration/` a `wazuh-waha/`. Esta guía es
para clones viejos o instalaciones previas del relay.

## Checklist de migración

### 1. Mover el código

```bash
# Si el proyecto está en ~/Desktop/wazuh-integration/
mv ~/Desktop/wazuh-integration ~/Desktop/wazuh-waha
```

### 2. Renombrar subdirs internos

```bash
cd ~/Desktop/wazuh-waha
mv relay wazuh-waha
mv wazuh-waha/wazuh_relay wazuh-waha/wazuh_waha
```

### 3. Actualizar el unit de systemd

El unit `/etc/systemd/system/wazuh-relay.service` (viejo nombre) tiene que
desaparecer y ser reemplazado por `wazuh-waha.service`:

```bash
sudo systemctl stop wazuh-relay
sudo systemctl disable wazuh-relay
sudo rm /etc/systemd/system/wazuh-relay.service
sudo rm -rf /etc/systemd/system/wazuh-relay.service.d   # si había override
```

Y reinstalar el nuevo (ver `docs/deployment.md` §1.4).

### 4. Mover logs y state

```bash
sudo mv /var/log/wazuh-relay /var/log/wazuh-waha
sudo mv /var/lib/wazuh-relay /var/lib/wazuh-waha
```

### 5. Actualizar `.env`

Editar `RELAY_LOG_DIR` y `RELAY_LIB_DIR`:

```ini
RELAY_LOG_DIR=/var/log/wazuh-waha
RELAY_LIB_DIR=/var/lib/wazuh-waha
```

Y `RELAY_API_KEY` se mantiene igual (no se regenera).

### 6. Si tenés el servicio corriendo en producción

```bash
sudo systemctl daemon-reload
sudo systemctl reset-failed
sudo systemctl start wazuh-waha
sudo systemctl status wazuh-waha --no-pager
```

### 7. Re-escanear el QR de WAHA (no, esto NO es necesario)

El volumen Docker de WAHA se mantiene igual (`wazuh_waha_sessions`). El
container `wazuh-waha` no cambia. La sesión de WhatsApp persiste.

## Búsqueda de paths viejos

Para encontrar cualquier referencia residual al nombre viejo:

```bash
cd ~/Desktop/wazuh-waha
grep -rE '(wazuh-integration|wazuh_relay|wazuh-relay)' \
  --include='*.py' --include='*.sh' --include='*.xml' \
  --include='*.md' --include='*.toml' --include='*.service' \
  --exclude-dir='.venv' --exclude-dir='*.egg-info' .
```

Si aparece algo que no debería, es un bug. Reemplazar siguiendo el mapping
de Task 1-3.
