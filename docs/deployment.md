# Deployment

Instalar `wazuh-waha` desde cero en un host Arch (o Linux similar). Asume que
ya tenés WAHA corriendo en Docker y Wazuh manager en una VM aparte.

## 1. Instalar el relay

### 1.1 Clonar el repo

```bash
git clone https://github.com/<owner>/wazuh-waha.git
cd wazuh-waha
```

### 1.2 Crear `.env`

```bash
cp .env.example .env
$EDITOR .env
chmod 600 .env
```

Generar API key:
```bash
openssl rand -hex 24   # pegar en RELAY_API_KEY
```

### 1.3 Crear venv e instalar deps

```bash
cd wazuh-waha
python3.11 -m venv .venv
.venv/bin/pip install -e .
```

(Si el sistema tiene Python < 3.11, instalar `python3.11` desde AUR o usar
el `pyenv` del usuario.)

### 1.4 Instalar como servicio systemd

```bash
sudo cp systemd/wazuh-waha.service /etc/systemd/system/wazuh-waha.service
sudo mkdir -p /etc/wazuh-waha
sudo cp ../deploy/arch-host/relay.env /etc/wazuh-waha/relay.env
sudo chmod 600 /etc/wazuh-waha/relay.env
sudo cp ../deploy/arch-host/wazuh-waha.service.override.conf \
        /etc/systemd/system/wazuh-waha.service.d/override.conf

sudo systemctl daemon-reload
sudo systemctl enable wazuh-waha
sudo systemctl restart wazuh-waha
```

### 1.5 Verificar

```bash
systemctl status wazuh-waha --no-pager
curl -m 3 http://127.0.0.1:8765/health
# esperado: {"status":"ok","service":"wazuh-waha","version":"0.3.0","worker_id":<pid>}
```

## 2. Instalar en la VM del manager

### 2.1 Subir archivos

Desde el host Arch:
```bash
scp manager/custom/whatsapp_alert.py tadeou7@<VM_IP>:/tmp/
scp manager/rules/local_rules.xml tadeou7@<VM_IP>:/tmp/
scp manager/ossec.conf.snippet.xml tadeou7@<VM_IP>:/tmp/
```

### 2.2 Instalar en la VM (ssh + sudo con TTY)

En la VM:
```bash
sudo mv /tmp/whatsapp_alert.py /var/ossec/integrations/custom/
sudo chmod 750 /var/ossec/integrations/custom/whatsapp_alert.py
sudo chown root:wazuh /var/ossec/integrations/custom/whatsapp_alert.py

sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
```

### 2.3 Editar `ossec.conf`

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%s)
sudo nano /var/ossec/etc/ossec.conf
```

Pegar el bloque `<integration>` de `ossec.conf.snippet.xml` justo antes del
`</ossec_config>` final. Reemplazar `<REEMPLAZAR_RELAY_HOST>` por la IP del
host donde corre el relay, y `<REEMPLAZAR_RELAY_API_KEY>` por el valor de
`RELAY_API_KEY` del `.env` del host.

Validar XML:
```bash
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("/var/ossec/etc/ossec.conf"); print("XML_OK")'
```

### 2.4 Reiniciar manager

```bash
sudo systemctl restart wazuh-manager
```

### 2.5 Verificar que el bloque está cargado

```bash
sudo /var/ossec/bin/wazuh-logtest -t   # testea lectura de ossec.conf
sudo tail -f /var/ossec/logs/ossec.log | grep -i integration
```

## 3. Test end-to-end

Desde el agente (tu host Arch):
```bash
# SSH fallido (regla 5710)
sshpass -p wrongpass ssh root@localhost 2>&1 || true

# O un FIM (regla 550)
touch /tmp/test_fim
```

Esperá 5-10 segundos. Debería llegarte un WhatsApp. Si no llega,
ver `docs/troubleshooting.md`.
