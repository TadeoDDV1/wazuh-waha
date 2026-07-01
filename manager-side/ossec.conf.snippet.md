# Variantes del bloque `<integration>` para Wazuh → wazuh-waha

Este archivo complementa `ossec.conf.snippet.xml`. El `.xml` tiene **solo** el
bloque ejecutable (lo que se pega dentro de `<ossec_config>`); este `.md` tiene
las variantes y la documentación.

## Fuente de verdad de la IP del manager

La IP del manager Wazuh vive en **una sola variable** del `.env` del repo:
`WAZUH_SERVER_IP`. Cambiarla ahí y todos los scripts + el helper de renderizado
la reflejan automáticamente.

## Cómo usar el helper `scripts/render_manager_snippet.py`

**Opción recomendada** (no editable a mano):

```bash
# 1. Asegurarse de que .env tiene WAZUH_SERVER_IP=...
grep ^WAZUH_SERVER_IP .env

# 2a. Modo commiteable: imprime el snippet con API key placeholder
python3 scripts/render_manager_snippet.py

# 2b. Modo deploy: inyecta la API key real del .env local
python3 scripts/render_manager_snippet.py --with-key > /tmp/integration.xml

# 3. Subir a la VM y pegar
scp /tmp/integration.xml tadeou7@$(grep ^WAZUH_SERVER_IP .env | cut -d= -f2):/tmp/
ssh tadeou7@$(grep ^WAZUH_SERVER_IP .env | cut -d= -f2) \
  'sudo python3 scripts/insert-integration-block.py /var/ossec/etc/ossec.conf /tmp/integration.xml'
```

## Cómo usar (manual, sin helper)

1. Abrir `ossec.conf.snippet.xml`.
2. Reemplazar los placeholders:
   - `REEMPLAZAR_RELAY_HOST` → el valor de `WAZUH_SERVER_IP` del `.env` (ej `172.44.30.14`).
   - `REEMPLAZAR_RELAY_API_KEY` → el valor de `RELAY_API_KEY` en
     `/etc/wazuh-waha/relay.env` del host del relay.
3. Pegar el bloque dentro de `<ossec_config>` en
   `/var/ossec/etc/ossec.conf` del manager Wazuh, **justo antes** del
   `</ossec_config>` final.
4. Validar:
   ```bash
   sudo python3 -c "import xml.etree.ElementTree as ET; ET.parse('/var/ossec/etc/ossec.conf'); print('XML_OK')"
   ```
5. Reiniciar:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## Variante A (default — level mínimo)

Manda todas las alertas con `level >= 10`. Es la más verbosa. Pegar esto:

```xml
<integration>
  <name>custom-whatsapp</name>
  <hook_url>http://REEMPLAZAR_RELAY_HOST:8765/alerts</hook_url>
  <api_key>REEMPLAZAR_RELAY_API_KEY</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
  <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
</integration>
```

## Variante B (targeted — solo rule_ids específicos)

Manda solo las reglas listadas. Útil si querés filtrar por tipo de evento.
**No usar junto con la Variante A**, son excluyentes.

```xml
<integration>
  <name>custom-whatsapp-targeted</name>
  <hook_url>http://REEMPLAZAR_RELAY_HOST:8765/alerts</hook_url>
  <api_key>REEMPLAZAR_RELAY_API_KEY</api_key>
  <rule_id>5710,5712,5715,550,553,554,520,2902,2903</rule_id>
  <alert_format>json</alert_format>
  <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
</integration>
```

## Explicación de campos

| Campo | Significado |
|---|---|
| `name` | Identificador libre (aparece en logs del manager). |
| `hook_url` | URL del relay `wazuh-waha`. |
| `api_key` | Se inyecta como env var `WAZUH_RELAY_API_KEY` al script. Debe coincidir con `RELAY_API_KEY` en `/etc/wazuh-waha/relay.env`. |
| `level` | Nivel mínimo de alerta (10 = crítico). |
| `rule_id` | Alternativa a `level`: lista de rule_ids separados por coma. |
| `alert_format` | `json` (recomendado) o `plain`. El script no soporta `plain`. |
| `options` | Args extra: `--script` (path al script) y `--timeout` (segundos antes de matar). |
