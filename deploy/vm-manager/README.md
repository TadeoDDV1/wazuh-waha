# Wazuh Manager VM - Deploy

Qué archivos del proyecto `manager-side/` subir a la VM Wazuh y dónde van.

## Tabla de mapping

| Archivo en el repo | Destino en la VM | Permisos | Comando |
|---|---|---|---|
| `manager-side/custom/whatsapp_alert.py` | `/var/ossec/integrations/custom/whatsapp_alert.py` | `0750 root:wazuh` | `sudo mv` + `sudo chown` |
| `manager-side/rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | `0640 root:wazuh` | `sudo mv` + `sudo chown` |
| `manager-side/ossec.conf.snippet.xml` | (NO subir, copiar el bloque) | n/a | pegar en `ossec.conf` |

## Pasos

Ver `docs/deployment.md` §2.

## Snippets específicos de este host

Por ejemplo, si esta VM tiene un path distinto para `ossec.conf` o reglas
custom propias, van en subcarpetas de `vm-manager-side/`:

- `vm-manager-side/extra-rules.xml` — reglas que no van en el repo principal.
- `vm-manager-side/ossec.conf.patches.md` — diffs manuales aplicados a esta VM.
