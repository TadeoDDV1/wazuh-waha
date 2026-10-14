# Rules coverage

Mapeo rule_id → plantilla de mensaje → level mínimo en el `<integration>`.

| rule_id | Descripción | Plantilla | Level mín. | Grupo |
|---|---|---|---|---|
| 520 | Binario SUID | `templates.py:SUID` | 10 | syscheck |
| 550 | Archivo nuevo (FIM) | `templates.py:FIM_created` | 10 | syscheck |
| 553 | Archivo modificado (FIM) | `templates.py:FIM_modified` | 10 | syscheck |
| 554 | Archivo eliminado (FIM) | `templates.py:FIM_deleted` | 10 | syscheck |
| 2901 | Useradd fallido | `default` | 10 | adduser |
| 2902 | Descarga web | `templates.py:web_download` | 10 | web |
| 2903 | Descarga sospechosa | `templates.py:web_download_suspicious` | 10 | web |
| 5401 | Sudo fallido | `templates.py:sudo_failed` | 10 | sudo |
| 5710 | SSH fallido | `templates.py:ssh_failed` | 10 | sshd |
| 5712 | Múltiples SSH fallidos | `templates.py:ssh_bruteforce` | 10 | sshd |
| 5715 | `su` fallido | `templates.py:su_failed` | 10 | authentication |
| 57100 | SSH login exitoso (custom) | `templates.py:ssh_login_success` | 10 | authentication_success |
| 57101 | SSH login con pubkey (custom) | `templates.py:ssh_login_pubkey` | 10 | authentication_success |
| 57102 | SSH login como root (custom) | `templates.py:root_login` | 12 | authentication_success, root_login |
| 57103 | `su` exitoso (custom) | `templates.py:su_success` | 10 | authentication_success |
| 57104 | Sudo exitoso (custom) | `templates.py:sudo_success` | 8 | authentication_success |
| 57105 | Login local TTY (custom) | `templates.py:local_login` | 8 | authentication_success |
| 57106 | Logout (custom) | `templates.py:logout` | 3 | authentication_success |

| 23505 | CVE de severidad HIGH (stock) | `templates.py:vuln_high` | 10 | vulnerability_detector |
| 23506 | CVE de severidad CRITICAL (stock) | `templates.py:vuln_critical` | 12 | vulnerability_detector |
| 57107 | CVE de severidad MEDIUM (custom) | `templates.py:vuln_medium` | 8 | vulnerability_detector |
| 57108 | CVE de severidad LOW (custom) | `templates.py:vuln_low` | 8 | vulnerability_detector |
| 57109 | CVE resuelta (custom) | `templates.py:vuln_solved` | 8 | vulnerability_detector |
| 57110 | Vulnerabilidades limpiadas (custom) | `templates.py:vuln_cleared` | 8 | vulnerability_detector |

## Cómo agregar un nuevo template

1. Editar `relay/wazuh_waha/domain/templates.py`.
2. Agregar el `rule_id` en el dict `TEMPLATES` con su función lambda.
3. Si la regla es custom (fuera de stock Wazuh), agregar el bloque en
   `manager-side/rules/local_rules.xml` y reiniciar el manager.
4. Actualizar esta tabla.

## Cómo desactivar un template

Borrar (o comentar) la entrada del dict `TEMPLATES` en `relay/wazuh_waha/domain/templates.py`.
Reiniciar el servicio. Las alertas que matcheen ese rule_id caerán a
`render_default()` (formato genérico).
