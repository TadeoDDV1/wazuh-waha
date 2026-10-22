# Seguridad

## Modelo de acceso

- **Dashboard**: login con API key maestra → cookie de sesión HttpOnly firmada.
  La key nunca se guarda en el navegador ni en el bundle.
- **RBAC**: `full` (lectura/escritura) y `read` (solo lectura).
- **Consola web**: requiere `full`, HTTPS/VPN, validación de `Origin`,
  allowlist de destinos, límite de sesiones, timeouts y auditoría.
- **Integración Wazuh**: `X-Api-Key` solo desde el manager/scripts.

## Recomendaciones obligatorias en producción

- `SESSION_COOKIE_SECURE=true`.
- HTTPS con Caddy/Let's Encrypt.
- `ENABLE_DOCS=false`.
- `CONSOLE_ALLOW_LOCAL_SHELL=false`.
- `CONSOLE_TARGETS=manager` (sin agentes salvo necesidad).
- `WAZUH_MANAGER_CONFIG_WRITE_ENABLED=false`.
- `WAZUH_VM_SSH_STRICT_HOST_KEY=yes` + `known_hosts`.
- Firewall: solo 80/443 público; 22 restringido; resto en localhost/VPN.
- SSH solo claves; deshabilitar login root.
- Backups con permisos 600/700 y destino externo.

## Puertos y superficies

| Puerto | Debe ser público |
|---|---|
| 80/443 | Sí (Caddy) |
| 22 | Solo admin/VPN |
| 8765, 8001, 3001 | No |
| 55000, 1514/1515 | No (red interna/VPN) |

## Secretos

- `.env` con `600 root:wazuh-waha`.
- `/etc/wazuh-waha/relay.env` con `640 root:wazuh-waha`.
- Clave SSH en `/etc/wazuh-waha/ssh` con `600`.
- Nunca commitear `.env`, claves, `wsl-relay.conf` real ni backups.
- Rotar claves ante sospecha de compromiso.

## Auditoría

- Mutaciones: `/var/lib/wazuh-waha/audit.jsonl`.
- Sesiones de consola: apertura/cierre, target, sid, IP y duración.
- Rate limit y body limit activos en el relay.
- Logs de Caddy con rotación.

## Consola web: riesgo residual

Una shell web equivale a acceso directo al servidor. No exponerla a Internet
sin TLS + VPN/MFA. Si no se necesita, dejarla deshabilitada.
