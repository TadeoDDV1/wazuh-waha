# Changelog

## [1.0.0] - 2026-10-21

### Añadido
- Despliegue de producción con systemd + Docker Compose + Caddy.
- Scripts `install-production.sh`, `deploy-production.sh`, `preflight.sh`,
  `healthcheck.sh`, `backup.sh`, `restore.sh`, `rollback.sh` y
  `install-manager-side.sh`.
- Plantilla `.env.production.example` y documentación de despliegue.
- Vista **Detecciones Wazuh** (alertas, FIM, SCA, Rootcheck, vulnerabilidades,
  Syscollector y MITRE).
- Control real de módulos de agente con merge seguro de `agent.conf`.
- Terminal de red real basada en `ss` + syscollector, con DNS y dirección.
- Pestaña de conexiones reales en la terminal de tráfico.
- Consola web/SSH con xterm.js, auditoría, límites y timeouts.
- CI de GitHub Actions.

### Seguridad
- Sesión BFF con cookie HttpOnly/SameSite.
- `SESSION_COOKIE_SECURE=true` en producción.
- Consola solo con sesión `full`, allowlist de destinos y validación de Origin.
- Documentación de hardening, puertos y TLS.

### Corregido
- Eliminados datos sintéticos de latencia/paquetes/destinos.
- Lectura real de syscollector (DB local/remota/API) y `sys_netaddr`.
- `sync_relay_env.sh` ahora sincroniza todas las claves del `.env`.
- Rutas locales reemplazadas por configuración portable.
