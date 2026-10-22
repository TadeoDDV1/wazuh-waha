# Despliegue de producción

Esta carpeta contiene los artefactos para instalar wazuh-waha en un servidor
dedicado con systemd + Docker + Caddy.

## Instalación rápida

```bash
sudo git clone https://github.com/TadeoDDV1/wazuh-waha.git /opt/wazuh-waha
cd /opt/wazuh-waha
sudo bash scripts/install-production.sh
sudo nano .env
sudo bash scripts/deploy-production.sh
```

La guía completa está en [`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md).

## Componentes

- `docker-compose.prod.yml`: WAHA y dashboard, publicados solo en `127.0.0.1`.
- `Caddyfile`: TLS automático + reverse proxy (dashboard, API, SSE y WebSocket).
- `systemd/`: unidad del relay y watchdog.
