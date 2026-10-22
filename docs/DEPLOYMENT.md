# Despliegue en servidor dedicado

Guía para instalar wazuh-waha desde GitHub en un servidor Ubuntu 24.04 LTS
(compatible con Debian 12). El servidor puede alojar también el Wazuh Manager
o conectarse a uno remoto.

## 1. Requisitos

- Ubuntu 24.04 LTS / Debian 12.
- 4 vCPU, 8 GB RAM y 20 GB libres como mínimo (más si aloja Wazuh Indexer).
- Python >= 3.11, Docker + Compose, Caddy (TLS), git, curl, openssl.
- Dominio o subdominio apuntando al servidor (recomendado).
- Acceso SSH por clave.

## 2. Instalación rápida

```bash
sudo git clone https://github.com/TadeoDDV1/wazuh-waha.git /opt/wazuh-waha
cd /opt/wazuh-waha
sudo bash scripts/preflight.sh
sudo bash scripts/install-production.sh
sudo nano .env
sudo bash scripts/deploy-production.sh
sudo bash scripts/install-manager-side.sh
```

El instalador:
- Crea el usuario `wazuh-waha` y los directorios de estado/logs/backups.
- Instala dependencias del sistema si faltan.
- Crea `.env` desde `.env.production.example` y genera claves si están vacías.
- Crea el venv del relay e instala dependencias.
- Instala units systemd, watchdog y Caddyfile.
- Sincroniza `/etc/wazuh-waha/relay.env`.

## 3. Configuración `.env`

Editar `/opt/wazuh-waha/.env`. Variables imprescindibles:

```env
DOMAIN=soc.example.com
WAZUH_SERVER_IP=127.0.0.1          # o IP del manager remoto
WAZUH_MANAGER_API_USER=wazuh-wui
WAZUH_MANAGER_API_PASS=...
RELAY_API_KEY=...                  # se genera automáticamente
WAHA_API_KEY=...                   # se genera automáticamente
ADMIN_PHONE=...
SESSION_COOKIE_SECURE=true
ALLOWED_ORIGINS=https://soc.example.com
CONSOLE_ENABLED=true
CONSOLE_TARGETS=manager
CONSOLE_ALLOW_LOCAL_SHELL=false
```

### Manager local
```env
WAZUH_SERVER_IP=127.0.0.1
TRAFFIC_SOURCE=local
WAZUH_MANAGER_HOST=
```

### Manager remoto
```env
WAZUH_SERVER_IP=10.0.0.20
WAZUH_MANAGER_HOST=10.0.0.20
TRAFFIC_SOURCE=ssh
WAZUH_VM_SSH_USER=wazuh
WAZUH_VM_SSH_KEY_PATH=/etc/wazuh-waha/ssh/id_ed25519
WAZUH_VM_SSH_STRICT_HOST_KEY=yes
```

Provisionar la clave y `known_hosts`:
```bash
sudo install -d -m 750 -o root -g wazuh-waha /etc/wazuh-waha/ssh
sudo install -m 600 -o wazuh-waha -g wazuh-waha ~/.ssh/id_ed25519 /etc/wazuh-waha/ssh/id_ed25519
sudo ssh-keyscan -H 10.0.0.20 | sudo tee -a /etc/wazuh-waha/ssh/known_hosts
```

## 4. TLS y reverse proxy

`install-production.sh` renderiza `/etc/caddy/Caddyfile` con el `DOMAIN`.
Caddy obtiene el certificado automáticamente.

- Dashboard: `https://DOMAIN/`
- API/SSE: `https://DOMAIN/api/*`
- Consola WebSocket: `https://DOMAIN/api/v1/console/*`
- Health: `https://DOMAIN/health`

Sin dominio: dejar `DOMAIN=` vacío. Caddy servirá HTTP en `:80`; usar túnel SSH:
```bash
ssh -L 8001:127.0.0.1:8001 usuario@servidor
```
y abrir `http://127.0.0.1:8001`.

## 5. Integración con Wazuh Manager

Local:
```bash
sudo bash scripts/install-manager-side.sh
```

Remoto (con `RELAY_URL` accesible desde el manager):
```bash
sudo bash scripts/install-manager-side.sh \
  --relay-url http://10.0.0.30:8765/alerts
```

El script instala:
- `/var/ossec/integrations/custom/whatsapp_alert.py`
- `/var/ossec/etc/wsl-relay.conf`
- `local_rules.xml`
- Bloque `<integration>` en `ossec.conf` (con backup)

El manager remoto requiere `sudo -n` para el usuario SSH.

## 6. Configuraciones manuales restantes

1. **DNS**: registro A/AAAA de `DOMAIN` al servidor.
2. **TLS**: verificar `https://DOMAIN`.
3. **WhatsApp**: abrir el dashboard, escanear el QR de WAHA.
4. **Telegram**: crear bot en @BotFather, poner token y hacer `/start`.
5. **Email**: configurar SMTP o Hyvor.
6. **Usuario API Wazuh**: crear usuario con permisos mínimos (agentes,
   syscollector, SCA, FIM, rootcheck, grupos) y ponerlo en `.env`.
7. **Firewall**:
   ```bash
   sudo ufw default deny incoming
   sudo ufw allow from <IP_ADMIN> to any port 22 proto tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```
8. **Backups externos**: programar `scripts/backup.sh` en cron y copiar
   `/var/backups/wazuh-waha` a otro destino.
9. **Registro de agentes**: instalar `wazuh-agent` en endpoints.

## 7. Verificación

```bash
sudo bash scripts/healthcheck.sh
curl -k https://DOMAIN/health
systemctl status wazuh-waha
docker compose -f deploy/production/docker-compose.prod.yml ps
```

Comprobar:
- Login HTTPS y cookie `Secure`.
- SSE de telemetría y red.
- Consola WebSocket.
- Toggle de un módulo de agente (con backup).
- Reporte PDF.
- Reinicio del servidor y arranque automático.

## 8. Actualización

```bash
cd /opt/wazuh-waha
sudo git pull --ff-only
sudo bash scripts/deploy-production.sh
```

Si falla:
```bash
sudo bash scripts/rollback.sh
```

## 9. Arquitectura de puertos

| Puerto | Exposición | Servicio |
|---|---|---|
| 80/443 | Pública (Caddy) | Dashboard/API/TLS |
| 8765 | 127.0.0.1 | Relay |
| 8001 | 127.0.0.1 | Dashboard nginx |
| 3001 | 127.0.0.1 | WAHA |
| 55000 | Red interna | Wazuh API |
| 1514/1515 | Red interna/VPN | Agentes Wazuh |

No exponer 8765, 8001, 3001, 55000 ni 1514/1515 a Internet.
