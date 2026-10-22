# Troubleshooting

## El relay no arranca
```bash
systemctl status wazuh-waha
journalctl -u wazuh-waha -n 80 --no-pager
```
Causas típicas:
- `.env` inválido o faltante.
- Puerto 8765 ocupado: `ss -ltnp | grep 8765`.
- Venv roto: recrear con `scripts/install-production.sh`.
- Disco lleno: `df -h /` y `docker system df`.

## Dashboard no responde
```bash
docker ps
docker logs wazuh-waha-dashboard
curl -I http://127.0.0.1:8001/
```
Verificar que WAHA y dashboard estén en `127.0.0.1` y Caddy arriba.

## HTTPS no funciona
```bash
systemctl status caddy
journalctl -u caddy -n 80 --no-pager
dig +short DOMINIO
```
El DNS debe apuntar al servidor y los puertos 80/443 deben estar abiertos.

## WAHA no conecta / QR
```bash
docker logs wazuh-waha
curl -H "X-Api-Key: $WAHA_API_KEY" http://127.0.0.1:3001/api/sessions/default
```
Abrir el dashboard y usar el QR. Si la sesión quedó trabada:
```bash
sudo bash scripts/recover-waha.sh
```

## No llegan alertas de Wazuh
- Verificar integración:
  ```bash
  grep -n custom-whatsapp /var/ossec/etc/ossec.conf
  cat /var/ossec/etc/wsl-relay.conf
  ```
- Probar:
  ```bash
  curl -H "X-Api-Key: $RELAY_API_KEY" http://127.0.0.1:8765/health
  ```
- Revisar `journalctl -u wazuh-manager -n 80`.
- Si el manager es remoto, verificar firewall y que el manager alcance el relay.

## Terminal de red sin IPs/DNS
- Confirmar `TRAFFIC_SOURCE` y conectividad al manager.
- Si el manager es remoto, verificar SSH:
  ```bash
  ssh -i /etc/wazuh-waha/ssh/id_ed25519 usuario@manager 'ss -tunap'
  ```
- Comprobar que el agente esté activo en Wazuh.
- Revisar `/var/lib/wazuh-waha/traffic.jsonl` y logs del relay.

## Consola WebSocket no conecta
- Debe ser HTTPS/WSS y sesión `full`.
- Caddy debe proxear `/api/v1/console/*`.
- Revisar `Origin` y `ALLOWED_ORIGINS`.
- Logs: `journalctl -u wazuh-waha | grep console`.

## Error de permisos
```bash
ls -la /etc/wazuh-waha /var/lib/wazuh-waha /var/backups/wazuh-waha
```
El usuario `wazuh-waha` necesita lectura del proyecto y escritura en
`/var/lib/wazuh-waha`, `/var/log/wazuh-waha` y `/var/backups/wazuh-waha`.

## Restaurar un backup
```bash
sudo bash scripts/restore.sh /var/backups/wazuh-waha/<timestamp>
```
