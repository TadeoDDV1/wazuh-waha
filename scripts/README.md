# Scripts

Ejecutables bash de primer nivel. No se commitean con sudo, ver nota en cada uno.

| Script | Para qué sirve | Necesita sudo | TTY |
|---|---|---|---|
| `diagnose.sh` | Check read-only de toda la stack | a veces | no |
| `diag-vbox.sh` | Diagnóstico de red VirtualBox | no | no |
| `fix-wazuh-waha.sh` | Reinicia el servicio si está zombie | sí | sí |
| `install-wazuh-waha.sh` | Instala unit + dirs + restart | sí | sí |
| `recover-waha.sh` | STOP+wait+START sesión WAHA pegada | no | no |
