# Deploy

Configuración específica por host. Cada host donde se corre este proyecto tiene
su subcarpeta. El código de `wazuh-waha/` y `manager/` no se toca por deploys.

| Subdir | Para qué sirve |
|---|---|
| `arch-host/` | Ejemplo: el host Arch donde corre el relay. |
| `vm-manager/` | Ejemplo: la VM Wazuh 4.x que manda las alertas. |
