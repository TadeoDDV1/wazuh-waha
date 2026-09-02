#!/bin/bash
# ==============================================================================
# Wazuh WAHA - Visualizador de Logs Unificados
# ==============================================================================

CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}     Mostrando logs de Docker y del Relay           ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "Presiona Ctrl+C para salir.\n"

# Iniciar logs de docker en background
docker compose logs -f --tail=20 &
DOCKER_PID=$!

# Iniciar logs de systemd (relay) en background
journalctl -u wazuh-waha -f -n 20 &
RELAY_PID=$!

# Función para limpiar procesos al presionar Ctrl+C
cleanup() {
    echo -e "\n${CYAN}Deteniendo logs...${NC}"
    kill $DOCKER_PID $RELAY_PID 2>/dev/null
    exit 0
}

# Atrapar la señal SIGINT (Ctrl+C)
trap cleanup SIGINT SIGTERM

# Esperar infinitamente a que terminen los procesos
wait
