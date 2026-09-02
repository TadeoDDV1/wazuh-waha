#!/bin/bash

# ==============================================================================
# Wazuh WAHA - Monitor de Estado y Logs
# ==============================================================================

# Colores para la salida
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}        Estado de los Servicios (Docker)            ${NC}"
echo -e "${CYAN}====================================================${NC}"
docker compose ps

echo -e "\n${CYAN}====================================================${NC}"
echo -e "${CYAN}                 Enlaces Locales                    ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "🎨 ${GREEN}Dashboard UI:${NC} http://localhost"
echo -e "🔌 ${GREEN}WAHA API:${NC}      http://localhost:3001"
echo -e "====================================================\n"

echo -e "${YELLOW}Mostrando logs en tiempo real... (Presiona Ctrl+C para salir)${NC}"
echo "----------------------------------------------------"
docker compose logs -f
