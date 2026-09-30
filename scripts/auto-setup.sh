#!/bin/bash
set -e

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
ENV_FILE="$PROJECT_ROOT/.env"

echo -e "\n\033[1;36m====================================================\033[0m"
echo -e "\033[1;36m   Wazuh-WAHA Auto-Setup: Buscando Servidor Wazuh   \033[0m"
echo -e "\033[1;36m====================================================\033[0m\n"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$PROJECT_ROOT/.env.example" ]; then
        cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"
        echo -e "\033[0;33m[!] Archivo .env creado desde .env.example\033[0m"
    else
        echo -e "\033[0;31m[!] No se encontró .env ni .env.example\033[0m"
        exit 1
    fi
fi

TARGET_IP=""

# Check for manual IP
if [ "$1" == "--ip" ] && [ -n "$2" ]; then
    TARGET_IP="$2"
    echo -e "\033[0;32m[+] Usando IP manual: $TARGET_IP\033[0m"
else
    echo -e "\033[0;34m[*] Detectando red local...\033[0m"
    # Try to find default route interface and its subnet
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$IFACE" ]; then
        echo -e "\033[0;31m[x] No se pudo detectar la interfaz de red por defecto.\033[0m"
        exit 1
    fi
    
    SUBNET=$(ip -o -f inet addr show $IFACE | awk '{print $4}')
    echo -e "\033[0;34m[*] Escaneando subred: $SUBNET en interfaz $IFACE...\033[0m"
    
    # We will use nmap if available, otherwise fallback to simple iteration.
    if command -v nmap &> /dev/null; then
        echo -e "\033[0;34m[*] Usando nmap para escaneo rápido...\033[0m"
        # Scan for alive hosts, then grep for port 55000 or 1515 open.
        ALIVE_HOSTS=$(nmap -sn $SUBNET -oG - | awk '/Up$/{print $2}')
    else
        echo -e "\033[0;33m[*] Nmap no encontrado, intentando escaneo de ping (puede tardar más)...\033[0m"
        BASE_IP=$(echo $SUBNET | cut -d/ -f1 | cut -d. -f1-3)
        ALIVE_HOSTS=""
        for i in {1..254}; do
            (ping -c 1 -W 1 $BASE_IP.$i > /dev/null && echo "$BASE_IP.$i" >> /tmp/alive_hosts_$$) &
        done
        wait
        if [ -f /tmp/alive_hosts_$$ ]; then
            ALIVE_HOSTS=$(cat /tmp/alive_hosts_$$)
            rm /tmp/alive_hosts_$$
        fi
    fi

    echo -e "\033[0;34m[*] Verificando puertos Wazuh en hosts activos...\033[0m"
    for ip in $ALIVE_HOSTS; do
        # Check port 55000 (API) or 1515 (Enrollment)
        if timeout 1 bash -c "echo >/dev/tcp/$ip/55000" 2>/dev/null || timeout 1 bash -c "echo >/dev/tcp/$ip/1515" 2>/dev/null; then
            echo -e "\033[0;32m[+] Posible servidor Wazuh encontrado en $ip\033[0m"
            
            # Verify API
            echo -e "\033[0;34m[*] Validando API Wazuh en $ip...\033[0m"
            if curl -s -k -m 3 "https://$ip:55000/" | grep -q "title" || curl -s -k -m 3 "https://$ip:55000/" | grep -q "message"; then
                 TARGET_IP=$ip
                 echo -e "\033[1;32m[✔] ¡Servidor Wazuh confirmado en $TARGET_IP!\033[0m"
                 break
            fi
        fi
    done
fi

if [ -z "$TARGET_IP" ]; then
    echo -e "\n\033[1;31m[!] No se pudo encontrar automáticamente el servidor Wazuh.\033[0m"
    read -p "Introduce la IP del manager Wazuh manualmente: " TARGET_IP
fi

if [ -n "$TARGET_IP" ]; then
    echo -e "\033[0;34m[*] Actualizando $ENV_FILE con $TARGET_IP...\033[0m"
    sed -i -E "s/^(WAZUH_SERVER_IP)=.*/\1=$TARGET_IP/" "$ENV_FILE"
    
    # Verify it was updated
    if grep -q "^WAZUH_SERVER_IP=$TARGET_IP" "$ENV_FILE"; then
        echo -e "\033[1;32m[✔] Configuración guardada correctamente.\033[0m"
    else
        echo -e "\033[0;31m[x] Error al actualizar el archivo .env\033[0m"
        echo "Asegúrate de tener WAZUH_SERVER_IP= en el archivo."
    fi
else
    echo -e "\033[0;31m[x] Operación cancelada.\033[0m"
    exit 1
fi
