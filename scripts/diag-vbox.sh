#!/bin/bash
# Diagnostico del networking de VirtualBox desde el host Arch.
# NO modifica nada. Solo lee.

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }
sep()  { echo -e "\n${YEL}========== $1 ==========${NC}"; }

VM_NAME="${1:-wazuh-prueba1}"   # nombre de la VM Wazuh (default)

sep "1. VBoxManage existe?"
if command -v VBoxManage >/dev/null 2>&1; then
  ok "VBoxManage: $(which VBoxManage)"
  VBoxManage --version 2>&1
else
  fail "VBoxManage no esta en PATH"
  echo "Si VirtualBox esta instalado, proba:"
  echo "  /usr/lib/virtualbox/VBoxManage --version"
  echo "  /opt/VBoxManage --version"
  echo "  find / -name VBoxManage 2>/dev/null"
  exit 1
fi

sep "2. VMs registradas"
VBoxManage list vms 2>&1

sep "3. Estado de la VM $VM_NAME"
VBoxManage showvminfo "$VM_NAME" --details 2>&1 | head -40

sep "4. Adaptadores host-only de VirtualBox"
VBoxManage list hostonlyifs 2>&1

sep "5. DHCP servers de VirtualBox"
VBoxManage list dhcpservers 2>&1

sep "6. Tu Arch tiene la IP esperada en el host-only?"
ip -4 addr show 2>&1 | grep -E "inet 172.44" || warn "NO hay IP 172.44.30.x en ninguna interfaz"
echo
ip -4 addr show 2>&1 | grep -E "vbox|host-only|virbr" || echo "tampoco hay interface 'vboxnet' tipica"

sep "7. Si la VM esta corriendo, que dice su red (guest side)"
RUNNING=$(VBoxManage list runningvms 2>&1 | grep -c "$VM_NAME")
if [ "$RUNNING" -gt 0 ]; then
  ok "$VM_NAME esta corriendo"
  VBoxManage guestproperty get "$VM_NAME" "/VirtualBox/GuestInfo/Net/0/V4/IP" 2>&1
  VBoxManage guestproperty get "$VM_NAME" "/VirtualBox/GuestInfo/Net/0/Status" 2>&1
else
  warn "$VM_NAME NO esta corriendo"
fi

echo
echo -e "${GRN}========== FIN ==========${NC}"
echo "Pegame la salida completa en el chat."
