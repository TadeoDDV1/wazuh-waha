#!/usr/bin/env python3
"""
test_traffic_detection.py - Prueba de detección de tráfico y eventos de seguridad en Wazuh.
Genera eventos de red (tráfico SSH ilegítimo, legítimo y comandos sudo) y extrae en tiempo
real las alertas correlacionadas por el motor de reglas de Wazuh.

Requiere (sin defaults de secretos):
  WAZUH_SERVER_IP  — IP del manager
  WAZUH_SSH_USER   — usuario SSH del manager
  WAZUH_SSH_PASS   — password SSH (opcional si hay clave BatchMode)
"""

import json
import os
import subprocess
import time

SERVER_IP = os.getenv("WAZUH_SERVER_IP", "")
SERVER_USER = os.getenv("WAZUH_SSH_USER", "")
SERVER_PASS = os.getenv("WAZUH_SSH_PASS", "")


def _build_ssh_base() -> list[str]:
    if not SERVER_IP or not SERVER_USER:
        raise SystemExit(
            "ERROR: define WAZUH_SERVER_IP y WAZUH_SSH_USER en el entorno "
            "(y WAZUH_SSH_PASS si usas sshpass). No hay passwords por defecto."
        )
    if not SERVER_PASS:
        return [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            f"{SERVER_USER}@{SERVER_IP}",
        ]
    return [
        "sshpass", "-p", SERVER_PASS,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        f"{SERVER_USER}@{SERVER_IP}",
    ]


SSH_BASE: list[str] = []


def run_remote(cmd: str) -> str:
    return subprocess.check_output(SSH_BASE + [cmd], text=True)


def sudo_prefix() -> str:
    return f"echo '{SERVER_PASS}' | sudo -S " if SERVER_PASS else "sudo -n "


def main() -> None:
    global SSH_BASE
    SSH_BASE = _build_ssh_base()
    print("=" * 70)
    print("      PRUEBA DE CAPTURA DE TRÁFICO Y EVENTOS EN WAZUH SIEM / XDR     ")
    print("=" * 70)

    print("\n[1] Verificando agentes conectados a la flota...")
    try:
        agents = run_remote(f"{sudo_prefix()}/var/ossec/bin/agent_control -l")
        for line in agents.splitlines():
            if "ID:" in line or "Wazuh agent_control" in line:
                print("   ", line.strip())
    except Exception as e:
        print(f"    Error consultando agentes: {e}")

    start_count = 0
    try:
        out = run_remote(f"{sudo_prefix()}wc -l /var/ossec/logs/alerts/alerts.json")
        start_count = int(out.strip().split()[0])
        print(f"\n[2] Alertas registradas antes del test: {start_count}")
    except Exception as e:
        print(f"    Error contando alertas: {e}")

    print("\n[3] Generando tráfico de prueba (logins SSH fallidos)...")
    for user in ("nouser", "root"):
        try:
            subprocess.run(
                [
                    "sshpass", "-p", "wrongpass", "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=3",
                    f"{user}@{SERVER_IP}", "id",
                ],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass

    print("\n[4] Esperando correlación de reglas (5s)...")
    time.sleep(5)

    try:
        out = run_remote(f"{sudo_prefix()}tail -n 20 /var/ossec/logs/alerts/alerts.json")
        new_lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        print(f"\n[5] Últimas alertas ({len(new_lines)} líneas):")
        for ln in new_lines[-5:]:
            try:
                data = json.loads(ln)
                rule = data.get("rule", {})
                agent = data.get("agent", {})
                print(
                    f"    - [{agent.get('name')}] L{rule.get('level')} "
                    f"#{rule.get('id')}: {str(rule.get('description', ''))[:80]}"
                )
            except json.JSONDecodeError:
                pass
        if start_count:
            print("\n[OK] Si el conteo creció, Wazuh está registrando tráfico del host.")
    except Exception as e:
        print(f"    Error leyendo alertas: {e}")


if __name__ == "__main__":
    main()
