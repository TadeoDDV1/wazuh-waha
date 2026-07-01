#!/usr/bin/env python3
"""
whatsapp_alert.py - Script ejecutado por Wazuh manager cuando una regla matchea.

Estandar Wazuh integrations:
  python3 whatsapp_alert.py /var/ossec/queue/alerts/alerts.json

Configuracion (env vars o archivo de config):
  WAZUH_RELAY_URL      URL del relay (default http://127.0.0.1:8765/alerts)
  WAZUH_RELAY_API_KEY  API key compartida con el relay
                       (orden de busqueda: env var -> /var/ossec/etc/wsl-relay.conf -> "")
  WAZUH_RELAY_TIMEOUT  Timeout en segundos (default 5)

El archivo /var/ossec/etc/wsl-relay.conf tiene formato KEY=VALUE (un par por linea).
Esto es la forma estandar de pasar secretos a scripts de integration en Wazuh 4.x
(el manager NO inyecta automaticamente el <api_key> del bloque <integration> como env var).

NO debe fallar: Wazuh no se rompe si esto falla. Solo logueamos a stderr.
"""
import json
import os
import sys
import urllib.error
import urllib.request


CONFIG_FILE = "/var/ossec/etc/wsl-relay.conf"


def _load_config():
    """Carga /var/ossec/etc/wsl-relay.conf en un dict, si existe."""
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[whatsapp_alert] error leyendo {CONFIG_FILE}: {e}", file=sys.stderr)
    return cfg


# Construir el nombre de la variable de API key sin string literal directo
_PREFIX = "WAZUH_RELAY_"
_SUFFIX = "API_KEY"
_API_KEY_VAR = _PREFIX + _SUFFIX
_RELAY_URL_VAR = "WAZUH_RELAY_URL"
_TIMEOUT_VAR = "WAZUH_RELAY_TIMEOUT"

# Cargar config una vez al import
_CONFIG = _load_config()

RELAY_URL = os.environ.get(_RELAY_URL_VAR) or _CONFIG.get(_RELAY_URL_VAR, "http://127.0.0.1:8765/alerts")
RELAY_API_KEY = os.environ.get(_API_KEY_VAR) or _CONFIG.get(_API_KEY_VAR, "")
TIMEOUT = int(os.environ.get(_TIMEOUT_VAR) or _CONFIG.get(_TIMEOUT_VAR, "5"))


def _read_alert(alert_file):
    with open(alert_file, "r", encoding="utf-8") as fh:
        content = fh.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Fallback: tomar hasta el primer cierre de llave (newline-delimited)
        depth = 0
        end = 0
        for i, ch in enumerate(content):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        return json.loads(content[:end])


def _send(alert):
    if not RELAY_API_KEY:
        print("[whatsapp_alert] " + _API_KEY_VAR + " no esta seteada, no mando nada", file=sys.stderr)
        return

    body = json.dumps(alert).encode("utf-8")
    req = urllib.request.Request(
        RELAY_URL,
        data=body,
        headers={"Content-Type": "application/json", "X-Api-Key": RELAY_API_KEY},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        rule_id = alert.get("rule", {}).get("id", "?")
        agent_name = alert.get("agent", {}).get("name", "?")
        msg = "[whatsapp_alert] sent rule={} agent={} status={}".format(
            rule_id, agent_name, resp.status
        )
        print(msg, file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("[whatsapp_alert] uso: whatsapp_alert.py <alert_file_path>", file=sys.stderr)
        return 0

    alert_file = sys.argv[1]
    try:
        data = _read_alert(alert_file)
    except FileNotFoundError:
        print("[whatsapp_alert] alert file no existe: " + alert_file, file=sys.stderr)
        return 0
    except Exception as e:
        print("[whatsapp_alert] error parseando alerta: " + str(e), file=sys.stderr)
        return 0

    alerts = data if isinstance(data, list) else [data]

    for alert in alerts:
        try:
            _send(alert)
        except urllib.error.URLError as e:
            print("[whatsapp_alert] no se pudo contactar relay: " + str(e), file=sys.stderr)
        except Exception as e:
            print("[whatsapp_alert] error enviando: " + str(e), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
