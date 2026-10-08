"""
Configuracion: lee el .env del proyecto.
Pydantic Settings valida tipos y reporta errores en el arranque.
"""
import json as _json
import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

_log = logging.getLogger("wazuh-waha.config")


class Settings(BaseSettings):
    # --- Relay ---
    relay_port: int = 8765
    relay_bind: str = "0.0.0.0"
    relay_api_key: str = "changeme"
    relay_dedup_ttl: int = 300
    relay_min_level_unknown: int = 8
    relay_log_dir: str = "/var/log/wazuh-waha"
    relay_lib_dir: str = "/var/lib/wazuh-waha"
    relay_backup_dir: str = str(PROJECT_ROOT / "backups")
    relay_backup_enabled: bool = True
    relay_workers: int = 2
    relay_lifespan_timeout: int = 10

    # --- Server Wazuh (manager) ---
    wazuh_server_ip: str = "192.168.1.72"
    wazuh_server_ip_fallback: str = ""
    wazuh_alerts_json_path: str = "/var/ossec/logs/alerts/alerts.json"
    auto_reconcile: bool = False

    # --- Telemetría / terminal de tráfico en vivo ---
    # auto = local si el path existe; si no, SSH a la VM; si no, API manager
    traffic_source: str = "auto"  # auto | local | ssh | api | off
    traffic_poll_interval_sec: float = 1.5
    traffic_journal_path: str = ""  # vacío = <relay_lib_dir>/traffic.jsonl
    # SSH a la VM manager (para leer alerts.json remoto cuando el host es agente)
    wazuh_vm_ssh_user: str = "wazuh"
    wazuh_vm_ssh_port: int = 22
    wazuh_vm_ssh_key_path: str = ""  # vacío = ssh default (~/.ssh/id_*)
    # CORS extra para dashboard (dev vite + nginx de prod)
    allowed_origins: str = "http://localhost:5173,http://localhost:8001,http://127.0.0.1:5173"

    # --- WhatsApp destino ---
    admin_phone: str = ""  # formato: 5219991234567 (sin +)

    # --- Ollama (IA local) ---
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:0.5b"
    ollama_timeout: int = 10
    ollama_enabled: bool = False

    # --- WAHA (WhatsApp HTTP API) ---
    waha_api_key: str = "changeme"
    waha_host: str = "http://localhost:3000"
    waha_session: str = "default"
    waha_log_level: str = "info"
    waha_hook_url: str = ""

    # --- Wazuh Manager API (para reportar health events) ---
    wazuh_manager_host: str = ""
    wazuh_manager_api_port: int = 55000
    wazuh_manager_api_user: str = "wazuh"
    wazuh_manager_api_pass: str = ""
    wazuh_manager_api_verify_tls: bool = False

    # --- Email backup (opcional, vacio = desactivado) ---
    email_provider: str = "smtp"               # smtp | hyvor_relay
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = "wazuh-waha@localhost"
    admin_email: str = ""
    smtp_tls: bool = True

    # --- Hyvor Relay (email API auto-hosteada) ---
    hyvor_base_url: str = ""                   # ej: http://localhost:8000 o https://relay.tudominio.com
    hyvor_api_key: str = ""                    # API key con scope sends.send
    hyvor_from: str = "wazuh-waha@localhost"   # debe ser dominio verificado en Hyvor

    # --- Auto-recovery de sesion WAHA ---
    waha_recovery_cooldown_sec: int = 300
    waha_recovery_max_wait_sec: int = 60
    waha_watchdog_interval_sec: int = 300

    # --- Seguridad ---
    # Tamaño máximo de body HTTP (requests mayores -> 413)
    max_body_bytes: int = 512 * 1024
    # TTL de la cookie de sesión (BFF): la key maestra nunca llega al browser
    session_ttl_hours: int = 8
    # API key opcional de solo-lectura (login con scope "read": ve dashboard
    # y telemetría pero no puede mutar config/agents/módulos)
    relay_readonly_api_key: str = ""
    # IPs/redes desde las que se confía X-Forwarded-For (proxy: nginx)
    trusted_proxies: str = "127.0.0.1,::1,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8"
    # Documentación interactiva (/docs, /openapi.json): apagada en prod
    enable_docs: bool = False
    # SSH del traffic source: yes = exigir known_hosts pre-provisionado
    wazuh_vm_ssh_strict_host_key: str = "accept-new"  # yes | accept-new | no
    session_cookie_secure: bool = False

    # --- Canales de Notificación (WhatsApp, Telegram, Correo) ---
    whatsapp_enabled: bool = True
    email_alerts_enabled: bool = False

    # --- Telegram Bot (monitoreo y notificaciones) ---
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_min_level: int = 8

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def admin_chat_id(self) -> str:
        return f"{self.admin_phone}@c.us"

    @property
    def dedup_state_file(self) -> Path:
        return Path(self.relay_lib_dir) / "dedup_state.json"

    @property
    def traffic_journal_file(self) -> Path:
        if self.traffic_journal_path:
            return Path(self.traffic_journal_path)
        return Path(self.relay_lib_dir) / "traffic.jsonl"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def trusted_proxies_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]


settings = Settings()

# ──────────────────────────────────────────────────────
# Runtime Config Overrides
# ──────────────────────────────────────────────────────
# El dashboard puede togglear settings (ej. OLLAMA_ENABLED) sin editar .env
# (que contiene secrets y puede ser read-only). Los overrides viven en un
# archivo JSON en relay_lib_dir, con permisos de escritura para el relay.
# Se aplican sobre los valores base de .env al arranque.

_overrides_file = Path(settings.relay_lib_dir) / "config_overrides.json"
if not _overrides_file.parent.exists():
    _overrides_file.parent.mkdir(parents=True, exist_ok=True)


def load_overrides() -> dict:
    """Lee overrides de config desde el archivo JSON."""
    if _overrides_file.exists():
        try:
            return _json.loads(_overrides_file.read_text())
        except Exception as e:
            _log.warning("config_overrides_load_error err=%s", e)
    return {}


def save_overrides(data: dict) -> None:
    """Persiste overrides de config al archivo JSON."""
    _overrides_file.write_text(_json.dumps(data, indent=2))


# Aplicar overrides sobre settings (atributos mutables en Pydantic v2)
_overrides = load_overrides()
for _k, _v in _overrides.items():
    if hasattr(settings, _k):
        try:
            setattr(settings, _k, _v)
        except Exception:
            pass
