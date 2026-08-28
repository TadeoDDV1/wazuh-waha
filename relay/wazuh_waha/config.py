"""
Configuracion: lee el .env del proyecto.
Pydantic Settings valida tipos y reporta errores en el arranque.
"""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
import os

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
print(f"DEBUG: PROJECT_ROOT={PROJECT_ROOT}", flush=True)
print(f"DEBUG: ENV_FILE={ENV_FILE}", flush=True)
print(f"DEBUG: ENV_FILE exists={ENV_FILE.exists()}", flush=True)
if ENV_FILE.exists():
    import subprocess
    result = subprocess.run(['grep', 'RELAY_API_KEY', str(ENV_FILE)], capture_output=True, text=True)
    print(f"DEBUG: ENV_FILE contents (RELAY_API_KEY line): {result.stdout.strip() if result.stdout else 'Not found'}", flush=True)
    
# Debug: Check what's in os.environ for RELAY_API_KEY
env_val = os.environ.get('RELAY_API_KEY')
print(f"DEBUG: os.environ.get('RELAY_API_KEY'): '{env_val}'", flush=True)


class Settings(BaseSettings):
    # --- Relay ---
    relay_port: int = 8765
    relay_bind: str = "0.0.0.0"
    relay_api_key: str = "changeme"
    relay_dedup_ttl: int = 300
    relay_min_level_unknown: int = 10
    relay_log_dir: str = "/var/log/wazuh-waha"
    relay_lib_dir: str = "/var/lib/wazuh-waha"
    relay_workers: int = 2
    relay_lifespan_timeout: int = 10

    # --- Server Wazuh (manager) ---
    wazuh_server_ip: str = "192.168.1.72"
    wazuh_server_ip_fallback: str = ""
    auto_reconcile: bool = False

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
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = "wazuh-waha@localhost"
    smtp_to: str = ""
    smtp_tls: bool = True

    # --- Hyvor Relay (email API auto-hosteada) ---
    hyvor_base_url: str = ""                   # ej: http://localhost:8000 o https://relay.tudominio.com
    hyvor_api_key: str = ""                    # API key con scope sends.send
    hyvor_from: str = "wazuh-waha@localhost"   # debe ser dominio verificado en Hyvor
    hyvor_to: str = ""                         # email destino

    # --- Auto-recovery de sesion WAHA ---
    waha_recovery_cooldown_sec: int = 300
    waha_recovery_max_wait_sec: int = 60
    waha_watchdog_interval_sec: int = 300

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Validator to debug what value is being set for relay_api_key
    @field_validator('relay_api_key')
    @classmethod
    def debug_relay_api_key(cls, v):
        print(f"DEBUG: relay_api_key validator called with value: '{v}'", flush=True)
        return v

    @property
    def admin_chat_id(self) -> str:
        return f"{self.admin_phone}@c.us"

    @property
    def dedup_state_file(self) -> Path:
        return Path(self.relay_lib_dir) / "dedup_state.json"


settings = Settings()
print(f"DEBUG: Settings relay_api_key after initialization: {settings.relay_api_key}", flush=True)

# ──────────────────────────────────────────────────────
# Runtime Config Overrides
# ──────────────────────────────────────────────────────
# El dashboard puede togglear settings (ej. OLLAMA_ENABLED) sin editar .env
# (que contiene secrets y puede ser read-only). Los overrides viven en un
# archivo JSON en relay_lib_dir, con permisos de escritura para el relay.
# Se aplican sobre los valores base de .env al arranque.
import json as _json
from pathlib import Path as _Path

_overrides_file = _Path(settings.relay_lib_dir) / "config_overrides.json"
print(f"DEBUG: Overrides file path: {_overrides_file}", flush=True)
print(f"DEBUG: Overrides file exists: {_overrides_file.exists()}", flush=True)
if not _overrides_file.parent.exists():
    _overrides_file.parent.mkdir(parents=True, exist_ok=True)

def load_overrides() -> dict:
    if _overrides_file.exists():
        try:
            data = _json.loads(_overrides_file.read_text())
            print(f"DEBUG: Loaded overrides: {data}", flush=True)
            return data
        except Exception as e:
            print(f"DEBUG: Error loading overrides: {e}", flush=True)
            pass
    return {}

def save_overrides(data: dict) -> None:
    _overrides_file.write_text(_json.dumps(data, indent=2))

# Aplicar overrides sobre settings (atributos mutables en Pydantic v2)
_overrides = load_overrides()
print(f"DEBUG: Overrides to apply: {_overrides}", flush=True)
for _k, _v in _overrides.items():
    if hasattr(settings, _k):
        try:
            print(f"DEBUG: Applying override {_k} = {_v}", flush=True)
            setattr(settings, _k, _v)
        except Exception:
            pass

print(f"DEBUG: Final settings relay_api_key: {settings.relay_api_key}", flush=True)
