"""
Configuracion: lee el .env del proyecto.
Pydantic Settings valida tipos y reporta errores en el arranque.
"""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


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


settings = Settings()
