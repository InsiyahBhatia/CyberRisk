"""Application configuration, read from environment / .env."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    app_name: str = "CyberRisk"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"
    gemini_fallback_models: str = "gemini-3.7-flash,gemini-3.5-flash"  # tried in order if the primary is busy or retired
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"
    groq_fallback_models: str = "openai/gpt-oss-20b,qwen/qwen3.8-27b,llama-3.3-70b-versatile"
    llm_provider: str = "auto"  # auto | gemini | groq. auto picks by key shape (gsk_ = Groq, otherwise Gemini)
    database_url: str = "sqlite:///./data/cyberrisk.db"
    vector_store_path: str = "./data/vector_store"
    log_level: str = "INFO"
    nvd_api_key: str = ""
    nvd_start_date: str = ""
    nvd_end_date: str = ""
    nvd_max_records: int = 300
    prompt_version: str = "v1"
    max_input_chars: int = 2000
    data_root: str = ""  # override for the data/ directory (tests)

    @property
    def data_dir(self) -> Path:
        return Path(self.data_root) if self.data_root else ROOT / "data"

    @property
    def db_path(self) -> Path:
        url = self.database_url
        if not url.startswith("sqlite:///"):
            raise ValueError("Only SQLite is supported")
        p = Path(url[len("sqlite:///"):])
        return p if p.is_absolute() else ROOT / p


@lru_cache
def get_settings() -> Settings:
    return Settings()
