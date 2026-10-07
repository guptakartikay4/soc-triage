"""
Application configuration (Pydantic Settings).

All configuration comes from environment variables or ``backend/.env``.
Secrets (GROQ_API_KEY) are held as ``SecretStr`` so they are never printed
by ``repr()`` / logging.  No credentials are hard-coded here: the default
DATABASE_URL points at a *local development* database only.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent

# The test-suite sets SOC_TESTING=1 so a developer's real .env (database URL,
# Groq key) can never leak into unit tests.
_ENV_FILE: Optional[Path] = None if os.getenv("SOC_TESTING") else BACKEND_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---------------------------------------------------------
    app_name: str = "SOC Triage API"
    app_version: str = "1.0.0"
    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    # Comma-separated list. "*" is only honoured outside production.
    cors_origins: str = "*"

    # --- Database ------------------------------------------------------------
    database_url: str = "postgresql+psycopg://soc_triage:soc_triage@localhost:5432/soc_triage"

    # --- AI briefing (Groq) --------------------------------------------------
    groq_api_key: Optional[SecretStr] = None
    groq_model: str = "openai/gpt-oss-120b"
    groq_timeout_seconds: float = 30.0
    ai_brief_max_per_run: int = Field(default=25, ge=0)

    # --- MTTT ----------------------------------------------------------------
    # No default baseline: a baseline must be a deliberate, labelled assumption.
    mttt_baseline_minutes: Optional[float] = Field(default=None, gt=0)
    mttt_baseline_note: Optional[str] = None

    # --- Data ----------------------------------------------------------------
    dataset_path: Path = BACKEND_DIR / "data" / "synthetic_alerts.csv"

    @field_validator("groq_api_key", mode="before")
    @classmethod
    def _blank_key_is_none(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return v

    @field_validator("mttt_baseline_minutes", mode="before")
    @classmethod
    def _blank_baseline_is_none(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    # --- Derived helpers -----------------------------------------------------
    @property
    def cors_origin_list(self) -> list[str]:
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if self.app_env == "production":
            origins = [o for o in origins if o != "*"]
        return origins or []

    @property
    def groq_configured(self) -> bool:
        return self.groq_api_key is not None and bool(self.groq_api_key.get_secret_value().strip())

    @property
    def database_backend(self) -> str:
        return self.database_url.split(":", 1)[0].split("+", 1)[0]


@lru_cache
def get_settings() -> Settings:
    return Settings()
