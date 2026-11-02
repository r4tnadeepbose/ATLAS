import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore", env_prefix="ATLAS_"
    )

    app_name: str = "ATLAS"
    app_env: Literal["development", "test", "demo", "production"] = "development"
    api_prefix: str = "/api/v1"
    debug: bool = False

    secret_key: str = "change-me-in-production-atlas-signing-key-48-bytes-minimum"
    access_token_minutes: int = 60
    refresh_token_days: int = 7
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "atlas"

    database_url: str = "sqlite:///./atlas.db"
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20

    redis_url: str | None = None
    rabbitmq_url: str | None = None
    celery_always_eager: bool = True

    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    allowed_hosts: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["*"])
    rate_limit_per_minute: int = 240
    max_upload_mb: int = 25
    scanner_timeout_seconds: int = 300

    # Identity provider (Keycloak / OIDC) — optional, JWT login remains available.
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_jwks_url: str | None = None

    # AI provider — provider independent. "none" yields deterministic,
    # clearly-labelled heuristic analysis instead of calling an LLM.
    ai_provider: Literal["none", "openai", "anthropic", "ollama", "openai_compatible"] = "none"
    ai_base_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: int = 60
    ai_max_tokens: int = 1600

    demo_mode: bool = False
    seed_demo_data: bool = False

    # External intelligence endpoints
    osv_api_url: str = "https://api.osv.dev/v1"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None

    require_scan_authorization: bool = True
    scanner_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("cors_origins", "allowed_hosts", "scanner_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, value):
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [item.strip() for item in text.split(",") if item.strip()]
        return value

    @property
    def is_demo(self) -> bool:
        return self.app_env == "demo" or self.demo_mode


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
