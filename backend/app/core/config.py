from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AuditFlow"
    api_prefix: str = "/api/v1"
    database_url: str = Field(default="sqlite:///./auditflow.db", alias="DATABASE_URL")
    allowed_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    environment: str = "development"

    jwt_secret_key: str = Field(default="change-me-in-production", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
