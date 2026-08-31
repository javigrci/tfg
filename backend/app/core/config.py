from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AuditFlow"
    api_prefix: str = "/api/v1"
    database_url: str = Field(
        default="postgresql+psycopg://auditflow:auditflow@localhost:5432/auditflow",
        alias="DATABASE_URL",
    )
    # CORS — coma-separated origins, e.g. "http://localhost:5173,http://localhost"
    allowed_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173",
        alias="ALLOWED_ORIGINS",
    )
    environment: str = "development"

    jwt_secret_key: str = Field(default="change-me-in-production", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 60

    # Bootstrap users — created on first startup if they do not exist yet
    admin_password: str = Field(default="admin", alias="ADMIN_PASSWORD")
    operator_password: str = Field(default="operator", alias="OPERATOR_PASSWORD")

    # NVD API key (opcional — sin key: 5 req/30s; con key: 50 req/30s)
    # Solicitar gratis en: https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str = Field(default="", alias="NVD_API_KEY")

    # Puertos a excluir del escaneo nmap — evita que la propia plataforma
    # aparezca como finding cuando el target comparte host con la app.
    # En producción con Nginx: EXCLUDED_PORTS=80,443
    excluded_ports: str = Field(default="8000,5173", alias="EXCLUDED_PORTS")
    chain_max_web_targets: int = Field(default=5, alias="CHAIN_MAX_WEB_TARGETS")

    # Cola Celery + Redis (ADR-009). broker/result_backend caen a redis_url si no se fijan.
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="", alias="CELERY_RESULT_BACKEND")

    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    def result_backend(self) -> str:
        return self.celery_result_backend or self.redis_url

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
