"""
Global configuration — loads from environment variables / .env file.
All services import Settings from here.
"""
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────────
    app_env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=False, alias="DEBUG")
    secret_key: SecretStr = Field(alias="SECRET_KEY")

    # ── Database ─────────────────────────────────────────────
    database_url: str = Field(alias="DATABASE_URL")

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # ── Kafka ────────────────────────────────────────────────
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092", alias="KAFKA_BOOTSTRAP_SERVERS"
    )
    kafka_topic_telemetry: str = Field(
        default="sentinelx.telemetry", alias="KAFKA_TOPIC_TELEMETRY"
    )
    kafka_topic_events: str = Field(
        default="sentinelx.events", alias="KAFKA_TOPIC_EVENTS"
    )
    kafka_topic_alerts: str = Field(
        default="sentinelx.alerts", alias="KAFKA_TOPIC_ALERTS"
    )
    kafka_topic_response: str = Field(
        default="sentinelx.response", alias="KAFKA_TOPIC_RESPONSE"
    )
    kafka_topic_dlq: str = Field(default="sentinelx.dlq", alias="KAFKA_TOPIC_DLQ")

    # ── OpenSearch ───────────────────────────────────────────
    opensearch_host: str = Field(default="localhost", alias="OPENSEARCH_HOST")
    opensearch_port: int = Field(default=9200, alias="OPENSEARCH_PORT")
    opensearch_user: str = Field(default="admin", alias="OPENSEARCH_USER")
    opensearch_password: SecretStr = Field(default="admin", alias="OPENSEARCH_PASSWORD")
    opensearch_use_ssl: bool = Field(default=False, alias="OPENSEARCH_USE_SSL")

    # ── JWT ──────────────────────────────────────────────────
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(
        default=30, alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7, alias="JWT_REFRESH_TOKEN_EXPIRE_DAYS"
    )

    # ── OpenTelemetry ────────────────────────────────────────
    otel_exporter_otlp_endpoint: str = Field(
        default="http://otel-collector:4317", alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    otel_service_name: str = Field(default="sentinelx", alias="OTEL_SERVICE_NAME")

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()  # type: ignore[call-arg]
