from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LM Studio
    lm_studio_base_url: str = "http://localhost:1234/v1"
    lm_studio_model: str = ""

    # Wazuh Manager API (agent management, auth healthcheck)
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_verify_ssl: bool = False

    # Wazuh Indexer (OpenSearch) — alerts live here, not in the manager API
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str = "SecretPassword"

    # Database
    database_url: str = "postgresql+asyncpg://alertbridge:alertbridge@localhost:5432/alertbridge"

    # osquery
    osquery_transport: str = "mock"  # "ssh" | "mock"
    osquery_ssh_user: str = "root"
    osquery_ssh_key_path: str = ""
    osquery_ssh_timeout: int = 10

    # Correlation
    correlation_time_window_minutes: int = 15

    # Application
    log_level: str = "INFO"


settings = Settings()
