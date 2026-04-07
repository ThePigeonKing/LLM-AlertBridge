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

    # Wazuh
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_verify_ssl: bool = False

    # Database
    database_url: str = "postgresql+asyncpg://alertbridge:alertbridge@localhost:5432/alertbridge"

    # Application
    log_level: str = "INFO"


settings = Settings()
