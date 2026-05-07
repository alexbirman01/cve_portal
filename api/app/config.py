from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    jira_base_url: str
    jira_email: str
    jira_api_token: str
    jira_use_jsm_internal_comments: bool = False

    postgres_dsn: str = "postgresql+psycopg://cve_portal:cve_portal@localhost:5432/cve_portal"
    redis_url: str = "redis://localhost:6379/0"

    nvd_api_key: str | None = None


settings = Settings()

