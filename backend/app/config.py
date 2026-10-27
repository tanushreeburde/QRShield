from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite+aiosqlite:///./qrshield.db"
    REQUEST_TIMEOUT_SECONDS: float = 6.0
    CONNECT_TIMEOUT_SECONDS: float = 3.0
    MAX_REDIRECT_HOPS: int = 8
    MAX_RESPONSE_BYTES: int = 1048576  # 1 MB
    RATE_LIMIT_PER_MINUTE: int = 30
    SAFE_BROWSING_API_KEY: Optional[str] = None
    WHOIS_LOOKUP_ENABLED: bool = True
    WHOIS_TIMEOUT_SECONDS: float = 2.0  # Reduced for faster scans
    OCR_ENABLED: bool = False
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
