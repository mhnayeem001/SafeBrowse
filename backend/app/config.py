import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    APP_NAME: str = "SafeBrowse X Security Core"
    APP_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "chrome-extension://*",
    ]

    # Database & Cache
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./safebrowse.db")
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CACHE_DEFAULT_TTL: int = 3600  # 1 hour
    DECISION_CACHE_TTL: int = 600  # 10 minutes

    # Security & Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "safebrowse-x-super-secure-production-key-change-in-prod-8837194")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    RATE_LIMIT_PER_MINUTE: int = 120

    # Threat Engine Thresholds
    BLOCK_RISK_THRESHOLD: int = 75
    WARN_RISK_THRESHOLD: int = 40
    CONFIDENCE_THRESHOLD_BLOCK: int = 70
    CONFIDENCE_THRESHOLD_WARN: int = 50

    # Security Modes: NORMAL, STRICT, MAXIMUM
    DEFAULT_SECURITY_MODE: str = "NORMAL"

    # SSRF Protection
    HTTP_TIMEOUT_SECONDS: float = 3.0
    MAX_REDIRECTS: int = 5
    MAX_RESPONSE_BYTES: int = 1_048_576  # 1MB limit for page scans

    # External Threat Intelligence (Optional)
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

settings = Settings()
