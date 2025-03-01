from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API path and headers.
    api_prefix: str = "/api/v1"
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379

    # OTP and SMS Settings
    SMS_API_KEY: str = ""
    OTP_EXPIRATION_SECONDS: int = 300
    SMS_API: str = ""

    # DB connections
    DATABASE_URL: str

    # JWT Settings
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DJANGO_MOUNTED: bool = True

    # Load .env file
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "allow"  # Allow additional env variables too.


settings = Settings()
