from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    neo4j_uri:      str = "bolt://localhost:7687"
    neo4j_user:     str = "neo4j"
    neo4j_password: str = "graphrisk_dev"

    # No default -- must be set via POSTGRES_URL env var.
    # Local dev: set in .env file.
    # Production: set in Render's environment variables.
    postgres_url:   str

    # No default -- must be set via SECRET_KEY env var.
    secret_key:     str

    algorithm:      str = "HS256"
    access_token_expire_minutes: int = 60
    environment:    str = "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()