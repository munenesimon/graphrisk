from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    neo4j_uri:      str = "bolt://localhost:7687"
    neo4j_user:     str = "neo4j"
    neo4j_password: str = "graphrisk_dev"
    postgres_url:   str = "postgresql+asyncpg://graphrisk:graphrisk_dev@localhost/graphrisk"

    # No insecure default: SECRET_KEY signs every JWT, so a guessable
    # fallback here would let anyone who reads this file (e.g. from a
    # public repo) forge tokens for any tenant. Missing the env var
    # fails startup loudly instead of silently running with a weak key.
    # Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key:     str

    algorithm:      str = "HS256"
    access_token_expire_minutes: int = 60
    environment:    str = "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()