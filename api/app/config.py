from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    neo4j_uri:      str = "bolt://localhost:7687"
    neo4j_user:     str = "neo4j"
    neo4j_password: str = "graphrisk_dev"
    postgres_url:   str = "postgresql+asyncpg://graphrisk:graphrisk_dev@localhost/graphrisk"
    secret_key:     str = "graphrisk-dev-secret-key"
    algorithm:      str = "HS256"
    access_token_expire_minutes: int = 60
    environment:    str = "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
