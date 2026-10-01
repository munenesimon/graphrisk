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

    # graph_tenant_ids that can be browsed but not changed through the API
    # -- the shared public demo, which every visitor logs into with the same
    # published credentials. Comma-separated; set READ_ONLY_TENANTS="" to
    # disable (e.g. in a local .env while seeding a local demo). Secure by
    # default: forgetting to configure it leaves the demo protected.
    read_only_tenants: str = "demo"

    # When set, a request carrying `X-Maintenance-Token: <this value>` may
    # still write to a read-only tenant -- this is how seed_demo.py reseeds
    # the demo. Empty means no bypass at all.
    maintenance_token: str = ""

    @property
    def read_only_tenant_ids(self) -> set[str]:
        return {t.strip() for t in self.read_only_tenants.split(",") if t.strip()}

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()