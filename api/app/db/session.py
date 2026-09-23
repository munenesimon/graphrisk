"""
Async SQLAlchemy engine and session factory for PostgreSQL.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings

# pool_pre_ping + pool_recycle work around Neon's serverless Postgres closing
# idle connections: without these, the second request after any idle period
# fails with asyncpg.exceptions._base.InterfaceError: connection is closed.
engine = create_async_engine(
    settings.postgres_url,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_recycle=280,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db():
    """FastAPI dependency: yields an async DB session, closed automatically after the request."""
    async with AsyncSessionLocal() as session:
        yield session
