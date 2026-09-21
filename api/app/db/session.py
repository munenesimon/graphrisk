"""
Async SQLAlchemy engine and session factory for PostgreSQL.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings

engine = create_async_engine(settings.postgres_url, echo=False, future=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db():
    """FastAPI dependency: yields an async DB session, closed automatically after the request."""
    async with AsyncSessionLocal() as session:
        yield session
