"""
One-time table creation script for the PostgreSQL schema.
Run directly: python -m app.db.init_db

Also seeds a "demo" tenant matching the tenant_id already used throughout
the Neo4j graph, so existing demo data and the new auth system line up
immediately with no migration needed.
"""
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

from app.config import settings
from app.db.models import Base, Tenant


async def init_models():
    engine = create_async_engine(settings.postgres_url, echo=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created.")

    SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as session:
        existing = await session.execute(select(Tenant).where(Tenant.graph_tenant_id == "demo"))
        if existing.scalar_one_or_none() is None:
            demo_tenant = Tenant(name="Demo Organization", graph_tenant_id="demo")
            session.add(demo_tenant)
            await session.commit()
            print(f"Seeded demo tenant: {demo_tenant.id} (graph_tenant_id='demo')")
        else:
            print("Demo tenant already exists.")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(init_models())
