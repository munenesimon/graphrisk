"""
Authentication endpoints: register a new tenant + user, and log in.
"""
import re
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db.models import Tenant, User
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse
from app.auth.security import hash_password, verify_password, create_access_token

router = APIRouter()


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "tenant"


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Create a new tenant and its first user (role: owner), then issue a token.
    If graph_tenant_id is omitted, it is derived from tenant_name.
    """
    existing_user = await db.execute(select(User).where(User.email == body.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    graph_tenant_id = body.graph_tenant_id or _slugify(body.tenant_name)

    existing_tenant = await db.execute(select(Tenant).where(Tenant.graph_tenant_id == graph_tenant_id))
    if existing_tenant.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"graph_tenant_id '{graph_tenant_id}' is already in use. Provide a different one.",
        )

    tenant = Tenant(name=body.tenant_name, graph_tenant_id=graph_tenant_id)
    db.add(tenant)
    await db.flush()  # populate tenant.id before creating the user

    user = User(
        tenant_id=tenant.id,
        email=body.email,
        hashed_password=hash_password(body.password),
        role="owner",
    )
    db.add(user)
    await db.commit()

    token = create_access_token(
        user_id=user.id, tenant_id=tenant.id,
        graph_tenant_id=tenant.graph_tenant_id, role=user.role,
    )
    return TokenResponse(
        access_token=token, tenant_id=tenant.id,
        graph_tenant_id=tenant.graph_tenant_id, role=user.role,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    token = create_access_token(
        user_id=user.id, tenant_id=tenant.id,
        graph_tenant_id=tenant.graph_tenant_id, role=user.role,
    )
    return TokenResponse(
        access_token=token, tenant_id=tenant.id,
        graph_tenant_id=tenant.graph_tenant_id, role=user.role,
    )
