"""
FastAPI dependency that verifies a JWT and returns the caller's verified
identity -- most importantly, graph_tenant_id, which endpoints should use
INSTEAD OF trusting a client-supplied tenant_id query parameter.

This is the actual fix for the multi-tenancy gap: previously any caller
could pass ?tenant_id=whatever and see that tenant's data. With this
dependency in place, the tenant comes from a verified, signed token that
only the server issued at login -- a client cannot forge or change it
without a valid credential for that tenant.
"""
from fastapi import Header, HTTPException, status
from typing import Optional
from jose import JWTError

from app.auth.security import decode_access_token


class CurrentUser:
    def __init__(self, user_id: str, tenant_id: str, graph_tenant_id: str, role: str):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.graph_tenant_id = graph_tenant_id
        self.role = role


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> CurrentUser:
    """
    Expects header: Authorization: Bearer <token>
    Raises 401 if missing, malformed, or the token is invalid/expired.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: Bearer <token>",
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    return CurrentUser(
        user_id=payload["sub"],
        tenant_id=payload["tenant_id"],
        graph_tenant_id=payload["graph_tenant_id"],
        role=payload.get("role", "member"),
    )
