"""
Keeps the shared public demo tenant read-only.

Everyone who tries GraphRisk logs into the same demo account with the same
published credentials, as an owner. Without this, any visitor could save
their own connector credentials into that shared tenant (which the next
visitor could then run), trigger connector runs, or change the data every
other visitor sees. Reads stay fully open; anything that changes state is
refused with a pointer to registering a free account of their own.

Applied as a router-level dependency on every router except /auth (login
and register must keep working). Every route on those routers already
depends on get_current_user, so depending on it here adds no new
requirement -- FastAPI resolves it once per request and shares the result.
"""
import hmac

from fastapi import Depends, HTTPException, Request, status

from app.auth.jwt_auth import CurrentUser, get_current_user
from app.config import settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

READ_ONLY_DETAIL = (
    "This is the shared, read-only demo, so changes are turned off. "
    "Register your own free account to connect tools and make changes."
)


def is_read_only_tenant(graph_tenant_id: str) -> bool:
    return graph_tenant_id in settings.read_only_tenant_ids


async def enforce_read_only_tenants(
    request: Request, user: CurrentUser = Depends(get_current_user)
) -> None:
    if request.method in SAFE_METHODS or not is_read_only_tenant(user.graph_tenant_id):
        return
    expected = settings.maintenance_token
    supplied = request.headers.get("X-Maintenance-Token", "")
    if expected and hmac.compare_digest(supplied.encode(), expected.encode()):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=READ_ONLY_DETAIL)
