"""
Pydantic request/response models for the auth endpoints.
"""
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    tenant_name: str = Field(min_length=1, max_length=200)
    # graph_tenant_id: the short string used inside Neo4j node properties.
    # Defaults to a slugified version of tenant_name if not provided.
    graph_tenant_id: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    graph_tenant_id: str
    role: str
    # True for the shared public demo: everything is viewable, nothing can
    # be changed through the API (see app/auth/read_only.py). Lets the UI
    # say so up front instead of only after a refused save.
    read_only: bool = False
