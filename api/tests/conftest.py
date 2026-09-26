"""
Shared pytest fixtures for the GraphRisk API test suite.

Design notes (read before adding a new test):

- Test-only environment variables are set at IMPORT time of this file,
  before any `app.*` module is imported anywhere -- app.config.Settings()
  reads SECRET_KEY/POSTGRES_URL etc. from the environment once, at import
  time, so they must exist before that first import happens. Never real
  secrets; CI provides none of these, this file is the only source.

- GRAPHRISK_API_KEY is deliberately left unset, which makes verify_api_key
  a no-op (see app/auth/api_key.py) -- exactly like local dev. Tests that
  care about the API key gate set/unset it explicitly.

- graphrisk_core is munenesimon's separate, private package (see the
  comment in app/graph/queries.py) -- it holds the actual Cypher query
  text and isn't installable here or in CI. Every route only ever does
  `queries.SOME_NAME` (attribute access) and hands the result straight to
  run_query/run_write, which every test replaces with a fake anyway -- so
  the *value* of a query constant never matters in this suite. We stand
  in a fake `graphrisk_core.queries` module (so the real
  `app/graph/queries.py`'s `from graphrisk_core.queries import *` doesn't
  explode on import) and give the real `app.graph.queries` module a
  `__getattr__` fallback so `queries.ANYTHING` returns a placeholder
  string instead of raising AttributeError.

- run_query/run_write are imported with `from app.graph.connection import
  run_query, run_write` at the top of most router modules, so patching
  `app.graph.connection.run_query` alone would NOT affect a module that
  already bound its own reference at import time. `fake_graph` patches
  every module that imports them individually. The one exception is
  `CheckRegistry._write_to_graph`, which does that import *inside the
  method body* -- so patching the connection module itself is exactly
  right for that one case, and it doubles as harmless belt-and-suspenders
  for anything imported after this fixture runs.
"""
import importlib
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

# Make `app` importable regardless of the cwd pytest was invoked from.
API_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API_ROOT))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-only-not-a-real-secret")
os.environ.setdefault("POSTGRES_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password-not-real")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.pop("GRAPHRISK_API_KEY", None)

# ── Stand in for the private graphrisk_core package (see docstring) ─────────
if "graphrisk_core" not in sys.modules:
    _stub_queries = types.ModuleType("graphrisk_core.queries")
    _stub_core = types.ModuleType("graphrisk_core")
    _stub_core.queries = _stub_queries
    sys.modules["graphrisk_core"] = _stub_core
    sys.modules["graphrisk_core.queries"] = _stub_queries

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.main import app
from app.graph import queries as app_queries
from app.db.session import get_db
from app.db.models import Base
from app.auth.jwt_auth import CurrentUser, get_current_user
from app.auth.api_key import verify_api_key

# Any `queries.SOME_NAME` the real code reaches for gets a harmless
# placeholder string instead of AttributeError -- see docstring.
if not hasattr(app_queries, "__getattr__"):
    app_queries.__getattr__ = lambda name: f"<stub query: {name}>"

GRAPH_MODULES = [
    "app.api.v1.assets",
    "app.api.v1.blast_radius",
    "app.api.v1.connectors",
    "app.api.v1.controls",
    "app.api.v1.dashboard",
    "app.api.v1.frameworks",
    "app.api.v1.organisation",
    "app.api.v1.risks",
    "app.connectors.registry",
    "app.graph.connection",
]


@pytest.fixture(autouse=True)
def _default_dns_resolves_to_a_public_address(monkeypatch):
    """
    Keeps the whole suite hermetic and independent of the runner's actual
    network access. Every adapter test hits real-looking vendor hostnames
    (api.crowdstrike.com, login.microsoftonline.com, ...) through the
    `responses` library, which intercepts the HTTP call itself -- but
    _assert_safe_url()'s SSRF guard still does a real DNS lookup before
    that ever happens, and a sandbox/CI runner without DNS would fail
    every connector test on that alone. A test that wants to exercise the
    guard's *rejection* behavior (private/loopback/etc targets) patches
    `app.connectors.base.socket.getaddrinfo` itself within its own `with`
    block, which simply overrides this default for that scope.
    """
    import socket as _socket

    def _fake(host, *a, **kw):
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr("app.connectors.base.socket.getaddrinfo", _fake)


@pytest.fixture
def client():
    """A plain TestClient. Startup calls get_graph_client(), which only
    constructs a neo4j.Driver object (lazy -- no real connection happens
    until a session actually runs a query), so this stays fully offline."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake_graph(monkeypatch):
    """
    Replaces run_query/run_write with in-memory fakes everywhere a route
    or the registry can reach them. Returns a namespace with `.query` and
    `.write` Mocks -- set `.return_value`, or a `.side_effect` list/callable,
    from the test.
    """
    fake_run_query = MagicMock(return_value=[])
    fake_run_write = MagicMock(return_value=[])
    for mod_path in GRAPH_MODULES:
        mod = importlib.import_module(mod_path)
        if hasattr(mod, "run_query"):
            monkeypatch.setattr(mod, "run_query", fake_run_query)
        if hasattr(mod, "run_write"):
            monkeypatch.setattr(mod, "run_write", fake_run_write)
    return SimpleNamespace(query=fake_run_query, write=fake_run_write)


def make_current_user(tenant_id="tenant-1", graph_tenant_id="demo", role="owner", user_id="user-1"):
    return CurrentUser(user_id=user_id, tenant_id=tenant_id, graph_tenant_id=graph_tenant_id, role=role)


@pytest.fixture
def as_user():
    """
    Overrides get_current_user with a fixed identity -- for any
    authenticated-endpoint test that doesn't need to exercise the real
    JWT decode path end to end (test_auth.py does that separately).
    Call it with role="member"/"admin"/"owner" etc. as needed; defaults
    to an "owner" on tenant "demo".
    """
    installed = {}

    def _set(role="owner", graph_tenant_id="demo", tenant_id="tenant-1", user_id="user-1"):
        user = make_current_user(tenant_id, graph_tenant_id, role, user_id)
        app.dependency_overrides[get_current_user] = lambda: user
        installed["user"] = user
        return user

    yield _set
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def no_api_key(monkeypatch):
    """Explicitly disables the X-API-Key gate (verify_api_key is already a
    no-op whenever GRAPHRISK_API_KEY is unset -- this fixture documents the
    intent at the call site and survives someone setting the env var
    elsewhere in the session)."""
    app.dependency_overrides[verify_api_key] = lambda: None
    yield
    app.dependency_overrides.pop(verify_api_key, None)


@pytest_asyncio.fixture
async def db_session():
    """
    A fresh in-memory SQLite database per test, standing in for Postgres.
    Verified directly against the real models (including the
    postgresql-dialect UUID column type, which SQLAlchemy compiles
    generically under SQLite without any changes needed).
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def client_with_db(db_session):
    """A TestClient with get_db overridden to the in-memory database, for
    the auth register/login integration tests."""

    async def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)
