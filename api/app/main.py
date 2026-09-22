from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.graph.connection import get_graph_client, close_graph_client
from app.api.v1 import assets, risks, controls, frameworks, blast_radius, dashboard, connectors, auth
from app.connectors import setup as connector_setup  # noqa: F401 -- registers adapters on import
from app.auth.api_key import verify_api_key

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_graph_client()
    print("GraphRisk API started \u2014 Neo4j connected")
    print(f"Registered connectors: {connector_setup.registry.registered_connectors}")
    yield
    close_graph_client()
    print("GraphRisk API stopped")

app = FastAPI(
    title="GraphRisk Intelligence Platform",
    description="Graph-based risk intelligence and control validation API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_auth = [Depends(verify_api_key)]

# Auth endpoints are protected by the API key only (not JWT -- you don't have
# a JWT yet until you register/login). Everything else keeps the API key
# gate for now; JWT-based tenant scoping is layered onto individual data
# endpoints incrementally, starting with the ones tested next.
app.include_router(auth.router,         prefix="/api/v1/auth",       tags=["Auth"],       dependencies=_auth)
app.include_router(assets.router,       prefix="/api/v1/assets",     tags=["Assets"],     dependencies=_auth)
app.include_router(risks.router,        prefix="/api/v1/risks",      tags=["Risks"],      dependencies=_auth)
app.include_router(controls.router,     prefix="/api/v1/controls",   tags=["Controls"],   dependencies=_auth)
app.include_router(frameworks.router,   prefix="/api/v1/frameworks", tags=["Frameworks"], dependencies=_auth)
app.include_router(blast_radius.router, prefix="/api/v1/graph",      tags=["Graph Intelligence"], dependencies=_auth)
app.include_router(dashboard.router,    prefix="/api/v1/dashboard",  tags=["Dashboard"],  dependencies=_auth)
app.include_router(connectors.router,   prefix="/api/v1/connectors", tags=["Connectors"], dependencies=_auth)

@app.get("/")
async def root():
    return {"platform": "GraphRisk Intelligence Platform", "version": "1.0.0", "status": "running", "docs": "/docs"}

@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "healthy"}
