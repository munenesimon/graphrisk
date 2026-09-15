from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.graph.connection import get_graph_client, close_graph_client
from app.api.v1 import assets, risks, controls, frameworks, blast_radius, dashboard

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_graph_client()
    print("GraphRisk API started — Neo4j connected")
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

app.include_router(assets.router,       prefix="/api/v1/assets",    tags=["Assets"])
app.include_router(risks.router,        prefix="/api/v1/risks",     tags=["Risks"])
app.include_router(controls.router,     prefix="/api/v1/controls",  tags=["Controls"])
app.include_router(frameworks.router,   prefix="/api/v1/frameworks",tags=["Frameworks"])
app.include_router(blast_radius.router, prefix="/api/v1/graph",     tags=["Graph Intelligence"])
app.include_router(dashboard.router,    prefix="/api/v1/dashboard", tags=["Dashboard"])

@app.get("/")
async def root():
    return {"platform": "GraphRisk Intelligence Platform", "version": "1.0.0", "status": "running", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
