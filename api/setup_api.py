"""
GraphRisk API — Setup Script
Run this once to create the project structure with correct encoding.
Usage: python setup_api.py
"""
import os
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))


def write(rel_path, content):
    full = os.path.join(BASE, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Written: {rel_path}")


# ── app/__init__.py ───────────────────────────────────────────────────────────
write("app/__init__.py", "# GraphRisk API\n")
write("app/api/__init__.py", "# API\n")
write("app/api/v1/__init__.py", "# API v1 routers\n")
write("app/graph/__init__.py", "# Graph module\n")
write("app/db/__init__.py", "# DB module\n")
write("app/schemas/__init__.py", "# Schemas\n")
write("app/services/__init__.py", "# Services\n")
write("app/auth/__init__.py", "# Auth\n")

# ── app/config.py ─────────────────────────────────────────────────────────────
write("app/config.py", '''from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    neo4j_uri:      str = "bolt://localhost:7687"
    neo4j_user:     str = "neo4j"
    neo4j_password: str = "graphrisk_dev"
    postgres_url:   str = "postgresql+asyncpg://graphrisk:graphrisk_dev@localhost/graphrisk"
    secret_key:     str = "graphrisk-dev-secret-key"
    algorithm:      str = "HS256"
    access_token_expire_minutes: int = 60
    environment:    str = "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
''')

# ── app/graph/connection.py ───────────────────────────────────────────────────
write("app/graph/connection.py", '''from neo4j import GraphDatabase
from app.config import settings

_driver = None

def get_graph_client():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
    return _driver

def close_graph_client():
    global _driver
    if _driver:
        _driver.close()
        _driver = None

def run_query(query: str, params: dict = None):
    driver = get_graph_client()
    with driver.session() as session:
        result = session.run(query, params or {})
        return result.data()

def run_write(query: str, params: dict = None):
    driver = get_graph_client()
    with driver.session() as session:
        result = session.run(query, params or {})
        return result.data()
''')

# ── app/graph/queries.py ──────────────────────────────────────────────────────
write("app/graph/queries.py", '''# All Cypher queries

GET_ALL_ASSETS = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    RETURN a.id AS id, a.name AS name, a.asset_type AS asset_type,
           a.criticality AS criticality, a.owner AS owner, a.environment AS environment
    ORDER BY a.criticality, a.name
"""

GET_ASSET_BY_ID = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (v:Vulnerability)-[:EXPOSES]->(a)
    RETURN a.id AS id, a.name AS name, a.asset_type AS asset_type,
           a.criticality AS criticality, a.owner AS owner, a.environment AS environment,
           collect(DISTINCT bp.name) AS business_processes,
           collect(DISTINCT v.cve_id)[..5] AS recent_vulnerabilities
"""

CREATE_ASSET = """
    CREATE (a:Asset {
        id: $id, name: $name, asset_type: $asset_type,
        criticality: $criticality, owner: $owner,
        environment: $environment, tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN a.id AS id
"""

GET_ALL_RISKS = """
    MATCH (r:Risk {tenant_id: $tenant_id})
    RETURN r.id AS id, r.title AS title, r.likelihood AS likelihood,
           r.impact AS impact, r.risk_score AS risk_score,
           r.status AS status, r.owner AS owner
    ORDER BY r.risk_score DESC
"""

GET_RISK_BY_ID = """
    MATCH (r:Risk {id: $risk_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    OPTIONAL MATCH (r)-[:IMPACTS]->(a:Asset)
    RETURN r.id AS id, r.title AS title, r.description AS description,
           r.likelihood AS likelihood, r.impact AS impact,
           r.risk_score AS risk_score, r.status AS status,
           collect(DISTINCT c.title) AS mitigating_controls,
           collect(DISTINCT a.name)  AS affected_assets
"""

CREATE_RISK = """
    CREATE (r:Risk {
        id: $id, title: $title, description: $description,
        likelihood: $likelihood, impact: $impact, risk_score: $risk_score,
        status: $status, owner: $owner, tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN r.id AS id
"""

GET_ALL_CONTROLS = """
    MATCH (c:Control {tenant_id: $tenant_id})
    RETURN c.id AS id, c.title AS title, c.control_type AS control_type,
           c.implementation_status AS implementation_status,
           c.effectiveness_score AS effectiveness_score,
           c.owner AS owner, c.last_tested_at AS last_tested_at
    ORDER BY c.implementation_status, c.title
"""

GET_CONTROL_BY_ID = """
    MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
    OPTIONAL MATCH (c)-[:SATISFIES]->(fc:FrameworkControl)-[:PART_OF]->(f:Framework)
    OPTIONAL MATCH (e:Evidence)-[:VALIDATES]->(c)
    RETURN c.id AS id, c.title AS title, c.description AS description,
           c.control_type AS control_type,
           c.implementation_status AS implementation_status,
           c.effectiveness_score AS effectiveness_score, c.owner AS owner,
           collect(DISTINCT r.title) AS risks_mitigated,
           collect(DISTINCT f.name)  AS frameworks_covered,
           collect(DISTINCT e.title) AS evidence_items
"""

CREATE_CONTROL = """
    CREATE (c:Control {
        id: $id, title: $title, description: $description,
        control_type: $control_type, implementation_status: $implementation_status,
        effectiveness_score: $effectiveness_score, owner: $owner,
        tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN c.id AS id
"""

GET_ALL_FRAMEWORKS = """
    MATCH (f:Framework)
    OPTIONAL MATCH (fc:FrameworkControl)-[:PART_OF]->(f)
    RETURN f.id AS id, f.name AS name, f.version AS version,
           f.owner AS owner, f.url AS url, count(fc) AS total_controls
    ORDER BY f.name
"""

GET_FRAMEWORK_CONTROLS = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id: $framework_id})
    RETURN fc.id AS id, fc.control_reference AS control_reference,
           fc.title AS title, fc.domain AS domain,
           fc.graphrisk_summary AS summary, fc.official_url AS official_url
    ORDER BY fc.control_reference
"""

GET_FRAMEWORK_COVERAGE = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id: $framework_id})
    OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})-[:SATISFIES]->(fc)
    RETURN f.name AS framework, count(fc) AS total_controls,
           count(c) AS covered_controls,
           round(toFloat(count(c)) / count(fc) * 100, 1) AS coverage_pct
"""

BLAST_RADIUS_CONTROL = """
    MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
    OPTIONAL MATCH (r)-[:IMPACTS]->(a:Asset)
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (c)-[:SATISFIES]->(fc:FrameworkControl)-[:PART_OF]->(f:Framework)
    RETURN c.title AS control_title, c.implementation_status AS control_status,
           c.effectiveness_score AS effectiveness_score,
           collect(DISTINCT r.title)  AS exposed_risks,
           collect(DISTINCT a.name)   AS affected_assets,
           collect(DISTINCT bp.name)  AS impacted_processes,
           collect(DISTINCT f.name)   AS compliance_gaps,
           collect(DISTINCT fc.control_reference) AS framework_controls,
           size(collect(DISTINCT r))  AS risk_count,
           size(collect(DISTINCT a))  AS asset_count,
           size(collect(DISTINCT f))  AS framework_count
"""

BLAST_RADIUS_TECHNIQUE = """
    MATCH (tech:Technique {technique_id: $technique_id})
    OPTIONAL MATCH (tech)-[:MITIGATES]->(fc:FrameworkControl)
    OPTIONAL MATCH (fc)-[:PART_OF]->(f:Framework)
    RETURN tech.name AS technique_name, tech.technique_id AS technique_id,
           collect(DISTINCT fc.control_reference) AS controls_mitigated,
           collect(DISTINCT f.name) AS frameworks_covered,
           size(collect(DISTINCT fc)) AS control_count,
           size(collect(DISTINCT f))  AS framework_count
"""

VENDOR_BREACH_CASCADE = """
    MATCH (v:Vendor {id: $vendor_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (v)-[:PROVIDES]->(a:Asset)
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (r:Risk)-[:IMPACTS]->(a)
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    WHERE c.implementation_status <> "Implemented"
    RETURN v.name AS vendor_name,
           collect(DISTINCT a.name)  AS exposed_assets,
           collect(DISTINCT bp.name) AS impacted_processes,
           collect(DISTINCT r.title) AS activated_risks,
           collect(DISTINCT c.title) AS missing_controls,
           size(collect(DISTINCT a)) AS asset_count,
           size(collect(DISTINCT r)) AS risk_count
"""

DASHBOARD_SUMMARY = """
    OPTIONAL MATCH (r:Risk {tenant_id: $tenant_id})
    OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})
    OPTIONAL MATCH (a:Asset {tenant_id: $tenant_id})
    RETURN count(DISTINCT r) AS total_risks, count(DISTINCT c) AS total_controls,
           count(DISTINCT a) AS total_assets, avg(r.risk_score) AS avg_risk_score,
           sum(CASE WHEN r.status = "Open" THEN 1 ELSE 0 END) AS open_risks,
           sum(CASE WHEN c.implementation_status = "Implemented" THEN 1 ELSE 0 END) AS implemented_controls
"""

TOP_RISKS = """
    MATCH (r:Risk {tenant_id: $tenant_id, status: "Open"})
    RETURN r.id AS id, r.title AS title, r.risk_score AS risk_score,
           r.likelihood AS likelihood, r.impact AS impact
    ORDER BY r.risk_score DESC LIMIT 5
"""

VULNERABILITY_STATS = """
    MATCH (v:Vulnerability)
    RETURN v.source AS source, count(v) AS total,
           sum(CASE WHEN v.ransomware_use = "Known" THEN 1 ELSE 0 END) AS ransomware_count
    ORDER BY total DESC
"""
''')

# ── app/main.py ───────────────────────────────────────────────────────────────
write("app/main.py", '''from fastapi import FastAPI
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
''')

# ── app/api/v1/assets.py ──────────────────────────────────────────────────────
write("app/api/v1/assets.py", '''from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import uuid
from app.graph.connection import run_query, run_write
from app.graph import queries

router = APIRouter()

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    criticality: str = "Medium"
    owner: str = ""
    environment: str = "Production"

@router.get("/")
async def list_assets(tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_ALL_ASSETS, {"tenant_id": tenant_id})
    return {"assets": result, "total": len(result)}

@router.get("/{asset_id}")
async def get_asset(asset_id: str, tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_ASSET_BY_ID, {"asset_id": asset_id, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return result[0]

@router.post("/", status_code=201)
async def create_asset(asset: AssetCreate, tenant_id: str = Query(default="demo")):
    asset_id = str(uuid.uuid4())
    run_write(queries.CREATE_ASSET, {
        "id": asset_id, "name": asset.name, "asset_type": asset.asset_type,
        "criticality": asset.criticality, "owner": asset.owner,
        "environment": asset.environment, "tenant_id": tenant_id,
    })
    return {"id": asset_id, "message": "Asset created", "name": asset.name}

@router.post("/{asset_id}/link-vulnerability")
async def link_vulnerability(asset_id: str, cve_id: str = Query(), tenant_id: str = Query(default="demo")):
    result = run_write("""
        MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (v)-[:EXPOSES]->(a)
        RETURN a.name AS asset, v.cve_id AS cve_id
    """, {"asset_id": asset_id, "tenant_id": tenant_id, "cve_id": cve_id})
    if not result:
        raise HTTPException(status_code=404, detail="Asset or vulnerability not found")
    return {"message": "Vulnerability linked", "data": result[0]}

@router.post("/{asset_id}/link-risk")
async def link_risk(asset_id: str, risk_id: str = Query(), tenant_id: str = Query(default="demo")):
    result = run_write("""
        MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
        MATCH (r:Risk {id: $risk_id, tenant_id: $tenant_id})
        MERGE (r)-[:IMPACTS]->(a)
        RETURN r.title AS risk, a.name AS asset
    """, {"asset_id": asset_id, "risk_id": risk_id, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Asset or risk not found")
    return {"message": "Risk linked to asset", "data": result[0]}
''')

# ── app/api/v1/risks.py ───────────────────────────────────────────────────────
write("app/api/v1/risks.py", '''from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import uuid
from app.graph.connection import run_query, run_write
from app.graph import queries

router = APIRouter()

class RiskCreate(BaseModel):
    title: str
    description: str = ""
    likelihood: int
    impact: int
    owner: str = ""
    status: str = "Open"

@router.get("/")
async def list_risks(tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_ALL_RISKS, {"tenant_id": tenant_id})
    return {"risks": result, "total": len(result)}

@router.get("/{risk_id}")
async def get_risk(risk_id: str, tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_RISK_BY_ID, {"risk_id": risk_id, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return result[0]

@router.post("/", status_code=201)
async def create_risk(risk: RiskCreate, tenant_id: str = Query(default="demo")):
    risk_id = str(uuid.uuid4())
    run_write(queries.CREATE_RISK, {
        "id": risk_id, "title": risk.title, "description": risk.description,
        "likelihood": risk.likelihood, "impact": risk.impact,
        "risk_score": risk.likelihood * risk.impact,
        "status": risk.status, "owner": risk.owner, "tenant_id": tenant_id,
    })
    return {"id": risk_id, "message": "Risk created", "risk_score": risk.likelihood * risk.impact}

@router.post("/{risk_id}/link-control")
async def link_control(risk_id: str, control_id: str = Query(), effectiveness: float = Query(default=0.8), tenant_id: str = Query(default="demo")):
    result = run_write("""
        MATCH (r:Risk {id: $risk_id, tenant_id: $tenant_id})
        MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
        MERGE (c)-[m:MITIGATES]->(r)
        SET m.effectiveness = $effectiveness
        RETURN c.title AS control, r.title AS risk
    """, {"risk_id": risk_id, "control_id": control_id, "effectiveness": effectiveness, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Risk or control not found")
    return {"message": "Control linked to risk", "data": result[0]}
''')

# ── app/api/v1/controls.py ────────────────────────────────────────────────────
write("app/api/v1/controls.py", '''from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import uuid
from app.graph.connection import run_query, run_write
from app.graph import queries

router = APIRouter()

class ControlCreate(BaseModel):
    title: str
    description: str = ""
    control_type: str = "Preventive"
    implementation_status: str = "Planned"
    effectiveness_score: float = 0.0
    owner: str = ""

@router.get("/")
async def list_controls(tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_ALL_CONTROLS, {"tenant_id": tenant_id})
    return {"controls": result, "total": len(result)}

@router.get("/{control_id}")
async def get_control(control_id: str, tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_CONTROL_BY_ID, {"control_id": control_id, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return result[0]

@router.post("/", status_code=201)
async def create_control(control: ControlCreate, tenant_id: str = Query(default="demo")):
    control_id = str(uuid.uuid4())
    run_write(queries.CREATE_CONTROL, {
        "id": control_id, "title": control.title, "description": control.description,
        "control_type": control.control_type, "implementation_status": control.implementation_status,
        "effectiveness_score": control.effectiveness_score, "owner": control.owner, "tenant_id": tenant_id,
    })
    return {"id": control_id, "message": "Control created"}

@router.patch("/{control_id}/status")
async def update_status(control_id: str, status: str = Query(), effectiveness: float = Query(default=None), tenant_id: str = Query(default="demo")):
    eff_map = {"Implemented": 1.0, "PartiallyImplemented": 0.5, "Planned": 0.2, "NotImplemented": 0.0}
    eff = effectiveness if effectiveness is not None else eff_map.get(status, 0.0)
    result = run_write("""
        MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
        SET c.implementation_status = $status, c.effectiveness_score = $eff, c.updated_at = datetime()
        WITH c
        OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
        SET r.risk_score = r.likelihood * r.impact * (1.0 - $eff)
        RETURN c.title AS control, count(r) AS risks_updated
    """, {"control_id": control_id, "tenant_id": tenant_id, "status": status, "eff": eff})
    if not result:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return {"message": "Status updated", "new_status": status, "effectiveness": eff, "risks_updated": result[0]["risks_updated"]}

@router.post("/{control_id}/link-framework-control")
async def link_framework(control_id: str, framework_control_ref: str = Query(), tenant_id: str = Query(default="demo")):
    result = run_write("""
        MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
        MATCH (fc:FrameworkControl {control_reference: $ref})
        MERGE (c)-[:SATISFIES]->(fc)
        RETURN c.title AS control, fc.control_reference AS ref
    """, {"control_id": control_id, "tenant_id": tenant_id, "ref": framework_control_ref})
    if not result:
        raise HTTPException(status_code=404, detail="Control or framework control not found")
    return {"message": "Framework control linked", "data": result[0]}
''')

# ── app/api/v1/frameworks.py ──────────────────────────────────────────────────
write("app/api/v1/frameworks.py", '''from fastapi import APIRouter, HTTPException, Query
from app.graph.connection import run_query
from app.graph import queries

router = APIRouter()

@router.get("/")
async def list_frameworks():
    result = run_query(queries.GET_ALL_FRAMEWORKS, {})
    return {"frameworks": result, "total": len(result)}

@router.get("/{framework_id}/controls")
async def get_framework_controls(framework_id: str, domain: str = Query(default=None)):
    result = run_query(queries.GET_FRAMEWORK_CONTROLS, {"framework_id": framework_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    if domain:
        result = [r for r in result if domain.lower() in (r.get("domain") or "").lower()]
    return {"framework_id": framework_id, "controls": result, "total": len(result)}

@router.get("/{framework_id}/coverage")
async def get_coverage(framework_id: str, tenant_id: str = Query(default="demo")):
    result = run_query(queries.GET_FRAMEWORK_COVERAGE, {"framework_id": framework_id, "tenant_id": tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    return result[0]

@router.get("/search/controls")
async def search_controls(q: str = Query(), framework_id: str = Query(default=None)):
    result = run_query("""
        MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework)
        WHERE toLower(fc.control_reference) CONTAINS toLower($q)
           OR toLower(fc.title) CONTAINS toLower($q)
        WITH fc, f WHERE $framework_id IS NULL OR f.id = $framework_id
        RETURN fc.control_reference AS control_reference, fc.title AS title,
               fc.domain AS domain, fc.graphrisk_summary AS summary, f.name AS framework
        ORDER BY fc.control_reference LIMIT 20
    """, {"q": q, "framework_id": framework_id})
    return {"results": result, "total": len(result)}

@router.get("/technique/{technique_id}/controls")
async def controls_for_technique(technique_id: str):
    result = run_query("""
        MATCH (tech:Technique {technique_id: $tid})-[:MITIGATES]->(fc:FrameworkControl)-[:PART_OF]->(f:Framework)
        RETURN tech.name AS technique, fc.control_reference AS control_reference,
               fc.title AS control_title, fc.graphrisk_summary AS summary, f.name AS framework
        ORDER BY f.name, fc.control_reference
    """, {"tid": technique_id.upper()})
    if not result:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return {"technique_id": technique_id.upper(), "technique": result[0]["technique"], "controls": result, "total": len(result)}
''')

# ── app/api/v1/blast_radius.py ────────────────────────────────────────────────
write("app/api/v1/blast_radius.py", '''from fastapi import APIRouter, HTTPException, Query
from app.graph.connection import run_query
from app.graph import queries

router = APIRouter()

@router.get("/blast-radius/control/{control_id}")
async def blast_radius_control(control_id: str, tenant_id: str = Query(default="demo")):
    result = run_query(queries.BLAST_RADIUS_CONTROL, {"control_id": control_id, "tenant_id": tenant_id})
    if not result or not result[0].get("control_title"):
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    row = result[0]
    return {
        "control_id": control_id, "control_title": row["control_title"],
        "control_status": row["control_status"], "effectiveness_score": row["effectiveness_score"],
        "blast_radius": {
            "exposed_risks": row["exposed_risks"], "affected_assets": row["affected_assets"],
            "impacted_processes": row["impacted_processes"], "compliance_gaps": row["compliance_gaps"],
            "framework_controls": row["framework_controls"],
        },
        "summary": {"risk_count": row["risk_count"], "asset_count": row["asset_count"], "framework_count": row["framework_count"]}
    }

@router.get("/blast-radius/technique/{technique_id}")
async def blast_radius_technique(technique_id: str):
    result = run_query(queries.BLAST_RADIUS_TECHNIQUE, {"technique_id": technique_id.upper()})
    if not result or not result[0].get("technique_name"):
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    row = result[0]
    return {
        "technique_id": row["technique_id"], "technique_name": row["technique_name"],
        "controls_mitigated": row["controls_mitigated"], "frameworks_covered": row["frameworks_covered"],
        "summary": {"control_count": row["control_count"], "framework_count": row["framework_count"]}
    }

@router.get("/technique-coverage")
async def technique_coverage(technique_ids: str = Query(description="Comma-separated ATT&CK IDs e.g. T1078,T1110")):
    ids = [t.strip().upper() for t in technique_ids.split(",")]
    results = []
    for tid in ids:
        rows = run_query(queries.BLAST_RADIUS_TECHNIQUE, {"technique_id": tid})
        if rows and rows[0].get("technique_name"):
            row = rows[0]
            results.append({
                "technique_id": row["technique_id"], "technique_name": row["technique_name"],
                "control_count": row["control_count"], "controls": row["controls_mitigated"],
            })
    return {"techniques_queried": len(ids), "techniques_found": len(results), "results": results}
''')

# ── app/api/v1/dashboard.py ───────────────────────────────────────────────────
write("app/api/v1/dashboard.py", '''from fastapi import APIRouter, Query
from app.graph.connection import run_query
from app.graph import queries

router = APIRouter()

@router.get("/summary")
async def dashboard_summary(tenant_id: str = Query(default="demo")):
    result   = run_query(queries.DASHBOARD_SUMMARY, {"tenant_id": tenant_id})
    top      = run_query(queries.TOP_RISKS, {"tenant_id": tenant_id})
    vulns    = run_query(queries.VULNERABILITY_STATS, {})
    summary  = result[0] if result else {}
    return {
        "tenant_id": tenant_id,
        "risks":    {"total": summary.get("total_risks",0), "open": summary.get("open_risks",0), "avg_score": round(summary.get("avg_risk_score") or 0,2), "top_risks": top},
        "controls": {"total": summary.get("total_controls",0), "implemented": summary.get("implemented_controls",0)},
        "assets":   {"total": summary.get("total_assets",0)},
        "vulnerabilities": {"by_source": vulns}
    }

@router.get("/graph-stats")
async def graph_stats():
    nodes = run_query("MATCH (n) RETURN labels(n)[0] AS type, count(n) AS total ORDER BY total DESC", {})
    rels  = run_query("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS total ORDER BY total DESC", {})
    return {"nodes": nodes, "relationships": rels, "total_nodes": sum(r["total"] for r in nodes), "total_edges": sum(r["total"] for r in rels)}

@router.get("/vulnerability-intel")
async def vulnerability_intel():
    stats = run_query("""
        MATCH (v:Vulnerability)
        WITH v.source AS source, count(v) AS total,
             sum(CASE WHEN v.ransomware_use = "Known" THEN 1 ELSE 0 END) AS ransomware,
             max(v.last_synced_at) AS last_sync
        RETURN source, total, ransomware, last_sync ORDER BY total DESC
    """, {})
    recent = run_query("""
        MATCH (v:Vulnerability {source:"CISA_KEV", ransomware_use:"Known"})
        RETURN v.cve_id AS cve_id, v.title AS title, v.vendor AS vendor,
               v.product AS product, v.date_added AS date_added
        ORDER BY v.date_added DESC LIMIT 10
    """, {})
    return {"vulnerability_sources": stats, "recent_ransomware_kev": recent}

@router.get("/framework-coverage")
async def framework_coverage(tenant_id: str = Query(default="demo")):
    result = run_query("""
        MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework)
        OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})-[:SATISFIES]->(fc)
        RETURN f.id AS framework_id, f.name AS framework, f.version AS version,
               count(fc) AS total_controls, count(c) AS covered_controls,
               round(toFloat(count(c)) / count(fc) * 100, 1) AS coverage_pct
        ORDER BY coverage_pct DESC
    """, {"tenant_id": tenant_id})
    return {"frameworks": result}
''')

print("\n" + "="*55)
print("  GraphRisk API — All files created successfully")
print("="*55)
print("\n  Start the API:")
print("  uvicorn app.main:app --reload --port 8000")
print("\n  Open API docs:")
print("  http://localhost:8000/docs")
print("="*55)
