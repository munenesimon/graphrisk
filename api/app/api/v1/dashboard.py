from fastapi import APIRouter, Depends
from app.graph.connection import run_query
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

@router.get("/summary")
async def dashboard_summary(user: CurrentUser = Depends(get_current_user)):
    """
    Tenant is taken from the verified JWT (user.graph_tenant_id), NOT from
    a query parameter. A caller can only ever see their own tenant's data.
    """
    tenant_id = user.graph_tenant_id
    risks    = run_query("MATCH (r:Risk {tenant_id: $t}) RETURN count(r) AS total, sum(CASE WHEN r.status = \'Open\' THEN 1 ELSE 0 END) AS open, avg(r.risk_score) AS avg_score", {"t": tenant_id})
    controls = run_query("MATCH (c:Control {tenant_id: $t}) RETURN count(c) AS total, sum(CASE WHEN c.implementation_status = \'Implemented\' THEN 1 ELSE 0 END) AS implemented", {"t": tenant_id})
    assets   = run_query("MATCH (a:Asset {tenant_id: $t}) RETURN count(a) AS total", {"t": tenant_id})
    top      = run_query(queries.TOP_RISKS, {"tenant_id": tenant_id})
    vulns    = run_query(queries.VULNERABILITY_STATS, {})
    r = risks[0]    if risks    else {}
    c = controls[0] if controls else {}
    a = assets[0]   if assets   else {}
    return {
        "tenant_id": tenant_id,
        "risks":    {"total": r.get("total",0), "open": r.get("open",0), "avg_score": round(r.get("avg_score") or 0,2), "top_risks": top},
        "controls": {"total": c.get("total",0), "implemented": c.get("implemented",0)},
        "assets":   {"total": a.get("total",0)},
        "vulnerabilities": {"by_source": vulns}
    }

@router.get("/graph-stats")
async def graph_stats(user: CurrentUser = Depends(get_current_user)):
    """
    Not tenant-scoped -- these are global graph statistics (vulnerability
    counts, framework sizes, etc.) shared across all tenants. Still requires
    a valid JWT so only authenticated users can query it.
    """
    nodes = run_query("MATCH (n) RETURN labels(n)[0] AS type, count(n) AS total ORDER BY total DESC", {})
    rels  = run_query("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS total ORDER BY total DESC", {})
    return {"nodes": nodes, "relationships": rels, "total_nodes": sum(r["total"] for r in nodes), "total_edges": sum(r["total"] for r in rels)}

@router.get("/vulnerability-intel")
async def vulnerability_intel(user: CurrentUser = Depends(get_current_user)):
    """Global threat intelligence -- not tenant-scoped, but still requires a valid JWT."""
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
async def framework_coverage(user: CurrentUser = Depends(get_current_user)):
    """
    Tenant is taken from the verified JWT (user.graph_tenant_id), NOT from
    a query parameter.
    """
    tenant_id = user.graph_tenant_id
    result = run_query("""
        MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework)
        OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})-[:SATISFIES]->(fc)
        RETURN f.id AS framework_id, f.name AS framework, f.version AS version,
               count(fc) AS total_controls, count(c) AS covered_controls,
               round(toFloat(count(c)) / count(fc) * 100, 1) AS coverage_pct
        ORDER BY coverage_pct DESC
    """, {"tenant_id": tenant_id})
    return {"frameworks": result}
