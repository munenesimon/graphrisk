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
    risks    = run_query(queries.DASHBOARD_RISKS_SUMMARY, {"t": tenant_id})
    controls = run_query(queries.DASHBOARD_CONTROLS_SUMMARY, {"t": tenant_id})
    assets   = run_query(queries.DASHBOARD_ASSETS_SUMMARY, {"t": tenant_id})
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
    nodes = run_query(queries.GRAPH_STATS_NODES, {})
    rels  = run_query(queries.GRAPH_STATS_RELATIONSHIPS, {})
    return {"nodes": nodes, "relationships": rels, "total_nodes": sum(r["total"] for r in nodes), "total_edges": sum(r["total"] for r in rels)}

@router.get("/vulnerability-intel")
async def vulnerability_intel(user: CurrentUser = Depends(get_current_user)):
    """Global threat intelligence -- not tenant-scoped, but still requires a valid JWT."""
    stats = run_query(queries.VULNERABILITY_INTEL_BY_SOURCE, {})
    recent = run_query(queries.VULNERABILITY_INTEL_RECENT_RANSOMWARE, {})
    return {"vulnerability_sources": stats, "recent_ransomware_kev": recent}

@router.get("/framework-coverage")
async def framework_coverage(user: CurrentUser = Depends(get_current_user)):
    """
    Tenant is taken from the verified JWT (user.graph_tenant_id), NOT from
    a query parameter.
    """
    tenant_id = user.graph_tenant_id
    result = run_query(queries.FRAMEWORK_COVERAGE_ALL, {"tenant_id": tenant_id})
    return {"frameworks": result}
