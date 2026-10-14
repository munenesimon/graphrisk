from fastapi import APIRouter, Depends
from app.graph.connection import run_query
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

# Health for a control whose status was set by hand and never measured
# (same mapping the controls API uses when a status is chosen).
STATUS_HEALTH = {"Implemented": 1.0, "PartiallyImplemented": 0.5, "Planned": 0.2, "NotImplemented": 0.0}
# A control at or above this health counts as fully working, matching the
# "met" threshold used for framework requirements.
WORKING = 0.95


def _health(row: dict) -> float:
    h = row.get("health")
    if h is None:
        h = STATUS_HEALTH.get(row.get("status") or "", 0.0)
    try:
        h = float(h)
    except (TypeError, ValueError):
        return 0.0
    return min(max(h, 0.0), 1.0)


def summarise_controls(rows: list[dict]) -> dict:
    """The organisation's controls with their current health, plus totals:
    how many are fully working, partly working or not working, and the
    average health across all of them (None when there are no controls)."""
    items = []
    for r in rows:
        h = _health(r)
        state = "working" if h >= WORKING else "partial" if h > 0 else "not_working"
        items.append({
            "id": r.get("id"), "title": r.get("title"), "status": r.get("status"),
            "health": round(h, 4), "state": state,
            "measured": r.get("source") is not None,
            "source": r.get("source"), "detail": r.get("detail"),
            "last_tested_at": r.get("last_tested_at"),
        })
    total = len(items)
    counts = {s: sum(1 for i in items if i["state"] == s) for s in ("working", "partial", "not_working")}
    return {
        "total": total,
        "implemented": sum(1 for r in rows if r.get("status") == "Implemented"),
        **counts,
        "avg_health_pct": round(sum(i["health"] for i in items) / total * 100, 1) if total else None,
        "items": items,
    }

@router.get("/summary")
async def dashboard_summary(user: CurrentUser = Depends(get_current_user)):
    """
    Tenant is taken from the verified JWT (user.graph_tenant_id), NOT from
    a query parameter. A caller can only ever see their own tenant's data.
    """
    tenant_id = user.graph_tenant_id
    risks    = run_query(queries.DASHBOARD_RISKS_SUMMARY, {"t": tenant_id})
    controls = run_query(queries.DASHBOARD_CONTROLS_DETAIL, {"t": tenant_id}) or []
    assets   = run_query(queries.DASHBOARD_ASSETS_SUMMARY, {"t": tenant_id})
    top      = run_query(queries.TOP_RISKS, {"tenant_id": tenant_id})
    vulns    = run_query(queries.VULNERABILITY_STATS, {})
    r = risks[0]    if risks    else {}
    a = assets[0]   if assets   else {}
    return {
        "tenant_id": tenant_id,
        "risks":    {"total": r.get("total",0), "open": r.get("open",0), "avg_score": round(r.get("avg_score") or 0,2), "top_risks": top},
        "controls": summarise_controls(controls),
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
