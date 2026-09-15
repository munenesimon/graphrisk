from fastapi import APIRouter, HTTPException, Query
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
