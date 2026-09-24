from fastapi import APIRouter, HTTPException, Query, Depends
from app.graph.connection import run_query
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

@router.get("/")
async def list_frameworks(user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_ALL_FRAMEWORKS, {})
    return {"frameworks": result, "total": len(result)}

@router.get("/{framework_id}/controls")
async def get_framework_controls(framework_id: str, domain: str = Query(default=None), user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_FRAMEWORK_CONTROLS, {"framework_id": framework_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    if domain:
        result = [r for r in result if domain.lower() in (r.get("domain") or "").lower()]
    return {"framework_id": framework_id, "controls": result, "total": len(result)}

@router.get("/{framework_id}/coverage")
async def get_coverage(framework_id: str, user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_FRAMEWORK_COVERAGE, {"framework_id": framework_id, "tenant_id": user.graph_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    return result[0]

@router.get("/search/controls")
async def search_controls(q: str = Query(), framework_id: str = Query(default=None), user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.SEARCH_FRAMEWORK_CONTROLS, {"q": q, "framework_id": framework_id})
    return {"results": result, "total": len(result)}

@router.get("/technique/{technique_id}/controls")
async def controls_for_technique(technique_id: str, user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.CONTROLS_FOR_TECHNIQUE, {"tid": technique_id.upper()})
    if not result:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return {"technique_id": technique_id.upper(), "technique": result[0]["technique"], "controls": result, "total": len(result)}
