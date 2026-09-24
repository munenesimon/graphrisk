from fastapi import APIRouter, HTTPException, Query, Depends
from app.graph.connection import run_query
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

@router.get("/blast-radius/control/{control_id}")
async def blast_radius_control(control_id: str, user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.BLAST_RADIUS_CONTROL, {"control_id": control_id, "tenant_id": user.graph_tenant_id})
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
            # Requirements in other frameworks (e.g. Kenya DPA) exposed via the
            # curated crosswalk rather than a direct SATISFIES link. .get() so
            # this still works if graphrisk_core is older than this router.
            "mapped_framework_controls": row.get("mapped_framework_controls", []),
        },
        "summary": {"risk_count": row["risk_count"], "asset_count": row["asset_count"], "framework_count": row["framework_count"]}
    }

@router.get("/blast-radius/technique/{technique_id}")
async def blast_radius_technique(technique_id: str, user: CurrentUser = Depends(get_current_user)):
    """Not tenant-scoped -- ATT&CK techniques and framework mappings are global data."""
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
async def technique_coverage(technique_ids: str = Query(description="Comma-separated ATT&CK IDs e.g. T1078,T1110"), user: CurrentUser = Depends(get_current_user)):
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
