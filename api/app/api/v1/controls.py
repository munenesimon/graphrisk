from fastapi import APIRouter, HTTPException, Query
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
