from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
import uuid
from app.graph.connection import run_query, run_write
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

class RiskCreate(BaseModel):
    title: str
    description: str = ""
    likelihood: int
    impact: int
    owner: str = ""
    status: str = "Open"

@router.get("/")
async def list_risks(user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_ALL_RISKS, {"tenant_id": user.graph_tenant_id})
    return {"risks": result, "total": len(result)}

@router.get("/{risk_id}")
async def get_risk(risk_id: str, user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_RISK_BY_ID, {"risk_id": risk_id, "tenant_id": user.graph_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return result[0]

@router.post("/", status_code=201)
async def create_risk(risk: RiskCreate, user: CurrentUser = Depends(get_current_user)):
    risk_id = str(uuid.uuid4())
    run_write(queries.CREATE_RISK, {
        "id": risk_id, "title": risk.title, "description": risk.description,
        "likelihood": risk.likelihood, "impact": risk.impact,
        "risk_score": risk.likelihood * risk.impact,
        "status": risk.status, "owner": risk.owner, "tenant_id": user.graph_tenant_id,
    })
    return {"id": risk_id, "message": "Risk created", "risk_score": risk.likelihood * risk.impact}

@router.post("/{risk_id}/link-control")
async def link_control(risk_id: str, control_id: str = Query(), effectiveness: float = Query(default=0.8), user: CurrentUser = Depends(get_current_user)):
    result = run_write(queries.LINK_CONTROL_TO_RISK, {"risk_id": risk_id, "control_id": control_id, "effectiveness": effectiveness, "tenant_id": user.graph_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Risk or control not found")
    return {"message": "Control linked to risk", "data": result[0]}
