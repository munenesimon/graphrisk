from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
import uuid
from app.graph.connection import run_query, run_write
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    criticality: str = "Medium"
    owner: str = ""
    environment: str = "Production"

@router.get("/")
async def list_assets(user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_ALL_ASSETS, {"tenant_id": user.graph_tenant_id})
    return {"assets": result, "total": len(result)}

@router.get("/{asset_id}")
async def get_asset(asset_id: str, user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_ASSET_BY_ID, {"asset_id": asset_id, "tenant_id": user.graph_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return result[0]

@router.post("/", status_code=201)
async def create_asset(asset: AssetCreate, user: CurrentUser = Depends(get_current_user)):
    asset_id = str(uuid.uuid4())
    run_write(queries.CREATE_ASSET, {
        "id": asset_id, "name": asset.name, "asset_type": asset.asset_type,
        "criticality": asset.criticality, "owner": asset.owner,
        "environment": asset.environment, "tenant_id": user.graph_tenant_id,
    })
    return {"id": asset_id, "message": "Asset created", "name": asset.name}

@router.post("/{asset_id}/link-vulnerability")
async def link_vulnerability(asset_id: str, cve_id: str = Query(), user: CurrentUser = Depends(get_current_user)):
    result = run_write(queries.LINK_VULNERABILITY_TO_ASSET, {"asset_id": asset_id, "tenant_id": user.graph_tenant_id, "cve_id": cve_id})
    if not result:
        raise HTTPException(status_code=404, detail="Asset or vulnerability not found")
    return {"message": "Vulnerability linked", "data": result[0]}

@router.post("/{asset_id}/link-risk")
async def link_risk(asset_id: str, risk_id: str = Query(), user: CurrentUser = Depends(get_current_user)):
    result = run_write(queries.LINK_RISK_TO_ASSET, {"asset_id": asset_id, "risk_id": risk_id, "tenant_id": user.graph_tenant_id})
    if not result:
        raise HTTPException(status_code=404, detail="Asset or risk not found")
    return {"message": "Risk linked to asset", "data": result[0]}
