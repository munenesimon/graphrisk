"""
Organisation-level settings:

- the regulatory profile: which frameworks the organisation is legally
  subject to, which decides which notification clocks (e.g. "tell CBK
  within 24 hours") show up in blast-radius and vulnerability-impact results;
- the risk appetite: the highest residual risk score the organisation
  accepts, which decides whether each risk's controls are adequate (see
  app/scoring.py's assess_risk).

Deliberately explicit: GraphRisk never assumes a tenant is regulated by
anything. With no profile set, no regulatory obligations are reported.
"""
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from app.graph.connection import run_query, run_write
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser
from app.scoring import DEFAULT_RISK_APPETITE, MAX_RISK_SCORE

router = APIRouter()

# Qualifiers narrow some duties to specific kinds of organisation. Must stay
# in step with QUALIFIERS in data-ingestion/crosswalk_loader.py.
AVAILABLE_QUALIFIERS = {
    "data_processor": "You process personal data on behalf of other organisations "
                      "(adds the Kenya DPA 48-hour processor-to-controller breach notice).",
    "sips_swips": "You operate a systemically or system-wide important payment system "
                  "(adds CBK's 2-hour incident report for payment service providers).",
}
PROFILE_EDITORS = {"owner", "admin"}


class RegulatoryProfile(BaseModel):
    frameworks: List[str] = Field(default_factory=list,
        description="Framework ids the organisation is subject to, e.g. KE_DPA_2019, CBK_CYBER_BANKS_2017")
    qualifiers: List[str] = Field(default_factory=list,
        description="Optional: " + ", ".join(AVAILABLE_QUALIFIERS))


def _read_profile(tenant_id: str) -> dict:
    rows = run_query(queries.GET_REGULATORY_PROFILE, {"tenant_id": tenant_id})
    row = rows[0] if rows else {}
    return {
        "frameworks": row.get("frameworks") or [],
        "qualifiers": row.get("qualifiers") or [],
        "available_qualifiers": AVAILABLE_QUALIFIERS,
    }


@router.get("/regulatory-profile")
async def get_regulatory_profile(user: CurrentUser = Depends(get_current_user)):
    return _read_profile(user.graph_tenant_id)


@router.put("/regulatory-profile")
async def set_regulatory_profile(body: RegulatoryProfile, user: CurrentUser = Depends(get_current_user)):
    """Replaces the profile wholesale. Send the full list each time."""
    if user.role not in PROFILE_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can change the regulatory profile")

    framework_ids = sorted(set(body.frameworks))
    qualifiers = sorted(set(body.qualifiers))

    unknown_q = [q for q in qualifiers if q not in AVAILABLE_QUALIFIERS]
    if unknown_q:
        raise HTTPException(status_code=400, detail={
            "error": f"Unknown qualifier(s): {unknown_q}",
            "available_qualifiers": AVAILABLE_QUALIFIERS,
        })
    if framework_ids:
        rows = run_query(queries.FIND_UNKNOWN_FRAMEWORKS, {"framework_ids": framework_ids})
        unknown = (rows[0]["unknown"] if rows else None) or []
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown framework id(s): {unknown}. See GET /api/v1/frameworks/")

    run_write(queries.SET_REGULATORY_PROFILE, {
        "tenant_id": user.graph_tenant_id, "framework_ids": framework_ids, "qualifiers": qualifiers,
    })
    return {"message": "Regulatory profile updated", **_read_profile(user.graph_tenant_id)}


# ── Risk appetite ────────────────────────────────────────────────────────────

class RiskAppetite(BaseModel):
    risk_appetite: float = Field(ge=0.0, le=MAX_RISK_SCORE,
        description="Highest residual risk score accepted, 0-25 (likelihood × impact scale).")


def read_risk_appetite(tenant_id: str) -> tuple[float, bool]:
    """(appetite, is_default). Falls back to the default if unset or unreadable."""
    try:
        rows = run_query(queries.GET_RISK_APPETITE, {"tenant_id": tenant_id})
    except Exception:
        return DEFAULT_RISK_APPETITE, True
    value = (rows[0] if rows else {}).get("risk_appetite")
    if isinstance(value, (int, float)) and 0 <= value <= MAX_RISK_SCORE:
        return float(value), False
    return DEFAULT_RISK_APPETITE, True


def _appetite_body(tenant_id: str) -> dict:
    value, is_default = read_risk_appetite(tenant_id)
    return {"risk_appetite": value, "is_default": is_default,
            "default": DEFAULT_RISK_APPETITE, "max": MAX_RISK_SCORE}


@router.get("/risk-appetite")
async def get_risk_appetite(user: CurrentUser = Depends(get_current_user)):
    return _appetite_body(user.graph_tenant_id)


@router.put("/risk-appetite")
async def set_risk_appetite(body: RiskAppetite, user: CurrentUser = Depends(get_current_user)):
    if user.role not in PROFILE_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can change the risk appetite")
    run_write(queries.SET_RISK_APPETITE, {"tenant_id": user.graph_tenant_id,
                                          "risk_appetite": round(body.risk_appetite, 2)})
    return {"message": "Risk appetite updated", **_appetite_body(user.graph_tenant_id)}
