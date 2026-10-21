import re
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field, field_validator
from app.graph.connection import run_query, run_write
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser
from app.sector_frameworks import is_hidden, hidden_summary, sector_info

router = APIRouter()

# Reading order for reference prefixes. Plain clause numbers come first (ISO
# 4.1-10.2 before Annex A); SOC 2 lists the common criteria (CC) before the
# optional categories. Anything else sorts alphabetically after these.
_PREFIX_ORDER = {"": 0, "CC": 0, "A": 1, "C": 2, "PI": 3, "P": 4}


def requirement_sort_key(reference: str | None) -> tuple:
    """Natural order for requirement references, so 4.2 comes before 10.1
    and A.5.9 before A.5.10 (plain text sort gets both wrong)."""
    ref = (reference or "").strip()
    m = re.match(r"[A-Za-z]*", ref)
    prefix = m.group(0).upper() if m else ""
    rest = ref[len(prefix):]
    parts = tuple((0, int(t), "") if t.isdigit() else (1, 0, t.lower())
                  for t in re.findall(r"\d+|[A-Za-z]+", rest))
    return (_PREFIX_ORDER.get(prefix, 5), prefix, parts)


# Who may record (self-declare) that a requirement is in place.
ATTESTATION_EDITORS = {"owner", "admin"}


def _summarise(row: dict) -> dict:
    """Counts and percentages for one framework's requirements, keeping
    "met" separate from "not evidenced yet".

    adherence_pct   share of applicable requirements met, counting a
                    partly-working control by its health and anything with
                    no evidence as 0 -- the strict figure.
    evidence_pct    share of applicable requirements GraphRisk has any
                    evidence for (a linked control or an attestation).
    met_of_evidenced_pct
                    how well the evidenced requirements are met -- what the
                    connectors and attestations actually show.
    """
    total = int(row.get("total") or 0)
    na = int(row.get("not_applicable") or 0)
    applicable = max(total - na, 0)
    counts = {k: int(row.get(k) or 0) for k in ("met", "partial", "gap", "attested", "no_evidence")}
    evidenced = applicable - counts["no_evidence"]
    score = float(row.get("score_sum") or 0.0)

    def pct(num: float, den: int) -> float | None:
        return round(num / den * 100, 1) if den > 0 else None

    return {
        "framework_id": row.get("framework_id"),
        "framework": row.get("framework"),
        "version": row.get("version"),
        "category": row.get("category") or "standard",
        "applies": bool(row.get("applies")),
        "total": total,
        "not_applicable": na,
        "applicable": applicable,
        **counts,
        "evidenced": evidenced,
        "adherence_pct": pct(score, applicable),
        "evidence_pct": pct(evidenced, applicable),
        "met_of_evidenced_pct": pct(score, evidenced),
    }


@router.get("/adherence")
async def framework_adherence(user: CurrentUser = Depends(get_current_user)):
    """Every framework, split by whether it's in the organisation's
    regulatory profile, with met / partly met / gap / self-declared /
    no-evidence counts per framework."""
    rows = run_query(queries.FRAMEWORK_ADHERENCE_ALL, {"tenant_id": user.graph_tenant_id}) or []
    frameworks = [_summarise(r) for r in rows]
    # Sector-specific frameworks the organisation hasn't switched on aren't
    # shown, not even for reference -- see app/sector_frameworks.py.
    hidden = [f["framework"] for f in frameworks if is_hidden(f["framework"], f["applies"])]
    shown = [f for f in frameworks if f["framework"] not in hidden]
    return {
        "has_profile": any(f["applies"] for f in shown),
        "obligations": [f for f in shown if f["applies"]],
        "other": [f for f in shown if not f["applies"]],
        "hidden_sector_frameworks": hidden_summary(hidden),
    }


@router.get("/{framework_id}/requirements")
async def framework_requirements(framework_id: str, user: CurrentUser = Depends(get_current_user)):
    """Each requirement of one framework with its evidence: the controls
    linked to it and their health, any attestation, and its status."""
    rows = run_query(queries.FRAMEWORK_REQUIREMENTS,
                     {"framework_id": framework_id, "tenant_id": user.graph_tenant_id}) or []
    if not rows:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    rows = sorted(rows, key=lambda r: requirement_sort_key(r.get("control_reference")))
    summary_row = {"framework_id": framework_id, "framework": rows[0].get("framework"),
                   "applies": rows[0].get("applies"), "total": len(rows), "score_sum": 0.0}
    for r in rows:
        summary_row[r["status"]] = summary_row.get(r["status"], 0) + 1
        if r["status"] != "not_applicable":
            summary_row["score_sum"] += float(r.get("score") or 0.0)
    return {
        **_summarise(summary_row),
        "can_attest": user.role in ATTESTATION_EDITORS,
        "requirements": [{k: v for k, v in r.items() if k not in ("framework", "applies")} for r in rows],
    }


class Attestation(BaseModel):
    requirement_id: str = Field(min_length=1, max_length=200)
    status: Literal["in_place", "not_applicable"]
    note: Optional[str] = Field(default=None, max_length=2000)
    evidence_url: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("evidence_url")
    @classmethod
    def _http_only(cls, v):
        if v and not v.lower().startswith(("https://", "http://")):
            raise ValueError("evidence_url must be an http(s) link")
        return v or None


@router.put("/{framework_id}/attestation")
async def set_attestation(framework_id: str, body: Attestation, user: CurrentUser = Depends(get_current_user)):
    """Record a requirement as in place (self-declared) or not applicable."""
    if user.role not in ATTESTATION_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can record attestations")
    rows = run_write(queries.SET_ATTESTATION, {
        "tenant_id": user.graph_tenant_id, "framework_id": framework_id,
        "requirement_id": body.requirement_id, "status": body.status,
        "note": (body.note or "").strip() or None, "evidence_url": body.evidence_url,
        "attested_by": user.user_id,
    }) or []
    if not rows:
        raise HTTPException(status_code=404, detail=f"Requirement {body.requirement_id} is not part of {framework_id}")
    return {"message": "Attestation recorded", "requirement_id": body.requirement_id, "status": body.status}


@router.delete("/{framework_id}/attestation")
async def delete_attestation(framework_id: str, requirement_id: str = Query(min_length=1),
                             user: CurrentUser = Depends(get_current_user)):
    if user.role not in ATTESTATION_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can remove attestations")
    run_write(queries.DELETE_ATTESTATION, {"tenant_id": user.graph_tenant_id, "requirement_id": requirement_id})
    return {"message": "Attestation removed", "requirement_id": requirement_id}

@router.get("/")
async def list_frameworks(user: CurrentUser = Depends(get_current_user)):
    result = run_query(queries.GET_ALL_FRAMEWORKS, {}) or []
    # Every framework, so the regulatory profile can offer each one; a
    # sector-specific framework carries the sector it's limited to.
    result = [{**r, "sector": sector_info(r.get("name"))} for r in result]
    return {"frameworks": result, "total": len(result)}

@router.get("/{framework_id}/controls")
async def get_framework_controls(
    framework_id: str,
    domain: str = Query(default=None),
    status: str = Query(default=None, description="Filter the returned list: 'covered' or 'not_covered'"),
    user: CurrentUser = Depends(get_current_user),
):
    # Per-control coverage (not just the framework-wide percentage) so
    # the UI can list exactly which requirements are covered and which
    # aren't -- see GET_FRAMEWORK_CONTROLS_WITH_STATUS's own comment in
    # graphrisk-core for the coverage rule this mirrors.
    result = run_query(
        queries.GET_FRAMEWORK_CONTROLS_WITH_STATUS,
        {"framework_id": framework_id, "tenant_id": user.graph_tenant_id},
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")
    if domain:
        result = [r for r in result if domain.lower() in (r.get("domain") or "").lower()]
    covered_count = sum(1 for r in result if r.get("status") != "not_covered")
    filtered = result
    if status == "covered":
        filtered = [r for r in result if r.get("status") != "not_covered"]
    elif status == "not_covered":
        filtered = [r for r in result if r.get("status") == "not_covered"]
    return {
        "framework_id": framework_id,
        "controls": filtered,
        "total": len(result),
        "covered": covered_count,
        "not_covered": len(result) - covered_count,
    }

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
