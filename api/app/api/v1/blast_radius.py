from typing import Literal
from fastapi import APIRouter, HTTPException, Query, Depends
from app.graph.connection import run_query
from app.graph import queries
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()

CLOCK_NOTE = (
    "Deadlines run from when you become aware of a breach or incident, not from this analysis. "
    "They show which regulatory clocks would start if this exposure were exploited, based on your "
    "organisation's regulatory profile. GraphRisk-curated regulatory data -- not legal advice."
)


def _regulatory_obligations(tenant_id: str, asset_ids: list) -> dict:
    """Notification duties that would apply if these assets were involved in a breach/incident."""
    obligations = []
    if asset_ids:
        rows = run_query(queries.REGULATORY_OBLIGATIONS_FOR_ASSETS, {"tenant_id": tenant_id, "asset_ids": asset_ids})
        obligations = [{
            "framework": r["framework"], "framework_id": r["framework_id"],
            "requirement": r["requirement"], "title": r["title"],
            "notify": r["notify"], "deadline_hours": r["deadline_hours"],
            "trigger": r["trigger"], "condition": r["condition"],
            "legal_source": r["legal_source"],
            "triggered_by_assets": r["triggered_by_assets"] or [],
        } for r in rows]
    block = {"note": CLOCK_NOTE, "obligations": obligations}
    if not obligations:
        profile = run_query(queries.GET_REGULATORY_PROFILE, {"tenant_id": tenant_id})
        if not profile or not (profile[0].get("frameworks") or []):
            block["hint"] = ("No regulatory profile set, so no obligations can be shown. "
                             "Set one with PUT /api/v1/organisation/regulatory-profile.")
    return block


def _group_frameworks(row: dict, scope: str):
    """
    Splits the frameworks a control supports into:
      standards          voluntary benchmarks (NIST, CSF, CIS, PCI) -- always shown
      your_regulations   regulations in the organisation's regulatory profile
      other_regulations  regulations it isn't subject to -- only with scope="all"
    Returns (grouped, included_names). included_names drives the flat
    compliance_gaps list and framework_count, so existing clients (the
    Flutter blast-radius screen) keep working and follow the chosen scope.
    """
    frameworks = row.get("frameworks")
    if frameworks is None:
        # graphrisk_core older than this router: only names are available
        frameworks = [{"id": n, "name": n, "category": "standard", "in_profile": False}
                      for n in row.get("compliance_gaps") or []]
    unique = {}
    for f in frameworks:
        unique.setdefault(f["id"], f)   # reached both directly and via the crosswalk
    fws = list(unique.values())
    standards = [f["name"] for f in fws if f["category"] != "regulation"]
    yours = [f["name"] for f in fws if f["category"] == "regulation" and f["in_profile"]]
    other = [f["name"] for f in fws if f["category"] == "regulation" and not f["in_profile"]]
    grouped = {"standards": standards, "your_regulations": yours}
    included = standards + yours
    if scope == "all":
        grouped["other_regulations"] = other
        included = included + other
    return grouped, included


@router.get("/blast-radius/control/{control_id}")
async def blast_radius_control(
    control_id: str,
    scope: Literal["all", "applicable"] = Query(
        "all",
        description="all: every framework this control supports, grouped. "
                    "applicable: standards plus only the regulations in your regulatory profile.",
    ),
    user: CurrentUser = Depends(get_current_user),
):
    result = run_query(queries.BLAST_RADIUS_CONTROL, {"control_id": control_id, "tenant_id": user.graph_tenant_id})
    if not result or not result[0].get("control_title"):
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    row = result[0]
    grouped, included = _group_frameworks(row, scope)
    # Crosswalk requirements are "<FRAMEWORK_NAME> <ref>"; keep only those in scope
    mapped = [m for m in row.get("mapped_framework_controls") or [] if m.split(" ", 1)[0] in included]
    return {
        "control_id": control_id, "control_title": row["control_title"],
        "control_status": row["control_status"], "effectiveness_score": row["effectiveness_score"],
        "scope": scope,
        "blast_radius": {
            "exposed_risks": row["exposed_risks"], "affected_assets": row["affected_assets"],
            "impacted_processes": row["impacted_processes"],
            "compliance_gaps": included,
            "frameworks": grouped,
            "framework_controls": row["framework_controls"],
            # Requirements in other frameworks (e.g. Kenya DPA) exposed via the
            # curated crosswalk rather than a direct SATISFIES link.
            "mapped_framework_controls": mapped,
        },
        "regulatory_obligations": _regulatory_obligations(user.graph_tenant_id, row.get("affected_asset_ids") or []),
        "summary": {"risk_count": row["risk_count"], "asset_count": row["asset_count"], "framework_count": len(included)}
    }


@router.get("/vulnerability-impact/{cve_id}")
async def vulnerability_impact(cve_id: str, user: CurrentUser = Depends(get_current_user)):
    """
    "This CVE was published today -- what does it mean for us?" Returns the
    caller's assets the CVE is linked to (via correlation or manual linking),
    the risks and mitigating controls on those assets, affected business
    processes, and the regulatory clocks that would start if it were exploited.
    """
    cve_id = cve_id.strip().upper()
    rows = run_query(queries.VULNERABILITY_IMPACT, {"cve_id": cve_id, "tenant_id": user.graph_tenant_id})
    if not rows:
        raise HTTPException(status_code=404, detail=f"{cve_id} is not in GraphRisk's vulnerability data (CISA KEV / NVD critical)")
    v = rows[0]
    assets = v["exposed_assets"] or []
    return {
        "cve_id": v["cve_id"], "title": v["title"], "description": v["description"],
        "severity": v["severity"], "cvss_score": v["cvss_score"],
        "known_ransomware_use": v["known_ransomware_use"], "source": v["source"],
        "affects_you": bool(assets),
        "exposed_assets": assets,
        "risks": v["risks"] or [],
        "mitigating_controls": v["mitigating_controls"] or [],
        "impacted_processes": v["impacted_processes"] or [],
        "regulatory_obligations": _regulatory_obligations(user.graph_tenant_id, [a["id"] for a in assets]),
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
