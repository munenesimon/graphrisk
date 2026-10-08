from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import Optional
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
    # Optional, but load-bearing: vulnerability correlation (both the
    # daily sync and the onboarding-time sweep below) can only match this
    # asset against CVEs if vendor/product are set. Left unset (None), a
    # blank asset just won't correlate -- it never becomes an accidental
    # wildcard match (see the query's own comments in graphrisk_core).
    vendor: Optional[str] = None
    product: Optional[str] = None
    # Drives data-protection regulatory clocks: a breach-notice duty like the
    # Kenya DPA's 72-hour ODPC notice only applies to assets holding personal data.
    holds_personal_data: bool = False


class AssetDataClassification(BaseModel):
    holds_personal_data: bool

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

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
MAX_VULNERABILITIES_SHOWN = 50


def _is_known_ransomware(value) -> bool:
    return value is True or str(value or "").strip().lower() == "known"


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _package_key(pkg: dict) -> tuple:
    """Windows often lists one install under two slightly different names
    (e.g. "ASP.NET Core 8.0.14 - Shared Framework" and "ASP.NET Core 8.0.14
    Shared Framework"). Same letters and digits + same version = one package."""
    name = "".join(ch for ch in str(pkg.get("name") or "").lower() if ch.isalnum())
    return name, str(pkg.get("version") or "")


def _merge_duplicate_packages(packages: list) -> list:
    merged: dict[tuple, dict] = {}
    for pkg in packages or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        key = _package_key(pkg)
        if key not in merged:
            merged[key] = {**pkg, "cve_ids": list(pkg.get("cve_ids") or [])}
            continue
        m = merged[key]
        for cve_id in pkg.get("cve_ids") or []:
            if cve_id not in m["cve_ids"]:
                m["cve_ids"].append(cve_id)
        m["cve_count"] = max(m.get("cve_count") or 0, pkg.get("cve_count") or 0, len(m["cve_ids"]))
        if _SEVERITY_ORDER.get(pkg.get("max_severity"), 0) > _SEVERITY_ORDER.get(m.get("max_severity"), 0):
            m["max_severity"] = pkg.get("max_severity")
    return list(merged.values())


def _fix_first(packages: list, vulns_by_id: dict) -> list:
    """Vulnerable software, one entry per package, with the CVEs behind it
    and whether any is known to be used in ransomware -- the "what do I
    patch first" list. Ransomware-linked packages first, then by worst
    CVSS, then by number of CVEs."""
    out = []
    for pkg in _merge_duplicate_packages(packages):
        cves = []
        for cve_id in pkg.get("cve_ids") or []:
            v = vulns_by_id.get(cve_id, {})
            cves.append({
                "cve_id": cve_id,
                "severity": v.get("severity"),
                "cvss_score": v.get("cvss_score"),
                "ransomware": _is_known_ransomware(v.get("ransomware_use")),
            })
        cves.sort(key=lambda c: (not c["ransomware"], -_num(c["cvss_score"])))
        out.append({
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "cves": cves,
            "cve_count": pkg.get("cve_count") or len(cves),
            "max_severity": pkg.get("max_severity"),
            "ransomware": any(c["ransomware"] for c in cves),
            "max_cvss": max([_num(c["cvss_score"]) for c in cves] or [0.0]),
        })
    out.sort(key=lambda p: (not p["ransomware"], -p["max_cvss"], -p["cve_count"]))
    return out


@router.get("/{asset_id}/profile")
async def get_asset_profile(asset_id: str, user: CurrentUser = Depends(get_current_user)):
    """
    Everything the asset page shows, from every connector that reports on
    this asset, merged into the universal device profile (see
    app/connectors/profile.py): one section per kind of detail, each field
    labelled with the connector it came from. Sensitive fields (IPs, MAC
    addresses, serial numbers, assigned user) are hidden from anyone but an
    owner/admin, and always in a read-only shared tenant like the demo.
    """
    from app.auth.read_only import is_read_only_tenant
    from app.connectors.profile import SECTIONS, merge_sections, mask_sensitive
    from app.connectors.registry import registry

    tenant_id = user.graph_tenant_id
    detail = run_query(queries.GET_ASSET_DETAIL, {"asset_id": asset_id, "tenant_id": tenant_id})
    if not detail:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    detail = detail[0]

    caps = registry.profile_capabilities
    names = {cid: c["name"] for cid, c in caps.items()}
    rows = run_query(queries.GET_ASSET_PROFILE_SECTIONS, {"asset_id": asset_id, "tenant_id": tenant_id})
    profile = merge_sections(rows, names)

    can_view_sensitive = user.role in ("owner", "admin") and not is_read_only_tenant(tenant_id)
    hidden = [] if can_view_sensitive else mask_sensitive(profile)

    vulns = [v for v in (detail.get("vulnerabilities") or []) if v and v.get("cve_id")]
    vulns_by_id = {v["cve_id"]: v for v in vulns}
    packages = (profile.get("software", {}).get("fields", {}) or {}).get("vulnerable_packages", [])
    vulns.sort(key=lambda v: (
        not _is_known_ransomware(v.get("ransomware_use")),
        -_SEVERITY_RANK.get(v.get("severity"), 0),
        -_num(v.get("cvss_score")),
    ))

    # Each risk's current score and verdict against the risk appetite, then
    # the device's recommended actions -- worked out now from what the
    # connectors last reported, so a newly discovered device gets them on
    # its first run and they change as soon as the evidence does.
    from app.api.v1.organisation import read_risk_appetite
    from app.recommendations import assess_asset_risks, recommend_for_asset
    appetite, _ = read_risk_appetite(tenant_id)
    risks = assess_asset_risks([r for r in (detail.get("risks") or []) if r and r.get("id")], appetite)
    fix_first = _fix_first(packages, vulns_by_id)

    # Matching identifiers live on the asset node for CheckRegistry's use;
    # the profile already shows them (masked where needed), so never echo
    # the raw lists here.
    asset = {k: v for k, v in (detail.get("asset") or {}).items() if not k.startswith("device_")}
    return {
        "asset": asset,
        # Other names this device was reported under and merged from (same
        # serial/MAC/instance id), and assets that only share a hostname.
        "also_known_as": asset.pop("aliases", None) or [],
        "possible_duplicates": [d for d in (detail.get("possible_duplicates") or []) if d and d.get("id")],
        "profile": profile,
        "hidden_fields": hidden,
        "can_view_sensitive": can_view_sensitive,
        # Which connectors *could* fill each section -- lets the page say
        # "connect X to see this" for a section nothing has reported yet.
        "capabilities": {
            section: [c["name"] for c in caps.values() if section in c["sections"]]
            for section in SECTIONS
        },
        "fix_first": fix_first,
        "recommendations": recommend_for_asset(profile, fix_first, risks),
        "risk_appetite": appetite,
        "vulnerabilities": {
            "total": len(vulns),
            "items": [
                {**v, "ransomware": _is_known_ransomware(v.get("ransomware_use"))}
                for v in vulns[:MAX_VULNERABILITIES_SHOWN]
            ],
        },
        "risks": risks,
    }


@router.post("/", status_code=201)
async def create_asset(asset: AssetCreate, user: CurrentUser = Depends(get_current_user)):
    asset_id = str(uuid.uuid4())
    run_write(queries.CREATE_ASSET, {
        "id": asset_id, "name": asset.name, "asset_type": asset.asset_type,
        "criticality": asset.criticality, "owner": asset.owner,
        "vendor": asset.vendor, "product": asset.product,
        "holds_personal_data": asset.holds_personal_data,
        "environment": asset.environment, "tenant_id": user.graph_tenant_id,
    })
    # One-time correlation against the FULL vulnerability history (not
    # just recent CVEs -- see the query's own comments in graphrisk_core
    # for why that distinction matters). No-ops immediately if vendor or
    # product wasn't provided.
    exposures = run_write(queries.CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES, {
        "asset_id": asset_id, "tenant_id": user.graph_tenant_id,
    })
    cascade = run_write(queries.CASCADE_RISK_ON_NEW_ASSET, {
        "asset_id": asset_id, "tenant_id": user.graph_tenant_id,
    })
    return {
        "id": asset_id, "message": "Asset created", "name": asset.name,
        "vulnerabilities_linked": len(exposures),
        "risks_updated": len(cascade),
    }

@router.patch("/{asset_id}/data-classification")
async def update_data_classification(asset_id: str, body: AssetDataClassification, user: CurrentUser = Depends(get_current_user)):
    result = run_write(queries.UPDATE_ASSET_DATA_CLASSIFICATION, {
        "asset_id": asset_id, "tenant_id": user.graph_tenant_id,
        "holds_personal_data": body.holds_personal_data,
    })
    if not result:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return {"message": "Asset data classification updated", **result[0]}

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
