"""
GraphRisk — Demo Seed Data
Creates demo assets, risks, controls and links them together.
Run from graphrisk-api folder with venv active.
Usage: python seed_demo.py
"""
import requests

BASE   = "http://localhost:8000/api/v1"
TENANT = "demo"


def post(path, body=None, params=None):
    p = {"tenant_id": TENANT}
    if params:
        p.update(params)
    if body:
        r = requests.post(f"{BASE}{path}", json=body, params=p)
    else:
        r = requests.post(f"{BASE}{path}", params=p)
    return r.json()


def main():
    print("=" * 55)
    print("  GraphRisk — Demo Seed Data")
    print("=" * 55)

    # ── Assets ────────────────────────────────────────────────
    print("\n[1/5] Creating demo assets...")
    # vendor/product are what the correlation engine (CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES
    # on creation, and the daily sync's CORRELATE_RECENT_VULNERABILITIES) actually match against --
    # without them an asset just can't pick up any CVE, no matter how relevant. Chosen to be real
    # vendor/product pairs with genuine CVE history in CISA KEV / NVD, not just plausible-sounding
    # labels, so correlation has something real to find.
    assets = [
        {"name": "Microsoft 365",   "asset_type": "CloudService", "criticality": "Critical", "owner": "IT Team",      "environment": "Production", "vendor": "Microsoft", "product": "Office"},
        {"name": "VPN Gateway",     "asset_type": "Server",       "criticality": "High",     "owner": "Network Team", "environment": "Production", "vendor": "Ivanti",    "product": "Connect Secure"},
        {"name": "Payroll System",  "asset_type": "Application",  "criticality": "Critical", "owner": "Finance Team", "environment": "Production", "vendor": "Oracle",    "product": "PeopleSoft"},
        {"name": "HR Database",     "asset_type": "Database",     "criticality": "Critical", "owner": "HR Team",      "environment": "Production", "vendor": "Microsoft", "product": "SQL Server"},
        {"name": "Email Gateway",   "asset_type": "Application",  "criticality": "High",     "owner": "IT Team",      "environment": "Production", "vendor": "Barracuda", "product": "Email Security Gateway"},
    ]
    asset_ids = {}
    for a in assets:
        result = post("/assets/", body=a)
        asset_ids[a["name"]] = result["id"]
        print(f"  + {a['name']} ({a['criticality']}) -> {result['id'][:8]}...")

    # ── Risks ─────────────────────────────────────────────────
    print("\n[2/5] Creating demo risks...")
    risks = [
        {"title": "Identity Compromise Risk",  "description": "Risk of unauthorized access via compromised or stolen credentials", "likelihood": 4, "impact": 5, "owner": "CISO", "status": "Open"},
        {"title": "Ransomware Infection Risk", "description": "Risk of ransomware encrypting critical business data and systems",   "likelihood": 3, "impact": 5, "owner": "CISO", "status": "Open"},
        {"title": "Data Exfiltration Risk",    "description": "Risk of sensitive data being stolen by internal or external actors", "likelihood": 3, "impact": 4, "owner": "CISO", "status": "Open"},
    ]
    risk_ids = {}
    for ri in risks:
        result = post("/risks/", body=ri)
        risk_ids[ri["title"]] = result["id"]
        print(f"  + {ri['title']} (score: {result['risk_score']}) -> {result['id'][:8]}...")

    # ── Controls ──────────────────────────────────────────────
    print("\n[3/5] Creating demo controls...")
    controls_data = [
        {"title": "Multi-Factor Authentication",    "description": "MFA enforced for all users and privileged accounts across all systems", "control_type": "Preventive", "implementation_status": "Implemented",          "effectiveness_score": 0.9, "owner": "IT Security"},
        {"title": "Endpoint Detection & Response",  "description": "EDR solution deployed on all managed endpoints with active monitoring",  "control_type": "Detective",  "implementation_status": "Implemented",          "effectiveness_score": 0.8, "owner": "SOC Team"},
        {"title": "Privileged Access Management",   "description": "PAM controls restricting and auditing privileged account usage",         "control_type": "Preventive", "implementation_status": "PartiallyImplemented", "effectiveness_score": 0.5, "owner": "IT Security"},
        {"title": "Data Loss Prevention",           "description": "DLP policies preventing sensitive data leaving the organization",        "control_type": "Preventive", "implementation_status": "Planned",              "effectiveness_score": 0.0, "owner": "IT Security"},
    ]
    control_ids = {}
    for c in controls_data:
        result = post("/controls/", body=c)
        control_ids[c["title"]] = result["id"]
        print(f"  + {c['title']} ({c['implementation_status']}) -> {result['id'][:8]}...")

    # ── Link Risks to Assets ──────────────────────────────────
    print("\n[4/5] Linking risks to assets...")
    mfa_id  = control_ids["Multi-Factor Authentication"]
    edr_id  = control_ids["Endpoint Detection & Response"]
    pam_id  = control_ids["Privileged Access Management"]
    dlp_id  = control_ids["Data Loss Prevention"]

    id_risk  = risk_ids["Identity Compromise Risk"]
    ran_risk = risk_ids["Ransomware Infection Risk"]
    dex_risk = risk_ids["Data Exfiltration Risk"]

    # Risk -> Asset links
    links = [
        (asset_ids["Microsoft 365"],  id_risk),
        (asset_ids["VPN Gateway"],    id_risk),
        (asset_ids["Payroll System"], ran_risk),
        (asset_ids["HR Database"],    ran_risk),
        (asset_ids["HR Database"],    dex_risk),
        (asset_ids["Email Gateway"],  dex_risk),
    ]
    for asset_id, risk_id in links:
        post(f"/assets/{asset_id}/link-risk", params={"risk_id": risk_id})
    print(f"  + {len(links)} risk-asset links created")

    # ── Link Controls to Risks ────────────────────────────────
    print("\n[5/5] Linking controls to risks and frameworks...")

    # Control -> Risk links
    ctrl_risk_links = [
        (mfa_id, id_risk,  0.9),
        (mfa_id, ran_risk, 0.7),
        (edr_id, ran_risk, 0.8),
        (pam_id, id_risk,  0.5),
        (dlp_id, dex_risk, 0.0),
        (edr_id, dex_risk, 0.6),
    ]
    for ctrl_id, risk_id, eff in ctrl_risk_links:
        post(f"/risks/{risk_id}/link-control", params={"control_id": ctrl_id, "effectiveness": eff})
    print(f"  + {len(ctrl_risk_links)} control-risk links created")

    # Control -> FrameworkControl links (SATISFIES)
    fw_links = [
        (mfa_id, "PR.AA-03"),
        (mfa_id, "AC-2"),
        (mfa_id, "IA-2"),
        (mfa_id, "IA-5"),
        (edr_id, "DE.CM-01"),
        (edr_id, "DE.CM-03"),
        (pam_id, "AC-5"),
        (pam_id, "AC-6"),
        (dlp_id, "PR.DS-01"),
        (dlp_id, "PR.DS-02"),
    ]
    for ctrl_id, ref in fw_links:
        post(f"/controls/{ctrl_id}/link-framework-control", params={"framework_control_ref": ref})
    print(f"  + {len(fw_links)} framework control links created")

    # Link a real CVE to an asset
    cve_link = requests.post(
        f"{BASE}/assets/{asset_ids['VPN Gateway']}/link-vulnerability",
        params={"tenant_id": TENANT, "cve_id": "CVE-2024-21887"}
    )
    print(f"  + CVE-2024-21887 linked to VPN Gateway")

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  Seed Complete")
    print("=" * 55)
    print(f"\n  MFA Control ID: {mfa_id}")
    print(f"\n  Test blast radius:")
    print(f"  http://localhost:8000/api/v1/graph/blast-radius/control/{mfa_id}?tenant_id=demo")
    print("\n  Test dashboard:")
    print("  http://localhost:8000/api/v1/dashboard/summary?tenant_id=demo")
    print("=" * 55)


if __name__ == "__main__":
    main()
