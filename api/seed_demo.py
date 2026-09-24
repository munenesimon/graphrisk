"""
GraphRisk — Demo Seed Data
Creates demo assets, risks, controls and links them together.
Run from the graphrisk-api folder with venv active: python seed_demo.py

Every route is now gated by a JWT (and optionally a shared X-API-Key) --
this script logs into the demo account first and attaches the token to
every request, instead of the old params={"tenant_id": "demo"} shape
that predates that auth work and no longer does anything.

Config, all via env vars so nothing here is hardcoded to one deployment:
  GRAPHRISK_BASE_URL  API base, e.g. https://graphrisk.onrender.com/api/v1
                      (default: http://localhost:8000/api/v1 for local dev)
  DEMO_EMAIL / DEMO_PASSWORD
                      Demo account credentials (default: the ones published
                      in the README -- demo@graphrisk.dev / demopass123)
  GRAPHRISK_API_KEY   Only needed if the server you're pointing at has one
                      configured (Render does; local dev usually doesn't --
                      see app/auth/api_key.py). Left unset, no X-API-Key
                      header is sent at all.

To reseed the LIVE public demo (not just a local dev DB), run with
GRAPHRISK_BASE_URL and GRAPHRISK_API_KEY set to the deployed values.

Note: this script always creates new assets/risks/controls -- it doesn't
check for or clean up ones that already exist. Re-running it against an
already-seeded tenant will duplicate everything, not update it in place.
Run clear_demo_tenant.py first to start clean.

The demo organisation is modelled as a Kenyan commercial bank: subject to
the Kenya Data Protection Act, the CBK Guidance Note on Cybersecurity and
the CMCA critical-infrastructure regulations. Those frameworks must already
be loaded into the graph (data-ingestion DS-10 and DS-11) or the profile
step fails with a clear error.
"""
import os
import requests

BASE          = os.environ.get("GRAPHRISK_BASE_URL", "http://localhost:8000/api/v1")
DEMO_EMAIL    = os.environ.get("DEMO_EMAIL", "demo@graphrisk.dev")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demopass123")
DEMO_TENANT_NAME = os.environ.get("DEMO_TENANT_NAME", "Demo Tenant")
API_KEY       = os.environ.get("GRAPHRISK_API_KEY")  # optional -- see docstring

_token = None


def _headers():
    h = {}
    if _token:
        h["Authorization"] = f"Bearer {_token}"
    if API_KEY:
        h["X-API-Key"] = API_KEY
    return h


def authenticate():
    """Log into the demo account, registering it first if it doesn't exist yet."""
    global _token
    r = requests.post(f"{BASE}/auth/login",
                       json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
                       headers=_headers())
    if r.status_code == 401:
        print(f"  No account for {DEMO_EMAIL} yet -- registering...")
        r = requests.post(f"{BASE}/auth/register", json={
            "email": DEMO_EMAIL, "password": DEMO_PASSWORD, "tenant_name": DEMO_TENANT_NAME,
        }, headers=_headers())
    r.raise_for_status()
    _token = r.json()["access_token"]
    print(f"  Authenticated as {DEMO_EMAIL} ({BASE})")


def post(path, body=None, params=None):
    if body is not None:
        r = requests.post(f"{BASE}{path}", json=body, params=params, headers=_headers())
    else:
        r = requests.post(f"{BASE}{path}", params=params, headers=_headers())
    if not r.ok:
        raise RuntimeError(f"POST {path} failed ({r.status_code}): {r.text}")
    return r.json()


# Frameworks the demo organisation is subject to (see module docstring).
DEMO_REGULATORY_PROFILE = {
    "frameworks": ["KE_DPA_2019", "CBK_CYBER_BANKS_2017", "KE_CMCA_CII_2024"],
    "qualifiers": [],
}


def put(path, body):
    r = requests.put(f"{BASE}{path}", json=body, headers=_headers())
    if not r.ok:
        raise RuntimeError(f"PUT {path} failed ({r.status_code}): {r.text}")
    return r.json()


def main():
    print("=" * 55)
    print("  GraphRisk — Demo Seed Data")
    print("=" * 55)

    print("\n[0/6] Authenticating...")
    authenticate()

    # ── Assets ────────────────────────────────────────────────
    print("\n[1/6] Creating demo assets...")
    # vendor/product are what the correlation engine (CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES
    # on creation, and the daily sync's CORRELATE_RECENT_VULNERABILITIES) actually match against --
    # without them an asset just can't pick up any CVE, no matter how relevant. Chosen to be real
    # vendor/product pairs with genuine CVE history in CISA KEV / NVD, not just plausible-sounding
    # labels, so correlation has something real to find.
    assets = [
        {"name": "Microsoft 365",   "asset_type": "CloudService", "criticality": "Critical", "owner": "IT Team",      "environment": "Production", "vendor": "Microsoft", "product": "Office", "holds_personal_data": True},
        {"name": "VPN Gateway",     "asset_type": "Server",       "criticality": "High",     "owner": "Network Team", "environment": "Production", "vendor": "Ivanti",    "product": "Connect Secure"},
        {"name": "Payroll System",  "asset_type": "Application",  "criticality": "Critical", "owner": "Finance Team", "environment": "Production", "vendor": "Oracle",    "product": "PeopleSoft", "holds_personal_data": True},
        {"name": "HR Database",     "asset_type": "Database",     "criticality": "Critical", "owner": "HR Team",      "environment": "Production", "vendor": "Microsoft", "product": "SQL Server", "holds_personal_data": True},
        {"name": "Email Gateway",   "asset_type": "Application",  "criticality": "High",     "owner": "IT Team",      "environment": "Production", "vendor": "Barracuda", "product": "Email Security Gateway"},
    ]
    asset_ids = {}
    for a in assets:
        result = post("/assets/", body=a)
        asset_ids[a["name"]] = result["id"]
        linked = result.get("vulnerabilities_linked", 0)
        extra = f", {linked} CVE(s) auto-linked" if linked else ""
        print(f"  + {a['name']} ({a['criticality']}) -> {result['id'][:8]}...{extra}")

    # ── Risks ─────────────────────────────────────────────────
    print("\n[2/6] Creating demo risks...")
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
    print("\n[3/6] Creating demo controls...")
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
    print("\n[4/6] Linking risks to assets...")
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
    print("\n[5/6] Linking controls to risks and frameworks...")

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
    post(f"/assets/{asset_ids['VPN Gateway']}/link-vulnerability", params={"cve_id": "CVE-2024-21887"})
    print("  + CVE-2024-21887 linked to VPN Gateway")

    # ── Regulatory profile ────────────────────────────────────
    print("\n[6/6] Setting regulatory profile (Kenyan commercial bank)...")
    profile = put("/organisation/regulatory-profile", DEMO_REGULATORY_PROFILE)
    print(f"  + Subject to: {', '.join(f['id'] for f in profile['frameworks'])}")
    print("  + Personal data held by: Microsoft 365, Payroll System, HR Database")

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  Seed Complete")
    print("=" * 55)
    print(f"\n  MFA Control ID: {mfa_id}")
    print(f"\n  Test blast radius (needs the Authorization/X-API-Key headers above):")
    print(f"  GET {BASE}/graph/blast-radius/control/{mfa_id}")
    print("\n  Test regulatory clocks for a real CVE (VPN Gateway is Ivanti Connect Secure):")
    print(f"  GET {BASE}/graph/vulnerability-impact/CVE-2024-21887")
    print("\n  Test dashboard:")
    print(f"  GET {BASE}/dashboard/summary")
    print("=" * 55)


if __name__ == "__main__":
    main()
