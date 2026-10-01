"""
GraphRisk -- Starter seed for a REAL tenant (not the demo).

Why this exists: an empty tenant silently discards every connector result.
WRITE_CHECK_RESULT only MATCHes an existing Control by title, so until the
controls a connector reports into exist, a Wazuh run updates nothing.
Blast Radius also only shows an asset when a Risk IMPACTS it and some
Control MITIGATES that Risk. This script creates exactly that scaffolding
and nothing fictional: no assets, no fake findings, no demo data. Assets,
CVEs, and the risk links for your real devices all come from your
connectors.

What it creates (skipping anything that already exists, matched by title,
so re-running it is safe):

  Controls -- each one is a title a connector writes to, starting as
  "Planned" with effectiveness 0 until a real connector run sets it:
    Endpoint Detection & Response     <- Wazuh agent connectivity, CrowdStrike
    Secure Configuration Baseline     <- Wazuh SCA compliance
    Vulnerability & Patch Management  <- Qualys / CrowdStrike Spotlight (later)

  Risks -- the exact two titles CheckRegistry._ensure_risk_for_finding
  rolls Critical/High CVE findings into (it MERGEs on title, so it reuses
  these instead of creating unlinked copies):
    Ransomware Infection Risk         (CVE flagged in CISA KEV as ransomware-used)
    Unpatched Vulnerability Risk      (every other Critical/High CVE)

  MITIGATES links between them, so a device's CVE-driven risk shows up in
  the Blast Radius of the controls that actually reduce it, and SATISFIES
  links from each control to the framework requirements it maps to (any
  reference not loaded in your graph is skipped with a warning, not fatal).

It does NOT set a regulatory profile -- pick the frameworks your
organisation is actually subject to on the Regulatory screen.

Usage (PowerShell, from the graphrisk/api folder, venv active):
  1. Register your real account first, on the GraphRisk login screen
     ("Register"), with your own organisation name.
  2. $env:GRAPHRISK_BASE_URL = "https://graphrisk.onrender.com/api/v1"
     $env:GRAPHRISK_API_KEY  = "<the deployed API key>"
     $env:GRAPHRISK_EMAIL    = "<the account you just registered>"
     $env:GRAPHRISK_PASSWORD = "<its password>"
     python seed_real_tenant.py
"""
import os
import sys
import requests

BASE     = os.environ.get("GRAPHRISK_BASE_URL", "http://localhost:8000/api/v1")
EMAIL    = os.environ.get("GRAPHRISK_EMAIL")
PASSWORD = os.environ.get("GRAPHRISK_PASSWORD")
API_KEY  = os.environ.get("GRAPHRISK_API_KEY")
DEMO_EMAIL = "demo@graphrisk.dev"

_token = None


def _headers():
    h = {}
    if _token:
        h["Authorization"] = f"Bearer {_token}"
    if API_KEY:
        h["X-API-Key"] = API_KEY
    return h


def authenticate():
    """Logs in only -- never registers. Registering is done on the login
    screen, so the account and its organisation name are deliberate."""
    global _token
    r = requests.post(f"{BASE}/auth/login", json={"email": EMAIL, "password": PASSWORD}, headers=_headers())
    if r.status_code == 401:
        sys.exit(f"  Login failed for {EMAIL}. Register it on the GraphRisk login screen first, "
                 "or check GRAPHRISK_PASSWORD.")
    r.raise_for_status()
    body = r.json()
    _token = body["access_token"]
    tenant = body.get("graph_tenant_id")
    if tenant == "demo":
        sys.exit("  This account belongs to the 'demo' tenant -- refusing to seed it. "
                 "Use seed_demo.py for the demo.")
    print(f"  Authenticated as {EMAIL} (tenant: {tenant}, {BASE})")


def get(path):
    r = requests.get(f"{BASE}{path}", headers=_headers())
    if not r.ok:
        raise RuntimeError(f"GET {path} failed ({r.status_code}): {r.text}")
    return r.json()


def post(path, body=None, params=None, allow_404=False):
    r = requests.post(f"{BASE}{path}", json=body, params=params, headers=_headers())
    if allow_404 and r.status_code == 404:
        return None
    if not r.ok:
        raise RuntimeError(f"POST {path} failed ({r.status_code}): {r.text}")
    return r.json()


CONTROLS = [
    {"title": "Endpoint Detection & Response",
     "description": "Endpoint agents deployed and actively reporting. Effectiveness is set from live "
                    "connector data (Wazuh agent connectivity, CrowdStrike sensor health).",
     "control_type": "Detective"},
    {"title": "Secure Configuration Baseline",
     "description": "Endpoints hardened against a configuration benchmark. Effectiveness is set from "
                    "live connector data (Wazuh SCA pass rate).",
     "control_type": "Preventive"},
    {"title": "Vulnerability & Patch Management",
     "description": "Known vulnerabilities identified and remediated within SLA. Updated by a "
                    "vulnerability scanner connector (Qualys, CrowdStrike Spotlight) once connected.",
     "control_type": "Corrective"},
]

RISKS = [
    {"title": "Ransomware Infection Risk",
     "description": "Ransomware exploiting a known-ransomware-used vulnerability (CISA KEV) on an endpoint.",
     "likelihood": 3, "impact": 5},
    {"title": "Unpatched Vulnerability Risk",
     "description": "Critical or high severity vulnerabilities left unpatched on monitored endpoints.",
     "likelihood": 3, "impact": 4},
]

# (control title, risk title, link effectiveness)
MITIGATIONS = [
    ("Endpoint Detection & Response",    "Ransomware Infection Risk",    0.7),
    ("Secure Configuration Baseline",    "Ransomware Infection Risk",    0.5),
    ("Secure Configuration Baseline",    "Unpatched Vulnerability Risk", 0.4),
    ("Vulnerability & Patch Management", "Unpatched Vulnerability Risk", 0.8),
    ("Vulnerability & Patch Management", "Ransomware Infection Risk",    0.6),
]

# (control title, framework requirement reference) -- NIST CSF 2.0 + NIST 800-53
FRAMEWORK_LINKS = [
    ("Endpoint Detection & Response",    "DE.CM-01"),
    ("Endpoint Detection & Response",    "DE.CM-09"),
    ("Endpoint Detection & Response",    "SI-4"),
    ("Secure Configuration Baseline",    "PR.PS-01"),
    ("Secure Configuration Baseline",    "CM-2"),
    ("Secure Configuration Baseline",    "CM-6"),
    ("Secure Configuration Baseline",    "CM-7"),
    ("Vulnerability & Patch Management", "ID.RA-01"),
    ("Vulnerability & Patch Management", "PR.PS-02"),
    ("Vulnerability & Patch Management", "RA-5"),
    ("Vulnerability & Patch Management", "SI-2"),
]


def main():
    print("=" * 60)
    print("  GraphRisk -- Real tenant starter seed")
    print("=" * 60)
    if not EMAIL or not PASSWORD:
        sys.exit("  Set GRAPHRISK_EMAIL and GRAPHRISK_PASSWORD first (see the docstring at the top of this file).")
    if EMAIL.strip().lower() == DEMO_EMAIL:
        sys.exit("  That's the demo account -- refusing to seed it.")

    print("\n[0/4] Authenticating...")
    authenticate()

    print("\n[1/4] Controls...")
    existing = {c["title"]: c["id"] for c in get("/controls/").get("controls", [])}
    control_ids = {}
    for c in CONTROLS:
        if c["title"] in existing:
            control_ids[c["title"]] = existing[c["title"]]
            print(f"  = {c['title']} (already exists)")
            continue
        result = post("/controls/", body={**c, "implementation_status": "Planned",
                                          "effectiveness_score": 0.0, "owner": "Security Team"})
        control_ids[c["title"]] = result["id"]
        print(f"  + {c['title']}")

    print("\n[2/4] Risks...")
    existing = {r["title"]: r["id"] for r in get("/risks/").get("risks", [])}
    risk_ids = {}
    for ri in RISKS:
        if ri["title"] in existing:
            risk_ids[ri["title"]] = existing[ri["title"]]
            print(f"  = {ri['title']} (already exists)")
            continue
        result = post("/risks/", body={**ri, "owner": "Security Team", "status": "Open"})
        risk_ids[ri["title"]] = result["id"]
        print(f"  + {ri['title']}")

    print("\n[3/4] Control -> risk mitigation links...")
    for ctrl, risk, eff in MITIGATIONS:
        post(f"/risks/{risk_ids[risk]}/link-control",
             params={"control_id": control_ids[ctrl], "effectiveness": eff})
        print(f"  + {ctrl} -> {risk}")

    print("\n[4/4] Control -> framework requirement links...")
    skipped = []
    for ctrl, ref in FRAMEWORK_LINKS:
        if post(f"/controls/{control_ids[ctrl]}/link-framework-control",
                params={"framework_control_ref": ref}, allow_404=True) is None:
            skipped.append(ref)
            print(f"  ! {ref} not loaded in this graph -- skipped")
        else:
            print(f"  + {ctrl} -> {ref}")

    print("\n" + "=" * 60)
    print("  Done.")
    if skipped:
        print(f"  Skipped (not in graph): {', '.join(skipped)}")
    print("  Next: set your regulatory profile on the Regulatory screen, then")
    print("  re-enter your Wazuh credentials on Connectors and run it.")
    print("=" * 60)


if __name__ == "__main__":
    main()
