**Live demo:** `https://graphrisk-735a0.web.app` · **API:** `https://graphrisk.onrender.com` · **Source:** `https://github.com/munenesimon/graphrisk`

# GraphRisk Intelligence Platform

> **Risk is a network, not a list.**

GraphRisk is a graph-based cybersecurity risk intelligence platform that models your security posture as a traversable graph rather than a static spreadsheet. When a control fails, every affected asset, risk, and compliance obligation updates automatically — no manual re-entry.

**Live demo:** `https://graphrisk.onrender.com` · **API docs:** `https://graphrisk.onrender.com/docs`

---

## The Core Insight

Most GRC tools store risk data and report on it. GraphRisk traverses it.

When you mark a control as "Partially Implemented," GraphRisk instantly recalculates every downstream risk score, surfaces every compliance gap across every linked framework, and shows you exactly which assets are now exposed — across NIST 800-53, NIST CSF, CIS Controls, PCI DSS and Kenyan regulation (the Data Protection Act and Central Bank of Kenya cybersecurity guidance) simultaneously — and tells you which regulator notification deadlines would start if it's exploited.

One change. Automatic cascade. No spreadsheet.

---

## Live Demo

The public API is live and authenticated. To try it:

**1. Get a token:**
```bash
curl -X POST https://graphrisk.onrender.com/api/v1/auth/login \
  -H "X-API-Key: <request via GitHub issues>" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@graphrisk.dev","password":"demopass123"}'
```

**2. Run a blast radius query** (what happens if MFA fails?):
```bash
curl https://graphrisk.onrender.com/api/v1/graph/blast-radius/control/2b813abc-d89a-4186-b11e-b20a4216e15b \
  -H "X-API-Key: <key>" \
  -H "Authorization: Bearer <token>"
```

**Expected response:** 2 exposed risks, 4 affected assets and 4 frameworks, calculated live from the graph and grouped: standards (NIST 800-53, NIST CSF), your regulations (the Kenya Data Protection Act, reached through the NIST crosswalk), and other regulations this control also supports (the CBK guideline for payment service providers — this bank isn't one). Add `?scope=applicable` to leave out regulations the organisation isn't subject to. The demo organisation is modelled as a Kenyan commercial bank, so the response also lists the notification clocks that would start if those assets were breached: 24 hours to CBK, 24 hours to the banking-sector SOC, and 72 hours to the Data Commissioner for the three assets holding personal data.

**3. Ask what a real CVE means for this organisation** (CVE-2024-21887, Ivanti Connect Secure — actively exploited):
```bash
curl https://graphrisk.onrender.com/api/v1/graph/vulnerability-impact/CVE-2024-21887 \
  -H "X-API-Key: <key>" \
  -H "Authorization: Bearer <token>"
```

**Expected response:** the VPN Gateway is exposed, the risks and controls on it, and two 24-hour clocks (CBK and the banking-sector SOC). There's no 72-hour Data Commissioner clock, because the VPN gateway holds no personal data — the clocks follow what's actually affected.

---

## What's Actually Built

### Graph Intelligence Engine
- **Blast radius traversal** — given a failing control, instantly surfaces every affected asset, risk, and compliance obligation via Cypher graph traversal. Verified with real math: `risk_score = likelihood × impact × (1 - control_effectiveness)`.
- **Evidence origami** — one evidence artifact (e.g. an MFA enrollment report) automatically satisfies multiple framework requirements across different standards simultaneously, because it maps to a `Control` node already linked to `FrameworkControl` nodes via `SATISFIES` edges.
- **Regulatory crosswalk** — requirements from the Kenya Data Protection Act 2019, the CBK Guidance Note on Cybersecurity (banks), the CBK Guideline on Cybersecurity for Payment Service Providers and the 2024 Critical Information Infrastructure Regulations are linked to the NIST 800-53 and CSF controls they correspond to via `MAPS_TO` edges, so controls a tenant already has count toward Kenyan obligations with no extra mapping work. Coverage is reported as direct vs. via-crosswalk, and only controls that are actually in place (Implemented or Partially Implemented) count. Blast-radius results group frameworks into standards, the organisation's own regulations and other regulations the control supports; `?scope=applicable` shows only what applies.
- **Regulatory notification clocks** — each organisation declares which frameworks it's subject to and which assets hold personal data. Blast-radius and vulnerability-impact results then list the notification duties that would apply if the exposure became a breach: who to notify, the deadline (2, 24, 48 or 72 hours), the legal source, and which affected assets trigger it. A Kenyan bank can face three separate clocks from one incident; GraphRisk shows all of them, and only the ones that actually apply.
- **Vendor breach cascade** — given a third-party vendor breach, the graph traverses `PROVIDES → Asset → Risk` edges to surface every activated risk and flag any under-implemented mitigating controls.
- **Automatic vulnerability correlation** — bidirectional: daily threat intelligence sync auto-links newly-published CVEs to matching assets by vendor/product name (with structured CPE-based matching, not free-text search), and newly-onboarded assets are immediately checked against the full vulnerability history at creation time. Either direction cascades risk score updates without manual triage.

### Universal Connector Architecture
A three-layer adapter pattern (BaseConnector → per-vendor Adapter → CheckRegistry) lets any security tool plug into the graph with minimal new code, regardless of its authentication style.

| Connector | Auth Pattern | Checks | Validation |
|---|---|---|---|
| Mock | None | 1 | Live Neo4j write + risk cascade verified |
| Microsoft Entra ID | OAuth 2.0 client credentials | 5 | Structurally complete |
| AWS | SDK-managed IAM keys (boto3) | 4 | Offline-verified via moto |
| Okta | Static API key header | 4 | Offline-verified via responses |
| Wazuh | HTTP Basic → session JWT (self-hosted SIEM/XDR) | 2 | Structurally complete; pending a live instance |

Adding a new vendor means writing one adapter file (~150 lines) and one registration line. The registry, graph write, and cascade logic never change.

### Data Layer
Real-world, authoritative data — not synthetic demo content.

| Source | Records | Update Cadence |
|---|---|---|
| NVD CVE API (Critical severity) | 10,000+ | Daily automated delta sync |
| CISA Known Exploited Vulnerabilities | 1,700+ | Daily automated sync |
| MITRE ATT&CK Enterprise | 697 techniques, 15 tactics | On new release |
| NIST SP 800-53 Rev5 | 1,196 controls | Static |
| NIST CSF 2.0 | 106 controls | Static |
| CIS Controls v8.1 | 171 controls + safeguards | Static |
| PCI DSS v4.0.1 | 12 requirements | Static |
| Kenya Data Protection Act 2019 (+ 2021 Regulations) | 23 requirements, 57 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CBK Guidance Note on Cybersecurity (banks, 2017) | 19 requirements, 48 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CBK Guideline on Cybersecurity for PSPs (2019) | 21 requirements, 50 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CMCA Critical Information Infrastructure Regulations 2024 | 3 requirements, 7 NIST crosswalk mappings | Static (GraphRisk-curated) |
| AI-generated summaries | 1,999 nodes | Generated once via Claude |

### Multi-Tenant Authentication
JWT-based authentication backed by PostgreSQL (Neon). Every data-bearing endpoint derives `tenant_id` from the verified JWT — not from a client-supplied query parameter. Tenant isolation is enforced at the graph query level.

---

## Architecture

```
Browser / API Client
        │
        │  X-API-Key + Authorization: Bearer <JWT>
        ▼
┌─────────────────────────────┐
│  Render (FastAPI + Python)  │  graphrisk.onrender.com
│  REST API · JWT Auth        │
└──────────┬──────────────────┘
           │                    │
           ▼                    ▼
┌──────────────────┐  ┌─────────────────────────┐
│  Neon PostgreSQL │  │  Google Cloud Neo4j     │
│  Oregon (free)   │  │  e2-micro VM · us-west1 │
│  Tenants · Users │  │  13,700+ nodes          │
│  Audit log       │  │  Graph intelligence     │
└──────────────────┘  └─────────────▲───────────┘
                                     │
                    ┌────────────────┴──────────┐
                    │  GitHub Actions           │
                    │  Daily 06:00 UTC cron     │
                    │  CISA KEV + NVD delta     │
                    │  + Vuln correlation (v4)  │
                    └────────────────────────────┘
```

**Tech stack:** Neo4j 5.20 · FastAPI · Python 3.12 · Flutter Web · PostgreSQL (asyncpg + SQLAlchemy) · Docker

---

## Running Locally

**Prerequisites:** Docker Desktop, Python 3.12, Flutter 3.x

**1. Start the graph database:**
```bash
docker run --name graphrisk-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/graphrisk_dev \
  -v graphrisk-neo4j-data:/data \
  --restart unless-stopped -d \
  neo4j:5.20-community
```

**2. Start the API:**
```bash
cd api
pip install -r requirements.txt
# Copy .env.template to .env and fill in values
uvicorn app.main:app --reload --port 8000
```

**3. Create tables and seed demo data:**
```bash
python -m app.db.init_db
python seed_demo.py
```

**4. Run the Flutter UI:**
```bash
cd ui
flutter pub get
flutter run -d chrome --web-port=3000
```

**5. Load threat intelligence data** (optional — takes ~5 minutes):
```bash
cd data-ingestion
pip install -r requirements.txt
# Set NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env
python ingest/01_nist_csf.py
python ingest/02_nist_800_53.py
python ingest/04_mitre_attack.py
python ingest/05_attack_mappings.py
python ingest/06_cisa_kev.py
python ingest/07_nvd_cve.py
python ingest/10_kenya_dpa.py         # Kenya DPA + NIST crosswalk
python ingest/11_kenya_cyber_regs.py  # CBK banks/PSPs + CMCA CII regulations
```

---

## Honest Limitations

This is a portfolio/early-stage project. Here's what's real versus what's still in progress:

| Item | Status |
|---|---|
| Blast radius engine | ✅ Proven with verified math |
| Evidence origami | ✅ Proven with real graph data |
| Vendor breach cascade | ✅ Proven with real graph data |
| Universal connector pattern | ✅ Proven across 4 auth patterns |
| Vulnerability-to-asset correlation | ✅ Automated — daily sync + at asset onboarding |
| Flutter Web frontend | ✅ Live on Firebase Hosting |
| Multi-tenancy | ✅ JWT-enforced tenant scoping on every data endpoint (PostgreSQL on Neon free tier) |
| GitHub Actions daily sync | ✅ Running reliably against Google Cloud Neo4j (18/19 recent runs succeeded) |
| Connector coverage | ⚠️ 5 connectors vs. 200+ in mature tools |
| Sync correlation scope | ℹ️ Daily sync correlates new CVEs against the demo tenant by design — that's the account anyone testing GraphRisk logs into, so it stays populated with live data rather than sitting on months-old seed data. Not yet extended to arbitrary tenants. |
| Kenyan regulatory crosswalk | ⚠️ GraphRisk-curated mappings, not an official crosswalk — coverage means mapped controls are in place, not legal compliance (not legal advice). Six items derived from the Data Protection (General) Regulations 2021 are pending primary-text verification. |
| Regulatory clocks | ⚠️ Driven by a self-declared regulatory profile and per-asset personal-data flags. Deadlines run from becoming aware of a breach, and whether an incident is "significant" enough to report is a human judgement GraphRisk doesn't make — it shows the duty and its condition. API-only for now; not yet in the Flutter UI. |
| Production hardening | ⚠️ e2-micro Neo4j VM is memory-constrained (~1.4s query latency) |

---

## Roadmap

- [ ] Regulatory profile, personal-data flags and notification clocks in the Flutter UI
- [ ] Real vendor credential testing (AWS free tier, Okta developer org)
- [ ] Wazuh connector live-data validation (pending a self-hosted instance)
- [ ] CrowdStrike / Qualys connector adapters
- [ ] Connector management UI in Flutter
- [ ] Graph canvas visualization for blast radius
- [ ] CIS Controls commercial licensing review (required before paid use)

---

## Project Structure

```
graphrisk/
├── api/                    # FastAPI backend
│   ├── app/
│   │   ├── api/v1/         # REST endpoints (assets, risks, controls, auth, connectors...)
│   │   ├── auth/           # JWT + API key middleware
│   │   ├── connectors/     # Universal connector architecture
│   │   │   ├── base.py     # BaseConnector (transport layer)
│   │   │   ├── registry.py # CheckRegistry (orchestration)
│   │   │   └── adapters/   # Entra ID, AWS, Okta, Wazuh
│   │   ├── db/             # SQLAlchemy models + Neon PostgreSQL
│   │   └── graph/          # Neo4j connection + Cypher queries
│   └── requirements.txt
├── data-ingestion/         # Python ingestion scripts (DS-01 through DS-11)
│   ├── ingest/             # One script per data source
│   ├── crosswalk_loader.py         # Shared loader for regulatory frameworks on the NIST crosswalk
│   └── fix_vuln_correlation_v4.py  # Vulnerability-to-asset correlation
└── ui/                     # Flutter Web frontend
    └── lib/
        ├── screens/        # Dashboard, Blast Radius, Frameworks, Vulnerabilities, Login
        └── services/       # API service layer with JWT auth
```

---

## License

This project is currently **All Rights Reserved** while a formal open-source license is selected. Contact [@munenesimon](https://github.com/munenesimon) for usage permissions.

A license will be added shortly — candidates are MIT (maximum openness) and BSL 1.1 (free for non-commercial use, commercial use requires agreement).

---

## Author

**Simon Munene** · [github.com/munenesimon](https://github.com/munenesimon)

*Built as an independent project to explore graph-based approaches to cybersecurity risk intelligence.*
