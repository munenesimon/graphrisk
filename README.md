**Live demo:** `https://graphrisk-735a0.web.app` · **API:** `https://graphrisk.onrender.com` · **Source:** `https://github.com/munenesimon/graphrisk`

# GraphRisk Intelligence Platform

> **Risk is a network, not a list.**

GraphRisk is a graph-based cybersecurity risk intelligence platform that models your security posture as a traversable graph rather than a static spreadsheet. When a control fails, every affected asset, risk, and compliance obligation updates automatically — no manual re-entry.

**Live demo:** `https://graphrisk.onrender.com` · **API docs:** `https://graphrisk.onrender.com/docs`

---

## The Core Insight

Most GRC tools store risk data and report on it. GraphRisk traverses it.

When you mark a control as "Partially Implemented," GraphRisk instantly recalculates every downstream risk score, surfaces every compliance gap across every linked framework, and shows you exactly which assets are now exposed — across NIST 800-53, NIST CSF, CIS Controls, and PCI DSS simultaneously.

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
curl https://graphrisk.onrender.com/api/v1/graph/blast-radius/control/2333d7a2-4a12-4211-ae18-bc82ff502950 \
  -H "X-API-Key: <key>" \
  -H "Authorization: Bearer <token>"
```

**Expected response:** 2 exposed risks, 4 affected assets, 4 framework controls across 2 standards — calculated live from the graph.

---

## What's Actually Built

### Graph Intelligence Engine
- **Blast radius traversal** — given a failing control, instantly surfaces every affected asset, risk, and compliance obligation via Cypher graph traversal. Verified with real math: `risk_score = likelihood × impact × (1 - control_effectiveness)`.
- **Evidence origami** — one evidence artifact (e.g. an MFA enrollment report) automatically satisfies multiple framework requirements across different standards simultaneously, because it maps to a `Control` node already linked to `FrameworkControl` nodes via `SATISFIES` edges.
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
| Sync correlation scope | ⚠️ Daily sync correlates new CVEs for the demo tenant only, not yet per-tenant |
| Production hardening | ⚠️ e2-micro Neo4j VM is memory-constrained (~1.4s query latency) |

---

## Roadmap

- [ ] Per-tenant vulnerability correlation in the daily sync (currently demo-tenant only)
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
├── data-ingestion/         # Python ingestion scripts (DS-01 through DS-10)
│   ├── ingest/             # One script per data source
│   └── fix_vuln_correlation_v3.py  # Vulnerability-to-asset correlation
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
