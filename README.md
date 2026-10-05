# GraphRisk Intelligence Platform

> **Risk is a network, not a list.**

GraphRisk is a graph-based cybersecurity risk intelligence platform that models your security posture as a traversable graph rather than a static spreadsheet. When a control fails, every affected asset, risk, and compliance obligation updates automatically — no manual re-entry.

**Live app:** [graphrisk-735a0.web.app](https://graphrisk-735a0.web.app) · **API:** `https://graphrisk.onrender.com` · **API docs:** [graphrisk.onrender.com/docs](https://graphrisk.onrender.com/docs)

---

## The Core Insight

Most GRC tools store risk data and report on it. GraphRisk traverses it.

When you mark a control as "Partially Implemented," GraphRisk instantly recalculates every downstream risk score, surfaces every compliance gap across every linked framework, and shows you exactly which assets are now exposed — across NIST 800-53, NIST CSF, CIS Controls, PCI DSS and Kenyan regulation (the Data Protection Act and Central Bank of Kenya cybersecurity guidance) simultaneously — and tells you which regulator notification deadlines would start if it's exploited.

One change. Automatic cascade. No spreadsheet.

---

## Where It Fits

GraphRisk isn't meant to replace the security and compliance tools an organisation already uses. It sits on top of them and connects what they report into one picture of risk.

- **Monitoring and scanning tools** (SIEM/XDR, endpoint protection, vulnerability scanners, identity providers) report what's happening on each device and account. GraphRisk pulls those findings in through connectors and links them to the organisation's risks, controls and assets.
- **Compliance programmes** track whether each control is in place. GraphRisk adds what a control's failure would expose, and which obligations — including Kenyan regulation — that touches.
- **Risk registers** list risks. GraphRisk ties each one to the assets it affects and the specific CVEs behind it, so the register reflects what the tools are actually finding.

It's built with organisations in Kenya and East Africa in mind: those that need to meet the Data Protection Act and sector cybersecurity rules, may already run open-source tooling such as Wazuh, and want one place to see how technical findings translate into risk and regulatory exposure.

---

## Try It

### In the browser (no setup)

1. Open [graphrisk-735a0.web.app](https://graphrisk-735a0.web.app) and click **Use demo credentials**, then **Log in**.
2. You're in the demo organisation — a Kenyan commercial bank. Things worth trying:
   - **Blast Radius** — pick a control from the dropdown (e.g. *Multi-Factor Authentication*). **List** view shows the full cascade, with a **Root cause** under each exposed risk and asset (the CVEs behind the link, with severity, CVSS and a *Known ransomware use* flag from CISA KEV); **Graph** view shows the control at the hub with one node per category — tap a category to expand it (only one opens at a time), and tap any item for its details.
   - **Frameworks** — tap a framework to see exactly which of its requirements are covered (directly, or via the NIST crosswalk) and which aren't.
   - **Vulnerabilities**, **Assets**, **Regulatory** — real CVE impact, the asset inventory, and the notification duties that follow from the regulatory profile. Tap an asset for its own page: everything its connectors report about the device, and what to patch first.

The demo is **read-only**: everyone shares it, so saving connector credentials, running connectors and editing data are switched off there (the API returns `403`). To try those, register your own account.

### With your own account

Click **Register** on the login screen and enter an organisation name — you get your own empty, private tenant. A new tenant needs a few controls and risks before connector results have anything to land on; `api/seed_real_tenant.py` creates that starter set (it needs the API key — request one via a GitHub issue).

### With your own Wazuh

The Wazuh connector reads agents, SCA (configuration) results and — optionally, via the Wazuh indexer — per-device CVE findings. Because the API runs in the cloud, your Wazuh manager API (port 55000) must be reachable over public HTTPS; for a lab or home setup, a tunnel such as [ngrok](https://ngrok.com) works. Private and LAN addresses are deliberately rejected. In your own tenant: **Connectors → Wazuh**, enter the manager URL and a Wazuh **API** user (e.g. `wazuh-wui`, not the dashboard `admin` login), save, and run. Each agent becomes an asset; Critical/High CVEs reported for it become linked risks, so the device shows up in Blast Radius — with the specific CVEs listed as its root cause.

Per-device CVEs come from the Wazuh **indexer** (port 9200), which needs its own public HTTPS address (a second tunnel — e.g. a [Cloudflare quick tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/), since ngrok's free plan allows one endpoint) and must listen on more than `localhost` (`network.host` in `/etc/wazuh-indexer/opensearch.yml`). Enter its URL and the indexer user (e.g. `admin`) in the same connector form. Saving only updates the fields you fill in.

---

## API Walkthrough

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

As in the browser, the demo account is read-only through the API: `GET` requests work, anything that changes data returns `403`.

---

## What's Actually Built

### Graph Intelligence Engine
- **Blast radius traversal** — given a failing control, instantly surfaces every affected asset, risk, and compliance obligation via Cypher graph traversal. Verified with real math: `risk_score = likelihood × impact × (1 - control_effectiveness)`.
- **Evidence origami** — one evidence artifact (e.g. an MFA enrollment report) automatically satisfies multiple framework requirements across different standards simultaneously, because it maps to a `Control` node already linked to `FrameworkControl` nodes via `SATISFIES` edges.
- **Regulatory crosswalk** — requirements from the Kenya Data Protection Act 2019, the CBK Guidance Note on Cybersecurity (banks), the CBK Guideline on Cybersecurity for Payment Service Providers and the 2024 Critical Information Infrastructure Regulations are linked to the NIST 800-53 and CSF controls they correspond to via `MAPS_TO` edges, so controls a tenant already has count toward Kenyan obligations with no extra mapping work. Coverage is reported as direct vs. via-crosswalk, and only controls that are actually in place (Implemented or Partially Implemented) count. Blast-radius results group frameworks into standards, the organisation's own regulations and other regulations the control supports; `?scope=applicable` shows only what applies.
- **Regulatory notification clocks** — each organisation declares which frameworks it's subject to and which assets hold personal data. Blast-radius and vulnerability-impact results then list the notification duties that would apply if the exposure became a breach: who to notify, the deadline (2, 24, 48 or 72 hours), the legal source, and which affected assets trigger it. A Kenyan bank can face three separate clocks from one incident; GraphRisk shows all of them, and only the ones that actually apply.
- **Vendor breach cascade** — given a third-party vendor breach, the graph traverses `PROVIDES → Asset → Risk` edges to surface every activated risk and flag any under-implemented mitigating controls.
- **Connector-discovered assets** — connectors can report the devices they see, not just pass/fail checks. Each Wazuh agent becomes an `Asset`; per-device Critical/High CVE findings become `Vulnerability` nodes linked to it and roll into tenant risks (CISA-KEV ransomware-flagged CVEs into *Ransomware Infection Risk*, the rest into *Unpatched Vulnerability Risk*), reusing whatever controls already mitigate those risks — so a real device appears in Blast Radius as soon as it has real findings.
- **Root cause provenance** — every connector-created `Risk → Asset` link records the CVEs that caused it (`IMPACTS.driver_cves`). Blast Radius returns them per link, ransomware-flagged first and then by CVSS, so "this laptop is exposed to Ransomware Infection Risk" comes with *why*: e.g. two WinRAR CVEs CISA lists as used in ransomware campaigns — and therefore what to patch.
- **Universal device profile** — every connector that can see devices maps what it knows onto one vendor-neutral profile (identity, health, OS, hardware, network, software, vulnerabilities, configuration, protection, ownership, cloud, activity). Each connector declares which sections it can fill, so the asset page shows whatever the connected tools provide, labels every section with its source, and says which connector could fill what's missing. The page leads with **Fix first**: vulnerable software grouped by package, ransomware-linked first ("update WinRAR", not two CVE ids). IPs, MAC addresses, serials and assigned users are shown to owners/admins only.
- **One device, many tools** — when several connectors report the same machine, their records merge into one asset if they share a serial number, MAC address (virtual/VPN/randomised MACs excluded) or cloud instance id. A shared hostname alone is flagged as "possibly the same device" rather than merged, since wrongly combining two machines is worse than showing one twice.
- **Per-requirement framework coverage** — beyond the coverage percentage, every requirement in a framework is reported as covered directly, covered via the crosswalk, or not covered, along with which of the tenant's controls satisfy it.
- **Automatic vulnerability correlation** — bidirectional: daily threat intelligence sync auto-links newly-published CVEs to matching assets by vendor/product name (with structured CPE-based matching, not free-text search), and newly-onboarded assets are immediately checked against the full vulnerability history at creation time. Either direction cascades risk score updates without manual triage.

### Universal Connector Architecture
A three-layer adapter pattern (BaseConnector → per-vendor Adapter → CheckRegistry) lets any security tool plug into the graph with minimal new code, regardless of its authentication style.

| Connector | Auth Pattern | Checks | Validation | Device profile |
|---|---|---|---|---|
| Mock | None | 1 | Live Neo4j write + risk cascade verified | — |
| Microsoft Entra ID | OAuth 2.0 client credentials | 6 | Structurally complete | Directory devices: join type, OS, last sign-in, managed/compliant (offline-verified) |
| AWS | SDK-managed IAM keys (boto3) | 5 | Offline-verified via moto | EC2 instances: state, platform, addresses, region, instance type, security groups, internet exposure (offline-verified via moto) |
| Okta | Static API key header | 5 | Offline-verified via responses | Registered devices: model, serial, OS, assigned user, managed, disk encryption (offline-verified) |
| Wazuh | HTTP Basic → session JWT (self-hosted SIEM/XDR) | 2 | Live-verified against a self-hosted manager and indexer: agent connectivity, SCA, and per-device CVE findings flowing through to Blast Radius root cause | Identity, health, OS, hardware, network & ports, software, vulnerability counts, configuration benchmarks with failed checks (offline-verified; pending a live run of the new profile fields) |
| CrowdStrike Falcon | OAuth 2.0 client credentials | 4 | Offline-verified via responses; pending a live tenant | Hosts, sensor/prevention status, last user, cloud placement, open detections, Spotlight findings per host (offline-verified) |
| Qualys VM | HTTP Basic (per request), XML-only API | 4 | Offline-verified via responses; pending a live subscription | Hosts (identity, OS, IP), confirmed severity 4-5 counts, last scan (offline-verified) |

Adding a new vendor means writing one adapter file (~150 lines) and one registration line. The registry, graph write, and cascade logic never change. Qualys's VM API is the one exception worth calling out: it's XML-only (no JSON output option), so that adapter parses responses with Python's built-in `xml.etree.ElementTree` rather than pulling in a new dependency for one vendor.

Credentials can be saved per tenant (Fernet-encrypted at rest, Neo4j-backed, owner/admin only) so a connector doesn't need its config re-entered on every run — a later run automatically merges in the saved values, and typing a new value for one run never overwrites what's saved unless you explicitly hit Save again. Saved values are never returned to the client; the API reports only which config keys are set. Live-verified end to end: saved Entra ID test credentials were picked up on a subsequent run with every field left blank (visible as a real, correctly-rejected OAuth request to Microsoft's token endpoint), and clearing them removed the saved state immediately, confirmed after a full logout/login cycle.

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
| Kenya Data Protection Act 2019 (+ 2021 Regulations) | 27 requirements, 70 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CBK Guidance Note on Cybersecurity (banks, 2017) | 19 requirements, 48 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CBK Guideline on Cybersecurity for PSPs (2019) | 21 requirements, 50 NIST crosswalk mappings | Static (GraphRisk-curated) |
| CMCA Critical Information Infrastructure Regulations 2024 | 3 requirements, 7 NIST crosswalk mappings | Static (GraphRisk-curated) |
| AI-generated summaries | 1,999 nodes | Generated once via Claude |

### Multi-Tenant Authentication
JWT-based authentication backed by PostgreSQL (Neon). Every data-bearing endpoint derives `tenant_id` from the verified JWT — not from a client-supplied query parameter. Tenant isolation is enforced at the graph query level. Tenants listed in `READ_ONLY_TENANTS` (the shared demo, by default) can be read but not changed through the API; `seed_demo.py` reseeds it with a server-side `MAINTENANCE_TOKEN`.

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

> **Note:** the Cypher query library lives in a separate private package, `graphrisk-core`, which `api/app/graph/queries.py` imports and which isn't in `requirements.txt`. Without access to it the API won't start from this repo alone — the hosted app above is the way to try GraphRisk. The test suite doesn't need it (see below).

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
The demo tenant is read-only by default, so for a local server either set `READ_ONLY_TENANTS=` (empty) in `.env`, or set the same `MAINTENANCE_TOKEN` in both `.env` and your shell before seeding.

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

**Running the tests** (no database or `graphrisk-core` needed — the suite stubs both):
```bash
cd api
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q
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
| Persistent connector credentials | ✅ Fernet-encrypted at rest (Neo4j-backed), owner/admin only, values never returned to the client — live-verified save → reuse → clear cycle in the Flutter UI |
| Vulnerability-to-asset correlation | ✅ Automated — daily sync + at asset onboarding |
| Flutter Web frontend | ✅ Live on Firebase Hosting — each screen has its own URL (browser Back/Forward work), and the session survives a reload for the life of the tab |
| Shared public demo | ✅ Read-only through the API (writes return 403), so visitors can't change data or store credentials in the shared tenant |
| New-tenant onboarding | ⚠️ A fresh tenant needs starter controls/risks before connector results show up; today that's `seed_real_tenant.py` (needs the API key), not an in-app step |
| Self-hosting | ⚠️ The API depends on the private `graphrisk-core` query package, so it can't be run from this repo alone |
| Multi-tenancy | ✅ JWT-enforced tenant scoping on every data endpoint (PostgreSQL on Neon free tier) |
| GitHub Actions daily sync | ✅ Running reliably against Google Cloud Neo4j (18/19 recent runs succeeded) |
| Connector coverage | ⚠️ 7 connectors so far (Wazuh live-verified); more planned, and each new one is a single adapter file |
| Sync correlation scope | ℹ️ Daily sync correlates new CVEs against the demo tenant by design — that's the account anyone testing GraphRisk logs into, so it stays populated with live data rather than sitting on months-old seed data. Not yet extended to arbitrary tenants. |
| Kenyan regulatory crosswalk | ⚠️ GraphRisk-curated mappings, not an official crosswalk — coverage means mapped controls are in place, not legal compliance (not legal advice). All 27 Data Protection Act / General Regulations 2021 requirements now cite the exact statutory section or regulation sub-clause (verified against the primary text, including regulation 32(a)-(k) of the 2021 Regulations in full). |
| Regulatory clocks | ⚠️ Driven by a self-declared regulatory profile and per-asset personal-data flags. Deadlines run from becoming aware of a breach, and whether an incident is "significant" enough to report is a human judgement GraphRisk doesn't make — it shows the duty and its condition. Live in the Flutter UI (Regulatory Profile screen, Assets screen, and as a layer on Blast Radius / Vulnerability Impact) as well as the API. |
| Root cause | ✅ Live — CVEs behind each connector-created risk link, with CISA KEV ransomware flag. Links created before this feature (or by hand) show "No CVE recorded" until the connector runs again. CISA KEV publishes no CVSS, so a KEV-only CVE shows severity alone until NVD or the scanner supplies a score. |
| Device profiles | ⚠️ All seven connectors map devices onto the shared profile, but only offline-verified so far — Wazuh is the first to be checked live. The new device checks (AWS EC2 exposure, Entra device compliance, Okta disk encryption) need extra read permissions (`ec2:Describe*`, `Device.Read.All`, `okta.devices.read`); without them that one check errors and the rest still run. Cross-tool merging only happens on serial/MAC/instance id; hostname matches are flagged for review. |
| Connector scheduling | ⚠️ Connectors run on demand; no scheduled runs yet. Self-hosted tools behind a quick tunnel need the tunnel up (and its URL re-saved if it changed) for each run. |
| Production hardening | ⚠️ e2-micro Neo4j VM is memory-constrained (~1.4s query latency) |

---

## Roadmap

- [x] Regulatory profile, personal-data flags and notification clocks in the Flutter UI
- [ ] Real vendor credential testing (AWS free tier, Okta developer org, CrowdStrike/Qualys trial)
- [x] Wazuh connector live-data validation (agent connectivity + SCA)
- [x] Wazuh indexer vulnerability detection — live validation
- [x] Root cause (driving CVEs) for each exposed risk and asset
- [ ] Scheduled connector runs
- [ ] Downloadable compliance / blast-radius report (audit evidence)
- [ ] CrowdStrike / Qualys connector live-data validation (pending real tenants)
- [ ] In-app starter setup for newly registered tenants
- [x] Universal device profile and asset page, with connector capabilities
- [x] Device profiles for all seven connectors; one device across tools merged on hardware identifiers
- [ ] Live validation of device profiles beyond Wazuh
- [ ] Confirm or dismiss "possibly the same device" from the asset page
- [x] CrowdStrike / Qualys connector adapters
- [x] Connector management UI in Flutter
- [x] Persistent encrypted connector credential storage
- [x] Graph visualization for blast radius (expandable hub-and-spoke view)
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
│   │   │   ├── crypto.py   # Fernet encryption for saved credentials
│   │   │   └── adapters/   # Entra ID, AWS, Okta, Wazuh, CrowdStrike, Qualys
│   │   ├── db/             # SQLAlchemy models + Neon PostgreSQL
│   │   └── graph/          # Neo4j connection + Cypher queries
│   ├── tests/              # pytest suite (graph + private query package stubbed)
│   ├── seed_demo.py        # Seeds the shared demo tenant
│   ├── seed_real_tenant.py # Starter controls/risks for a real tenant
│   └── requirements.txt
├── data-ingestion/         # Python ingestion scripts (DS-01 through DS-11)
│   ├── ingest/             # One script per data source
│   ├── crosswalk_loader.py         # Shared loader for regulatory frameworks on the NIST crosswalk
│   └── fix_vuln_correlation_v4.py  # Vulnerability-to-asset correlation
└── ui/                     # Flutter Web frontend
    └── lib/
        ├── constants/      # Colors, API config, framework display names, connector metadata
        ├── screens/        # Dashboard, Blast Radius, Frameworks, Vulnerabilities, Assets,
        │                   # Regulatory Profile, Connectors, Login
        ├── widgets/        # Shared widgets (e.g. regulatory notification-clocks card)
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
