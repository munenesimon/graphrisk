# The graph-traversal queries (blast radius, vendor breach cascade,
# framework coverage, etc.) now live in the private `graphrisk-core`
# package -- see https://github.com/munenesimon/graphrisk-core.
# Render installs it during build (see the Build Command in Settings ->
# Build & Deploy); locally, run `pip install -e ../../graphrisk-core`
# (or wherever you've cloned it) to develop against it.
from graphrisk_core.queries import *  # noqa: F401,F403


# ── Local additions (not yet part of graphrisk-core) ────────────────────────
# The queries above come from the private graphrisk-core package (see the
# comment at the top of this file). Everything below is new, added directly
# here rather than in that package, since this checkout doesn't have
# graphrisk-core connected to develop against it. Move into graphrisk-core
# whenever convenient -- nothing about where these constants live matters to
# the code that calls them, which only ever does `queries.SOME_NAME`.

# Ensures a Vulnerability node exists for a CVE a *connector* (not the
# offline NVD/CISA-KEV bulk ingestion in data-ingestion/) discovered directly
# on a monitored asset -- e.g. Wazuh's indexer-backed vulnerability
# detection, which draws heavily on OSV/GitHub Security Advisories for
# OS-package and language-ecosystem (npm, pip, ...) CVEs that plain NVD/CISA
# KEV ingestion never covers. Deliberately ON CREATE SET only for the
# descriptive fields (cvss_score and description are only *filled in*
# when missing -- see the SET below): if data-ingestion's own MERGE_VULN (see
# data-ingestion/ingest/07_nvd_cve.py) already populated this same CVE id
# from NVD, a connector's scan of one device shouldn't overwrite that
# curated record -- it should just confirm the node exists and move on to
# linking it to the asset (see LINK_VULNERABILITY_TO_ASSET). Also returns
# ransomware_use -- unset on a connector-created node itself, but if this
# same cve_id was already NVD/CISA-KEV-ingested (data-ingestion sets it
# from CISA KEV's knownRansomwareCampaignUse), that flag survives
# untouched here, and CheckRegistry._ensure_risk_for_finding reads it back
# to decide which Risk a Critical/High finding should cascade into (see
# ENSURE_RISK_FOR_VULNERABILITY in graphrisk-core).
MERGE_VULNERABILITY_FROM_FINDING = """
    MERGE (v:Vulnerability {id: $cve_id})
    ON CREATE SET
        v.cve_id           = $cve_id,
        v.description      = $description,
        v.cvss_score       = $cvss_score,
        v.severity         = $severity,
        v.published_at     = $published_at,
        v.source           = $source,
        v.patch_available  = false,
        v.first_seen_at    = toString(datetime())
    SET v.last_synced_at = toString(datetime()),
        // Fill-in only, never overwrite: CISA KEV publishes no CVSS, so a
        // KEV-ingested node carries cvss_score 0.0 (see data-ingestion's
        // 09_daily_sync.py) until NVD fills it. When the scanner that found
        // the CVE on a real device knows the score, use it rather than
        // showing "CVSS 0.0" next to a High/Critical finding.
        v.cvss_score = CASE
            WHEN coalesce(v.cvss_score, 0.0) = 0.0 AND coalesce($cvss_score, 0.0) > 0.0
            THEN $cvss_score ELSE v.cvss_score END,
        v.description = CASE
            WHEN coalesce(v.description, '') = '' THEN $description
            ELSE v.description END
    RETURN v.id AS id, v.ransomware_use AS ransomware_use
"""


# ── Universal device profile (see app/connectors/profile.py) ────────────────
# One snapshot node per (asset, connector, section). The data itself is a
# JSON string -- Neo4j properties can't hold nested maps -- and is only ever
# read back whole, never queried into.
UPSERT_ASSET_PROFILE_SECTION = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    MERGE (a)-[:HAS_PROFILE]->(p:AssetProfileSection {
        asset_id: $asset_id, tenant_id: $tenant_id, source: $source, section: $section
    })
    SET p.data = $data, p.collected_at = $collected_at
    RETURN p.section AS section
"""

GET_ASSET_PROFILE_SECTIONS = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})-[:HAS_PROFILE]->(p:AssetProfileSection)
    RETURN p.source AS source, p.section AS section, p.data AS data, p.collected_at AS collected_at
"""

# Everything the asset page shows besides the profile itself: the asset's
# own properties, the risks it's under (with the CVEs recorded as each
# link's root cause, and the controls mitigating each risk), and the
# vulnerabilities linked to it.
GET_ASSET_DETAIL = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (r:Risk)-[i:IMPACTS]->(a)
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    WITH a, r, i, collect(DISTINCT CASE WHEN c IS NULL THEN NULL ELSE
         {id: c.id, title: c.title, status: c.implementation_status,
          effectiveness: c.effectiveness_score} END) AS controls
    WITH a, collect(CASE WHEN r IS NULL THEN NULL ELSE
         {id: r.id, title: r.title, risk_score: r.risk_score,
          likelihood: r.likelihood, impact: r.impact,
          driver_cves: coalesce(i.driver_cves, []), controls: controls} END) AS risks
    OPTIONAL MATCH (v:Vulnerability)-[:EXPOSES]->(a)
    WITH a, risks, collect(DISTINCT CASE WHEN v IS NULL THEN NULL ELSE
         {cve_id: v.id, severity: v.severity, cvss_score: v.cvss_score,
          ransomware_use: v.ransomware_use, description: v.description} END) AS vulns
    OPTIONAL MATCH (a)-[d:POSSIBLY_SAME_AS]-(other:Asset {tenant_id: $tenant_id})
    WITH a, risks, vulns, collect(DISTINCT CASE WHEN other IS NULL THEN NULL ELSE
         {id: other.id, name: other.name, reason: d.reason} END) AS possible_duplicates
    RETURN a {.*} AS asset, risks, vulns AS vulnerabilities, possible_duplicates
"""

# Device identifiers recorded on each asset, for matching one device across
# connectors (see CheckRegistry._ingest_assets and profile.device_keys).
GET_ASSET_IDENTIFIERS = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    RETURN a.id AS id, a.name AS name,
           coalesce(a.device_serials, []) AS serial,
           coalesce(a.device_macs, []) AS mac,
           coalesce(a.device_instance_ids, []) AS instance,
           coalesce(a.device_hostnames, []) AS hostname
"""

# Adds identifiers (and, when a record was merged in under another name, that
# name as an alias) to an asset, keeping each list free of duplicates.
MERGE_ASSET_IDENTIFIERS = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    SET a.device_serials = reduce(acc = [], x IN coalesce(a.device_serials, []) + $serial |
            CASE WHEN x IN acc THEN acc ELSE acc + x END),
        a.device_macs = reduce(acc = [], x IN coalesce(a.device_macs, []) + $mac |
            CASE WHEN x IN acc THEN acc ELSE acc + x END),
        a.device_instance_ids = reduce(acc = [], x IN coalesce(a.device_instance_ids, []) + $instance |
            CASE WHEN x IN acc THEN acc ELSE acc + x END),
        a.device_hostnames = reduce(acc = [], x IN coalesce(a.device_hostnames, []) + $hostname |
            CASE WHEN x IN acc THEN acc ELSE acc + x END),
        a.aliases = reduce(acc = [], x IN coalesce(a.aliases, []) + $aliases |
            CASE WHEN x IN acc THEN acc ELSE acc + x END)
    RETURN a.id AS id
"""

# Two assets that share only a hostname: flagged for a person to judge,
# never merged automatically.
LINK_POSSIBLE_DUPLICATE = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id}), (b:Asset {id: $other_id, tenant_id: $tenant_id})
    MERGE (a)-[r:POSSIBLY_SAME_AS]->(b)
    SET r.reason = $reason, r.detected_at = $detected_at
    RETURN a.id AS id
"""
