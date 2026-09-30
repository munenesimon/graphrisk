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
# descriptive fields: if data-ingestion's own MERGE_VULN (see
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
    SET v.last_synced_at = toString(datetime())
    RETURN v.id AS id, v.ransomware_use AS ransomware_use
"""
