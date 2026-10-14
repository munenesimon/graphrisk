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
    OPTIONAL MATCH (c:Control)-[m:MITIGATES]->(r)
    WITH a, r, i, collect(DISTINCT CASE WHEN c IS NULL THEN NULL ELSE
         {id: c.id, title: c.title, status: c.implementation_status,
          effectiveness: c.effectiveness_score, strength: m.effectiveness} END) AS controls
    WITH a, collect(CASE WHEN r IS NULL THEN NULL ELSE
         {id: r.id, title: r.title, risk_score: r.risk_score,
          likelihood: r.likelihood, impact: r.impact,
          driver_cves: coalesce(i.driver_cves, []), controls: controls} END) AS risks
    OPTIONAL MATCH (v:Vulnerability)-[e:EXPOSES]->(a)
    WITH a, risks, collect(DISTINCT CASE WHEN v IS NULL THEN NULL ELSE
         {cve_id: v.id, severity: v.severity, cvss_score: v.cvss_score,
          ransomware_use: v.ransomware_use, description: v.description,
          confirmed_by: coalesce(e.sources, []),
          last_seen: toString(e.last_seen)} END) AS vulns
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

# The organisation's risk appetite: the highest residual risk score (0-25)
# it accepts. Null until someone sets it -- the API then uses the default
# in app/scoring.py and says so.
GET_RISK_APPETITE = """
    OPTIONAL MATCH (o:Organisation {tenant_id: $tenant_id})
    RETURN o.risk_appetite AS risk_appetite,
           toString(o.risk_appetite_updated_at) AS updated_at
"""

SET_RISK_APPETITE = """
    MERGE (o:Organisation {tenant_id: $tenant_id})
    SET o.risk_appetite = $risk_appetite, o.risk_appetite_updated_at = datetime()
    RETURN o.risk_appetite AS risk_appetite
"""

# Progress-based control health (see CheckRegistry._apply_progress): remember
# the worst open-issue load a check has reported for this control, so later
# runs can score how much of it has been resolved.
# Worst open-issue load seen per (control, connector), for progress-based
# health (CheckRegistry._apply_progress). Only ever rises. The first Wazuh
# baseline carries over the control-level peak earlier versions kept.
RECORD_PROGRESS_PEAK = """
    OPTIONAL MATCH (c:Control {title: $control_title, tenant_id: $tenant_id})
    WITH CASE WHEN $source = 'wazuh' THEN coalesce(c.peak_open_weight, 0.0) ELSE 0.0 END AS legacy
    MERGE (b:ProgressBaseline {tenant_id: $tenant_id, control_title: $control_title, source: $source})
    ON CREATE SET b.peak_open_weight = CASE WHEN legacy > $open_weight THEN legacy ELSE $open_weight END,
                  b.created_at = datetime()
    ON MATCH SET b.peak_open_weight = CASE WHEN b.peak_open_weight < $open_weight
                                           THEN $open_weight ELSE b.peak_open_weight END
    SET b.updated_at = datetime()
    RETURN b.peak_open_weight AS peak
"""

RECORD_CONTROL_PEAK = """
    MATCH (c:Control {title: $control_title, tenant_id: $tenant_id})
    SET c.peak_open_weight = CASE
            WHEN c.peak_open_weight IS NULL OR c.peak_open_weight < $open_weight THEN $open_weight
            ELSE c.peak_open_weight END
    RETURN c.peak_open_weight AS peak
"""


# ── Framework adherence: obligations, evidence and attestations ─────────────
# One row per requirement (FrameworkControl) with what GraphRisk knows about
# it for this tenant, so "not met" and "not evidenced" are never confused:
#
#   met             a linked control is at (near) full health
#   partial         a linked control is working, but not fully
#   gap             a control is linked but isn't working (health 0)
#   attested        no control is linked, but the organisation has recorded
#                   it as in place (self-declared -- labelled as such)
#   no_evidence     nothing linked and nothing recorded: GraphRisk can't say
#   not_applicable  recorded as not applicable; left out of the totals
#
# A linked control is measured evidence and takes precedence over an
# attestation (except "not applicable", which removes the requirement).
# Controls count directly (SATISFIES) or through the crosswalk (MAPS_TO).
_REQUIREMENT_EVIDENCE = """
    OPTIONAL MATCH (d:Control {tenant_id: $tenant_id})-[:SATISFIES]->(fc)
    WITH f, fc, [x IN collect(DISTINCT d) WHERE x IS NOT NULL |
                 {title: x.title, health: coalesce(x.effectiveness_score, 0.0), via: "direct"}] AS direct
    OPTIONAL MATCH (fc)-[:MAPS_TO]->(:FrameworkControl)<-[:SATISFIES]-(m:Control {tenant_id: $tenant_id})
    WITH f, fc, direct, [x IN collect(DISTINCT m) WHERE x IS NOT NULL |
                 {title: x.title, health: coalesce(x.effectiveness_score, 0.0), via: "crosswalk"}] AS mapped
    OPTIONAL MATCH (a:Attestation {tenant_id: $tenant_id, requirement_id: fc.id})
    WITH f, fc, direct + [c IN mapped WHERE NOT c.title IN [x IN direct | x.title]] AS controls, a
    WITH f, fc, controls, a,
         reduce(h = 0.0, c IN controls | CASE WHEN c.health > h THEN c.health ELSE h END) AS health
    WITH f, fc, controls, a, health,
         CASE WHEN a.status = "not_applicable" THEN "not_applicable"
              WHEN size(controls) > 0 AND health >= 0.95 THEN "met"
              WHEN size(controls) > 0 AND health > 0 THEN "partial"
              WHEN size(controls) > 0 THEN "gap"
              WHEN a.status = "in_place" THEN "attested"
              ELSE "no_evidence" END AS status
    WITH f, fc, controls, a, status, health,
         CASE status WHEN "attested" THEN 1.0 WHEN "no_evidence" THEN 0.0
                     WHEN "not_applicable" THEN 0.0 ELSE health END AS score
"""

FRAMEWORK_ADHERENCE_ALL = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework)
""" + _REQUIREMENT_EVIDENCE + """
    WITH f, count(fc) AS total,
         sum(CASE status WHEN "not_applicable" THEN 1 ELSE 0 END) AS not_applicable,
         sum(CASE status WHEN "met" THEN 1 ELSE 0 END) AS met,
         sum(CASE status WHEN "partial" THEN 1 ELSE 0 END) AS partial,
         sum(CASE status WHEN "gap" THEN 1 ELSE 0 END) AS gap,
         sum(CASE status WHEN "attested" THEN 1 ELSE 0 END) AS attested,
         sum(CASE status WHEN "no_evidence" THEN 1 ELSE 0 END) AS no_evidence,
         sum(score) AS score_sum
    OPTIONAL MATCH (o:Organisation {tenant_id: $tenant_id})-[:SUBJECT_TO]->(f)
    RETURN f.id AS framework_id, f.name AS framework, f.version AS version,
           coalesce(f.category, "standard") AS category, o IS NOT NULL AS applies,
           total, not_applicable, met, partial, gap, attested, no_evidence, score_sum
    ORDER BY applies DESC, f.name
"""

FRAMEWORK_REQUIREMENTS = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id: $framework_id})
""" + _REQUIREMENT_EVIDENCE + """
    OPTIONAL MATCH (o:Organisation {tenant_id: $tenant_id})-[:SUBJECT_TO]->(f)
    RETURN f.name AS framework, o IS NOT NULL AS applies,
           fc.id AS id, fc.control_reference AS control_reference, fc.title AS title,
           fc.domain AS domain, fc.graphrisk_summary AS summary, fc.official_url AS official_url,
           fc.requirement_type AS requirement_type, controls, status, score,
           CASE WHEN a IS NULL THEN null ELSE {status: a.status, note: a.note,
                evidence_url: a.evidence_url, attested_by: a.attested_by,
                attested_at: toString(a.attested_at)} END AS attestation
    ORDER BY fc.control_reference
"""

# Self-declared evidence for a requirement no connector can measure (a
# policy, a plan, training...). One per (tenant, requirement); re-saving
# replaces it. Returns nothing when the requirement isn't in that framework.
SET_ATTESTATION = """
    MATCH (fc:FrameworkControl {id: $requirement_id})-[:PART_OF]->(:Framework {id: $framework_id})
    MERGE (a:Attestation {tenant_id: $tenant_id, requirement_id: $requirement_id})
    SET a.status = $status, a.note = $note, a.evidence_url = $evidence_url,
        a.attested_by = $attested_by, a.attested_at = datetime()
    MERGE (a)-[:ATTESTS]->(fc)
    RETURN a.status AS status
"""

DELETE_ATTESTATION = """
    MATCH (a:Attestation {tenant_id: $tenant_id, requirement_id: $requirement_id})
    DETACH DELETE a
    RETURN count(*) AS deleted
"""


# ── Device findings: only what a scan actually saw on the device ─────────────
# A CVE linked to a device by a scanner (Wazuh, Qualys, CrowdStrike...) records
# which scanners reported it and when it was last seen, on the link itself.
# `sources` is a list so two scanners reporting the same CVE on one device
# don't overwrite each other: each run only ever adds or removes its own name.
LINK_SCANNED_VULNERABILITY = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    MATCH (v:Vulnerability {cve_id: $cve_id})
    MERGE (v)-[e:EXPOSES]->(a)
    SET e.sources    = CASE WHEN $source IN coalesce(e.sources, []) THEN e.sources
                            ELSE coalesce(e.sources, []) + $source END,
        e.evidence   = "scan",
        e.first_seen = coalesce(e.first_seen, datetime()),
        e.last_seen  = datetime()
    RETURN a.name AS asset, v.cve_id AS cve_id
"""

# After a scanner has reported a device's COMPLETE current findings, drop
# everything on that device the scan no longer supports:
#   * a CVE this scanner reported before but not now -- patched or removed;
#     the link goes once no scanner still reports it
#   * a link with no scanner behind it at all (`sources` unset) -- older
#     links, and guesses made from the device's vendor/product NAME alone
#     (e.g. every "Microsoft Windows" CVE ever published), which say nothing
#     about this device's actual version
# then trims each connector-made risk link's recorded CVEs to the ones still
# on the device, and removes the risk link when none are left. Links added by
# hand (no recorded CVEs) are never touched. Only run on a complete scan: a
# failed or truncated fetch must not read as "everything was fixed".
RECONCILE_SCANNED_VULNERABILITIES = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (v:Vulnerability)-[e:EXPOSES]->(a)
    WHERE NOT v.cve_id IN $seen AND (e.sources IS NULL OR $source IN e.sources)
    WITH a, collect(e) AS stale
    WITH a, stale,
         [x IN stale WHERE size([s IN coalesce(x.sources, []) WHERE s <> $source]) = 0] AS gone
    FOREACH (x IN stale | SET x.sources = [s IN coalesce(x.sources, []) WHERE s <> $source])
    FOREACH (x IN gone | DELETE x)
    WITH a, size(gone) AS removed
    OPTIONAL MATCH (:Risk)-[i:IMPACTS]->(a)
    WHERE i.driver_cves IS NOT NULL AND i.source IS NOT NULL
    WITH a, removed, i,
         [c IN coalesce(i.driver_cves, []) WHERE
            size([(:Vulnerability {cve_id: c})-[:EXPOSES]->(a) | 1]) > 0] AS kept
    WITH a, removed, i, kept,
         CASE WHEN i IS NULL THEN 0 ELSE size(i.driver_cves) - size(kept) END AS dropped,
         CASE WHEN i IS NOT NULL AND size(kept) = 0 THEN 1 ELSE 0 END AS unlinked
    FOREACH (_ IN CASE WHEN i IS NOT NULL AND size(kept) > 0 THEN [1] ELSE [] END |
             SET i.driver_cves = kept)
    FOREACH (_ IN CASE WHEN unlinked = 1 THEN [1] ELSE [] END | DELETE i)
    RETURN removed, sum(dropped) AS drivers_dropped, sum(unlinked) AS risks_unlinked
"""


# Each of the organisation's own controls with how well it is working now,
# for the dashboard. effectiveness_score is the control's health (0..1):
# written by the latest connector check for it, or set from the status
# chosen by hand. last_check_* say which check set it and when.
DASHBOARD_CONTROLS_DETAIL = """
    MATCH (c:Control {tenant_id: $t})
    RETURN c.id AS id, c.title AS title, c.implementation_status AS status,
           c.effectiveness_score AS health, c.last_check_source AS source,
           c.last_check_detail AS detail, toString(c.last_tested_at) AS last_tested_at
    ORDER BY c.title
"""


# Overrides graphrisk-core's WRITE_CHECK_RESULT: the control status now
# comes from implementation_status_for() in connectors/registry.py (graded
# by health, so a failing check on a control that partly works reads
# "PartiallyImplemented", not "NotImplemented"). A null status leaves the
# control's status as it was. Move into graphrisk-core when convenient.
import graphrisk_core.queries as _core_queries  # noqa: E402
_RECOMPUTE_RISK = getattr(_core_queries, "_RECOMPUTE_RISK", "")

WRITE_CHECK_RESULT = """
    MATCH (c:Control {title: $control_title, tenant_id: $tenant_id})
    SET c.implementation_status = coalesce($implementation_status, c.implementation_status),
        c.effectiveness_score = $score,
        c.last_tested_at      = datetime(),
        c.last_check_source   = $source,
        c.last_check_detail   = $detail
    WITH c
    CALL {
        WITH c
        MATCH (c)-[:MITIGATES]->(r:Risk)
        WITH DISTINCT r
""" + _RECOMPUTE_RISK + """
        RETURN count(r) AS risks_updated
    }
    RETURN c.title AS control, risks_updated
"""
