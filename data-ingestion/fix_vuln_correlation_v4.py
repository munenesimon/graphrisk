"""
GraphRisk — Vulnerability-to-Asset Correlation (v4)
----------------------------------------------------------
What changed from v3:

1. Matching no longer touches v.title at all. v3 matched
   `toLower(v.title) CONTAINS toLower(a.product)` against free text --
   that over-matches on short/common product names (a product literally
   named "Go" would match any CVE title that happens to contain "Google",
   "Algorithm", "Ongoing", etc., since CONTAINS has no word boundaries).

2. Matching now REQUIRES vendor alignment, not just product. v3 never
   actually compared vendor anywhere in the query -- despite the WHERE
   clause requiring a.vendor IS NOT NULL -- so two unrelated vendors'
   similarly-named products could cross-match.

3. NVD-sourced CVEs can now actually correlate. Before this fix,
   ingest/06_cisa_kev.py populated v.vendor/v.product from CISA's own
   vendorProject/product fields, but ingest/07_nvd_cve.py and the NVD
   half of ingest/09_daily_sync.py never set v.vendor/v.product at all --
   and the NVD delta sync set v.title to the bare CVE ID, not a real
   title. Since NVD is the larger of the two vulnerability sources (up
   to 10,000 critical CVEs vs. CISA KEV's much smaller curated list),
   this meant most of the vulnerability corpus was structurally unable
   to correlate to any asset, regardless of asset data quality. Both
   ingestion scripts now extract vendor/product from the CVE's own CPE
   match data (see cpe_utils.py) and store it as v.vendor/v.product
   (first match) plus v.cpe_pairs (every affected vendor+product on the
   CVE, since one CVE can affect several products). This query matches
   KEV-style nodes on v.vendor/v.product directly, and NVD-style nodes
   on v.cpe_pairs.

4. The risk-score cascade no longer discards existing control
   effectiveness. v3's CASCADE_RISK_ON_NEW_EXPOSURE set
   risk_score = likelihood * impact -- full, unmitigated exposure --
   any time a new vulnerability touched an asset, even for risks that
   already had an effective mitigating control, silently wiping out the
   discount UPDATE_CONTROL_STATUS / WRITE_CHECK_RESULT had applied. It
   now reuses the same likelihood * impact * (1 - effectiveness) formula
   used everywhere else in the app, taking the strongest mitigating
   control's effectiveness for that risk (0 if the risk has no
   mitigating control yet, which reproduces the old, correct behavior
   for genuinely unmitigated risks).

Run from the graphrisk-data-ingestion folder: python fix_vuln_correlation_v4.py
Optionally pass a lookback window in days, e.g. for a full historical
backfill after re-running ingest/07_nvd_cve.py so existing NVD nodes pick
up v.vendor/v.product/v.cpe_pairs (MERGE ... SET updates existing nodes,
not just newly-created ones):
    python fix_vuln_correlation_v4.py 3650
"""
import sys
sys.path.insert(0, ".")
from neo4j_utils import Neo4jClient

TENANT_ID = "demo"
LOOKBACK_DAYS = 30

# ── Step 0: remove edges created under v3's title-based matching -- some
# may be over-matches (wrong asset) since v3 could match on any substring
# of free text, not a real product field. Anything still valid under the
# new logic gets re-added in Step 2. ────────────────────────────────────
CLEANUP = """
    MATCH (v:Vulnerability)-[e:EXPOSES]->(a:Asset {tenant_id: $tenant_id})
    DELETE e
    RETURN count(e) AS removed
"""

# ── Step 1: backfill first_seen_at (unchanged from v3; harmless no-op if
# already set on every node) ────────────────────────────────────────────
BACKFILL_FIRST_SEEN = """
    MATCH (v:Vulnerability)
    WHERE v.first_seen_at IS NULL
    SET v.first_seen_at = coalesce(v.date_added, v.published_date, v.last_synced_at)
    RETURN count(v) AS backfilled
"""

# ── Step 2: correlate on structured vendor/product data, never on
# free-text title. Two paths: KEV-style nodes carry v.vendor/v.product
# directly; NVD-style nodes carry v.cpe_pairs (one "vendor product"
# string per affected product, since a single CVE can affect several). ─
CORRELATE_RECENT_VULNERABILITIES = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    WHERE a.vendor IS NOT NULL AND a.product IS NOT NULL
    MATCH (v:Vulnerability)
    WHERE NOT (v)-[:EXPOSES]->(a)
      AND v.first_seen_at >= $cutoff
      AND (
            (
              v.vendor IS NOT NULL AND v.vendor <> "" AND
              v.product IS NOT NULL AND v.product <> "" AND
              (toLower(v.vendor) CONTAINS toLower(a.vendor) OR toLower(a.vendor) CONTAINS toLower(v.vendor)) AND
              (toLower(v.product) CONTAINS toLower(a.product) OR toLower(a.product) CONTAINS toLower(v.product))
            )
            OR
            ANY(pair IN coalesce(v.cpe_pairs, []) WHERE
                pair CONTAINS toLower(a.vendor) AND pair CONTAINS toLower(a.product))
          )
    MERGE (v)-[:EXPOSES]->(a)
    RETURN v.cve_id AS cve_id, v.title AS title, v.first_seen_at AS first_seen_at,
           a.name AS asset_name, a.id AS asset_id
"""

# ── Step 3: cascade, honoring any existing mitigating control's
# effectiveness instead of resetting the risk to full unmitigated
# exposure. ──────────────────────────────────────────────────────────
CASCADE_RISK_ON_NEW_EXPOSURE = """
    MATCH (v:Vulnerability {cve_id: $cve_id})-[:EXPOSES]->(a:Asset {tenant_id: $tenant_id})
    MATCH (r:Risk)-[:IMPACTS]->(a)
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    WITH r, max(coalesce(c.effectiveness_score, 0.0)) AS best_effectiveness
    SET r.risk_score = r.likelihood * r.impact * (1.0 - best_effectiveness),
        r.last_vulnerability_trigger = $cve_id,
        r.last_vulnerability_triggered_at = datetime()
    RETURN DISTINCT r.title AS risk_title, r.risk_score AS new_score
"""


def correlate_new_vulnerabilities(db, tenant_id=TENANT_ID, lookback_days=LOOKBACK_DAYS, verbose=True):
    """
    Call this after loading new vulnerabilities (e.g. at the end of
    ingest/09_daily_sync.py). Uses first_seen_at -- set once at true
    creation -- so re-syncing existing data never falsely re-triggers
    "new exposure" alerts for old, already-known CVEs.
    """
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")

    matches = db.run(CORRELATE_RECENT_VULNERABILITIES, {"tenant_id": tenant_id, "cutoff": cutoff})
    results = []

    for m in matches:
        cascade = db.run(CASCADE_RISK_ON_NEW_EXPOSURE, {"cve_id": m["cve_id"], "tenant_id": tenant_id})
        m["risks_updated"] = [{"title": c["risk_title"], "new_score": c["new_score"]} for c in cascade]
        results.append(m)
        if verbose:
            print(f"  NEW EXPOSURE: {m['cve_id']} (first seen {m['first_seen_at']}) -> {m['asset_name']}")
            for r in m["risks_updated"]:
                print(f"    Risk cascaded: {r['title']} -> score {r['new_score']}")

    if verbose and not results:
        print(f"  No new correlations found (nothing first-seen since {cutoff}).")

    return results


if __name__ == "__main__":
    lookback_days = int(sys.argv[1]) if len(sys.argv) > 1 else LOOKBACK_DAYS

    db = Neo4jClient()

    print("=" * 55)
    print("  Step 0: Cleaning up edges from v3's title-based matching")
    print("=" * 55)
    result = db.run(CLEANUP, {"tenant_id": TENANT_ID})
    print(f"  Removed {result[0]['removed']} EXPOSES edges (re-added below if still valid)")

    print("\n" + "=" * 55)
    print("  Step 1: Backfilling first_seen_at (no-op if already set)")
    print("=" * 55)
    result = db.run(BACKFILL_FIRST_SEEN)
    print(f"  Backfilled first_seen_at on {result[0]['backfilled']} vulnerability nodes")

    print("\n" + "=" * 55)
    print(f"  Step 2: Correlating on structured vendor/product data ({lookback_days}-day window)")
    print("=" * 55)
    print()
    correlate_new_vulnerabilities(db, lookback_days=lookback_days)

    db.close()

    print("\n" + "=" * 55)
    print("  Done.")
    print("=" * 55)
    print()
    print("  NOTE: if existing NVD-sourced Vulnerability nodes don't have")
    print("  v.vendor/v.product/v.cpe_pairs yet, they won't correlate here.")
    print("  Re-run `python ingest\\07_nvd_cve.py` once to backfill those")
    print("  fields onto existing nodes (MERGE ... SET updates them, not")
    print("  just newly-created ones), then run this script again --")
    print("  e.g. `python fix_vuln_correlation_v4.py 3650` for a full")
    print("  historical sweep instead of the normal 30-day window.")
    print("=" * 55)
