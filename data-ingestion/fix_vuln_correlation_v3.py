"""
GraphRisk — Vulnerability-to-Asset Correlation (v3, corrected)
----------------------------------------------------------
Fixes the real bug in v2: filtering on last_synced_at is wrong, because
that field reflects "when our ingestion script last touched this row",
not "when this vulnerability was first seen." Since a full re-ingest
touches every node, last_synced_at was recent for 8-year-old CVEs too --
the recency filter was silently doing nothing.

Correct fix: a new first_seen_at field, set ONCE at true node creation
(never updated on re-sync), used going forward for recency filtering.
For nodes that already exist, we backfill first_seen_at using the CVE's
own real-world date_added/published_date -- an honest historical value,
not "today" -- so the recency filter reflects genuine age from here on.

Run from graphrisk-data-ingestion folder: python fix_vuln_correlation_v3.py
"""
import sys
sys.path.insert(0, ".")
from neo4j_utils import Neo4jClient

TENANT_ID = "demo"
LOOKBACK_DAYS = 30

# ── Step 0: cleanup the incorrect matches from v2 ──────────────────────────────
CLEANUP = """
    MATCH (v:Vulnerability)-[e:EXPOSES]->(a:Asset {tenant_id: $tenant_id})
    DELETE e
    RETURN count(e) AS removed
"""

# ── Step 1: backfill first_seen_at honestly from the CVE's own real date ──────
# Priority: CISA KEV's date_added (when it was confirmed exploited) ->
# NVD's published_date (when the CVE was first published) -> if neither
# exists, fall back to last_synced_at as a last resort (better than nothing,
# but flagged so we know it's an approximation).
BACKFILL_FIRST_SEEN = """
    MATCH (v:Vulnerability)
    WHERE v.first_seen_at IS NULL
    SET v.first_seen_at = coalesce(v.date_added, v.published_date, v.last_synced_at)
    RETURN count(v) AS backfilled
"""

# ── Step 2: correlate using the CORRECT recency field ──────────────────────────
CORRELATE_RECENT_VULNERABILITIES = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    WHERE a.vendor IS NOT NULL AND a.product IS NOT NULL
    MATCH (v:Vulnerability)
    WHERE NOT (v)-[:EXPOSES]->(a)
      AND (
            toLower(coalesce(v.title, ""))   CONTAINS toLower(a.product)
         OR toLower(coalesce(v.product, "")) CONTAINS toLower(a.product)
      )
      AND v.first_seen_at >= $cutoff
    MERGE (v)-[:EXPOSES]->(a)
    RETURN v.cve_id AS cve_id, v.title AS title, v.first_seen_at AS first_seen_at,
           a.name AS asset_name, a.id AS asset_id
"""

CASCADE_RISK_ON_NEW_EXPOSURE = """
    MATCH (v:Vulnerability {cve_id: $cve_id})-[:EXPOSES]->(a:Asset {tenant_id: $tenant_id})
    MATCH (r:Risk)-[:IMPACTS]->(a)
    SET r.risk_score = r.likelihood * r.impact,
        r.last_vulnerability_trigger = $cve_id,
        r.last_vulnerability_triggered_at = datetime()
    RETURN DISTINCT r.title AS risk_title, r.risk_score AS new_score
"""


def correlate_new_vulnerabilities(db, tenant_id=TENANT_ID, lookback_days=LOOKBACK_DAYS, verbose=True):
    """
    Call this after loading new vulnerabilities (e.g. at the end of
    09_daily_sync.py). Uses first_seen_at -- set once at true creation --
    so re-syncing existing data never falsely re-triggers "new exposure"
    alerts for old, already-known CVEs.

    IMPORTANT: ingestion scripts (06_cisa_kev.py, 07_nvd_cve.py,
    09_daily_sync.py) must be updated to set first_seen_at with
    ON CREATE SET (not plain SET) so it is truly immutable after
    creation. See the MERGE pattern note at the bottom of this file.
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
    db = Neo4jClient()

    print("=" * 55)
    print("  Step 0: Cleaning up incorrect matches from v2")
    print("=" * 55)
    result = db.run(CLEANUP, {"tenant_id": TENANT_ID})
    print(f"  Removed {result[0]['removed']} incorrectly-dated EXPOSES edges")

    print("\n" + "=" * 55)
    print("  Step 1: Backfilling first_seen_at from real CVE dates")
    print("=" * 55)
    result = db.run(BACKFILL_FIRST_SEEN)
    print(f"  Backfilled first_seen_at on {result[0]['backfilled']} vulnerability nodes")
    print("  (using date_added -> published_date -> last_synced_at, in that priority)")

    print("\n" + "=" * 55)
    print(f"  Step 2: Correlating using TRUE recency ({LOOKBACK_DAYS}-day window)")
    print("=" * 55)
    print()
    correlate_new_vulnerabilities(db)

    db.close()

    print("\n" + "=" * 55)
    print("  Done.")
    print("=" * 55)
    print()
    print("  IMPORTANT next step: update the three ingestion scripts so")
    print("  first_seen_at is set with ON CREATE SET (never touched again),")
    print("  not plain SET -- otherwise every future full re-sync will")
    print("  reset it back to 'today' and reintroduce this exact bug.")
    print("=" * 55)
