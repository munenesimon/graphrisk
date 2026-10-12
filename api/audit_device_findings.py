"""
GraphRisk -- read-only audit: where did each issue on a device come from?

For every asset with the given name (default "Simo"), lists the CVEs linked
to it and sorts each link into:

  scanner        the Vulnerability node was created from a connector finding
                 (source wazuh/qualys/crowdstrike...), or the CVE is one of the
                 recorded reasons (driver_cves) a risk was linked to the device
  name-match     the CVE only matches the device's vendor/product NAME
                 ("Microsoft" / "Windows") -- no version check, so it may well
                 not apply to this device at all
  other          linked some other way (by hand, demo seed...)

and shows the risks linked to the device with how many recorded CVEs drive
each one. Nothing is changed: every query runs in a READ session.

Run from the api folder with the venv active and the NEO4J_* settings set
(same as check_queries.py):

    python audit_device_findings.py            # device "Simo"
    python audit_device_findings.py OtherName
"""
import sys
from collections import Counter

from neo4j import READ_ACCESS
from app.graph.connection import get_graph_client, close_graph_client

SCANNER_SOURCES = {"wazuh", "qualys", "crowdstrike", "okta", "entra_id", "aws"}

ASSETS = """
    MATCH (a:Asset) WHERE toLower(a.name) = toLower($name)
    RETURN a.id AS id, a.tenant_id AS tenant_id, a.name AS name,
           a.vendor AS vendor, a.product AS product, a.owner AS owner
"""

# Same name-matching rule CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES
# uses, evaluated per linked CVE so we can tell which links it explains.
LINKED_CVES = """
    MATCH (a:Asset {id: $asset_id})
    MATCH (v:Vulnerability)-[e:EXPOSES]->(a)
    OPTIONAL MATCH (:Risk)-[i:IMPACTS]->(a)
    WITH a, v, e, reduce(acc = [], l IN collect(coalesce(i.driver_cves, [])) | acc + l) AS drivers
    RETURN v.cve_id AS cve_id, v.source AS source, v.severity AS severity,
           v.cvss_score AS cvss, (v.ransomware_use = true OR toLower(toString(v.ransomware_use)) = "known") AS ransomware,
           v.published_at AS published, v.vendor AS v_vendor, v.product AS v_product,
           keys(e) AS edge_props,
           v.cve_id IN drivers AS is_driver,
           (a.vendor IS NOT NULL AND a.vendor <> "" AND a.product IS NOT NULL AND a.product <> "" AND (
              (v.vendor IS NOT NULL AND v.vendor <> "" AND v.product IS NOT NULL AND v.product <> "" AND
               (toLower(v.vendor) CONTAINS toLower(a.vendor) OR toLower(a.vendor) CONTAINS toLower(v.vendor)) AND
               (toLower(v.product) CONTAINS toLower(a.product) OR toLower(a.product) CONTAINS toLower(v.product)))
              OR ANY(pair IN coalesce(v.cpe_pairs, []) WHERE
                     pair CONTAINS toLower(a.vendor) AND pair CONTAINS toLower(a.product))
           )) AS name_match
"""

RISKS = """
    MATCH (r:Risk)-[i:IMPACTS]->(:Asset {id: $asset_id})
    RETURN r.title AS title, r.risk_score AS score, i.source AS source,
           size(coalesce(i.driver_cves, [])) AS drivers
    ORDER BY score DESC
"""

PROFILE = """
    MATCH (:Asset {id: $asset_id})-[:HAS_PROFILE]->(p:AssetProfileSection)
    RETURN p.source AS source, p.section AS section, toString(p.collected_at) AS updated_at
    ORDER BY section
"""


def classify(row: dict) -> str:
    if (row.get("source") or "").lower() in SCANNER_SOURCES or row.get("is_driver"):
        return "scanner"
    if row.get("name_match"):
        return "name-match"
    return "other"


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else "Simo"
    driver = get_graph_client()
    try:
        with driver.session(default_access_mode=READ_ACCESS) as s:
            assets = s.run(ASSETS, name=name).data()
            if not assets:
                print(f"No asset named {name!r}.")
                return
            for a in assets:
                print("=" * 70)
                print(f"  {a['name']}  (tenant {a['tenant_id']}, asset {a['id']})")
                print(f"  vendor/product used for name matching: {a['vendor']!r} / {a['product']!r}")
                print(f"  owner: {a['owner']}")
                print("=" * 70)

                rows = s.run(LINKED_CVES, asset_id=a["id"]).data()
                for r in rows:
                    r["kind"] = classify(r)
                kinds = Counter(r["kind"] for r in rows)
                print(f"\n  Linked CVEs: {len(rows)}")
                for k in ("scanner", "name-match", "other"):
                    print(f"    {k:<11} {kinds.get(k, 0)}")
                print(f"  By Vulnerability.source: {dict(Counter((r['source'] or 'none') for r in rows))}")
                print(f"  Link properties seen: {sorted({p for r in rows for p in (r['edge_props'] or [])}) or 'none (no provenance recorded)'}")

                nm = [r for r in rows if r["kind"] == "name-match"]
                if nm:
                    rw = sum(1 for r in nm if r["ransomware"])
                    years = Counter((str(r["published"] or "")[:4] or "????") for r in nm)
                    print(f"\n  Name-match only: {len(nm)} ({rw} with known ransomware use per CISA KEV)")
                    print(f"    by year published: {dict(sorted(years.items()))}")
                    print(f"    products named on them: {dict(Counter((r['v_product'] or '?') for r in nm).most_common(8))}")
                    print("    examples:")
                    for r in sorted(nm, key=lambda r: -(r["cvss"] or 0))[:10]:
                        print(f"      {r['cve_id']:<16} {str(r['severity'] or ''):<9} cvss {r['cvss']}  "
                              f"{'ransomware ' if r['ransomware'] else ''}{r['v_product'] or ''}")

                other = [r for r in rows if r["kind"] == "other"]
                if other:
                    print(f"\n  Other links (examples): {', '.join(r['cve_id'] for r in other[:10])}")

                print("\n  Risks linked to this device:")
                for r in s.run(RISKS, asset_id=a["id"]).data():
                    print(f"    {str(r['title']):<40} score {r['score']}  "
                          f"recorded CVEs {r['drivers']}  via {r['source'] or 'not recorded'}")

                print("\n  Device detail sections:")
                for p in s.run(PROFILE, asset_id=a["id"]).data():
                    print(f"    {str(p['section']):<14} from {str(p['source']):<10} {p['updated_at']}")
                print()
    finally:
        close_graph_client()


if __name__ == "__main__":
    main()
