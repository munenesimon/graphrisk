import requests
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neo4j_utils import Neo4jClient
from config import CISA_KEV_URL

MERGE_VULN = """
    UNWIND $batch AS row
    MERGE (v:Vulnerability {id: row.cve_id})
    ON CREATE SET v.first_seen_at = coalesce(row.date_added, row.published_at, row.published_date, toString(datetime()))
    SET v.cve_id          = row.cve_id,
        v.title           = row.title,
        v.description     = row.description,
        v.vendor          = row.vendor,
        v.product         = row.product,
        v.date_added      = row.date_added,
        v.due_date        = row.due_date,
        v.ransomware_use  = row.ransomware,
        v.severity        = "High",
        v.source          = "CISA_KEV",
        v.patch_available = true,
        v.last_synced_at  = row.synced_at
"""

def ingest():
    print("=" * 55)
    print("  DS-06: CISA KEV Ingestion")
    print("=" * 55)
    print("\n[1/3] Fetching CISA KEV catalog...")
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"  ERROR fetching KEV: {e}")
        return
    vulns = data.get("vulnerabilities", [])
    print(f"  Found {len(vulns)} entries")
    print(f"  Catalog version: {data.get('catalogVersion', 'unknown')}")
    print("\n[2/3] Building batch...")
    synced_at = datetime.now(timezone.utc).isoformat()
    batch = []
    for v in vulns:
        batch.append({
            "cve_id":      v.get("cveID", ""),
            "title":       v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "vendor":      v.get("vendorProject", ""),
            "product":     v.get("product", ""),
            "date_added":  v.get("dateAdded", ""),
            "due_date":    v.get("dueDate", ""),
            "ransomware":  v.get("knownRansomwareCampaignUse", "Unknown"),
            "synced_at":   synced_at
        })
    print("\n[3/3] Loading into Neo4j...")
    try:
        db = Neo4jClient()
        db.run_batch(MERGE_VULN, batch)
        db.close()
    except Exception as e:
        print(f"  ERROR writing to Neo4j: {e}")
        return
    ransomware_known = sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known")
    print("\n" + "=" * 55)
    print("  CISA KEV Ingestion Complete")
    print("=" * 55)
    print(f"  Total loaded         : {len(batch)}")
    print(f"  Known ransomware use : {ransomware_known}")
    print(f"  Synced at            : {synced_at[:19]}")
    print("\n  Verify in Neo4j Browser:")
    print("  MATCH (v:Vulnerability {source:'CISA_KEV'}) RETURN count(v)")
    print("=" * 55)

if __name__ == "__main__":
    ingest()
