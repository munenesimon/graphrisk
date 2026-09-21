import requests, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import NVD_CVE_URL, NVD_API_KEY
from datetime import datetime, timezone
from tqdm import tqdm

MERGE_VULN = """
    UNWIND $batch AS row
    MERGE (v:Vulnerability {id: row.cve_id})
    ON CREATE SET v.first_seen_at = coalesce(row.date_added, row.published_at, row.published_date, toString(datetime()))
    SET v.cve_id=row.cve_id, v.description=row.description,
        v.cvss_score=row.cvss_score, v.severity=row.severity,
        v.published_at=row.published_at, v.source="NVD",
        v.patch_available=false,
        v.last_synced_at=row.synced_at
"""

def fetch_page(start, severity="CRITICAL"):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params  = {"cvssV3Severity": severity, "resultsPerPage": 2000, "startIndex": start}
    r = requests.get(NVD_CVE_URL, headers=headers, params=params, timeout=60)
    r.raise_for_status()
    return r.json()

def parse_cve(item):
    cve  = item.get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")[:600]
    cvss = 0.0
    for m in cve.get("metrics",{}).get("cvssMetricV31",[]):
        cvss = m.get("cvssData",{}).get("baseScore", 0.0); break
    return {"cve_id": cve.get("id",""), "description": desc, "cvss_score": cvss,
            "severity": "Critical", "published_at": cve.get("published",""),
            "synced_at": datetime.now(timezone.utc).isoformat()}

def ingest(max_results=10000):
    print("=" * 55)
    print("  DS-07: NVD CVE Ingestion (Critical only)")
    print("=" * 55)
    if not NVD_API_KEY:
        print("  TIP: No API key set — slower rate limit.")
        print("  Get a free key: nvd.nist.gov/developers/request-an-api-key")
    print("\n[1/3] Fetching first page...")
    try:
        first = fetch_page(0)
    except Exception as e:
        print(f"  ERROR: {e}"); return
    total = min(first.get("totalResults", 0), max_results)
    print(f"  Total available: {first.get('totalResults',0):,}  Fetching: {total:,}")
    all_batch = [parse_cve(v) for v in first.get("vulnerabilities",[])]
    print("\n[2/3] Fetching remaining pages...")
    start = 2000
    with tqdm(total=total, initial=len(all_batch)) as pbar:
        while start < total:
            time.sleep(1)
            try:
                page  = fetch_page(start)
                chunk = [parse_cve(v) for v in page.get("vulnerabilities",[])]
                all_batch.extend(chunk); pbar.update(len(chunk)); start += 2000
            except Exception as e:
                print(f"\n  Retrying ({e})..."); time.sleep(5)
    print(f"\n[3/3] Loading {len(all_batch):,} CVEs into Neo4j...")
    db = Neo4jClient()
    db.run_batch(MERGE_VULN, all_batch)
    db.close()
    print("\n" + "=" * 55)
    print(f"  Done. {len(all_batch):,} Critical CVEs loaded.")
    print("  MATCH (v:Vulnerability {source:\'NVD\'}) RETURN count(v)")
    print("=" * 55)

if __name__ == "__main__": ingest()
