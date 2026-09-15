import requests, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import CISA_KEV_URL, NVD_CVE_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone

MERGE_VULN = """
    UNWIND $batch AS row
    MERGE (v:Vulnerability {id: row.cve_id})
    SET v.cve_id=row.cve_id, v.title=row.title, v.description=row.description,
        v.vendor=row.vendor, v.product=row.product, v.cvss_score=row.cvss_score,
        v.severity=row.severity, v.ransomware_use=row.ransomware,
        v.patch_available=row.patch_available, v.source=row.source,
        v.last_synced_at=row.synced_at
"""

def sync_cisa_kev(db):
    print("  [KEV] Full sync...")
    data      = requests.get(CISA_KEV_URL, timeout=30).json()
    synced_at = datetime.now(timezone.utc).isoformat()
    batch = [{"cve_id": v.get("cveID",""), "title": v.get("vulnerabilityName",""),
              "description": v.get("shortDescription",""), "vendor": v.get("vendorProject",""),
              "product": v.get("product",""), "cvss_score": 0.0, "severity": "High",
              "ransomware": v.get("knownRansomwareCampaignUse","Unknown"),
              "patch_available": True, "source": "CISA_KEV", "synced_at": synced_at}
             for v in data.get("vulnerabilities",[])]
    db.run_batch(MERGE_VULN, batch)
    print(f"  [KEV] {len(batch)} entries synced")
    return len(batch)

def sync_nvd_delta(db):
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    print(f"  [NVD] Delta {start[:10]} to {end[:10]}...")
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(NVD_CVE_URL, headers=headers, timeout=60,
                         params={"pubStartDate": start, "pubEndDate": end,
                                 "cvssV3Severity": "CRITICAL", "resultsPerPage": 2000})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
    except Exception as e:
        print(f"  [NVD] WARNING: {e}"); return 0
    if not vulns:
        print("  [NVD] No new Critical CVEs today"); return 0
    batch = []
    synced_at = now.isoformat()
    for item in vulns:
        cve  = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")[:600]
        cvss = 0.0
        for m in cve.get("metrics",{}).get("cvssMetricV31",[]):
            cvss = m.get("cvssData",{}).get("baseScore",0.0); break
        batch.append({"cve_id": cve.get("id",""), "title": cve.get("id",""), "description": desc,
                      "vendor": "", "product": "", "cvss_score": cvss, "severity": "Critical",
                      "ransomware": "Unknown", "patch_available": False,
                      "source": "NVD", "synced_at": synced_at})
    db.run_batch(MERGE_VULN, batch)
    print(f"  [NVD] {len(batch)} new CVEs added")
    return len(batch)

def main():
    print("=" * 55)
    print(f"  DS-09: Daily Sync — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 55)
    db = Neo4jClient()
    kev = sync_cisa_kev(db)
    time.sleep(2)
    nvd = sync_nvd_delta(db)
    db.close()
    print("\n" + "=" * 55)
    print(f"  KEV synced: {kev}  |  NVD new: {nvd}")
    print("=" * 55)

if __name__ == "__main__": main()
